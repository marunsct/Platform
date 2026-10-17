"""End-to-end check of MFA enforcement, sessions and tenant SSO (TS12, TS13) against Keycloak 26.4 with the Matura
extension and the realm from keycloak/realm, and a maturad that uses it (MATURA_AUTH=oidc, MATURA_ENV=development,
MATURA_KEYCLOAK_CLIENT_SECRET set, superuser database URL so the script can seed rows).

    MATURA_E2E_KEYCLOAK=http://localhost:8190 MATURA_E2E_MATURAD=http://localhost:8091 \
    MATURA_E2E_DATABASE=postgres://postgres@localhost:55432/matura python3 scripts/e2e_identity.py

Needs requests and beautifulsoup4. It turns on direct grants for matura-console (to get an owner token) and creates
a throwaway realm as the tenant's OIDC identity provider, which it deletes. Do not run it against a shared realm.
"""
import base64, hashlib, hmac, json, os, re, secrets, struct, sys, time, uuid
import requests
import http.cookiejar
from bs4 import BeautifulSoup
import subprocess

KC = os.environ.get("MATURA_E2E_KEYCLOAK", "http://localhost:8180")
MD = os.environ.get("MATURA_E2E_MATURAD", "http://localhost:8080")
DB = os.environ["MATURA_E2E_DATABASE"]


def sql(q):
    return subprocess.run(["psql", DB, "-tAc", q], check=True, capture_output=True, text=True).stdout.strip()


class Browser:
    """Just enough of a browser: cookies by name and path (Keycloak's are Secure, Version=1, on plain-HTTP localhost,
    which http.cookiejar will not send back)."""

    def __init__(self):
        self.s = requests.Session()
        self.s.trust_env = False
        self.jar = {}
        self.headers = self.s.headers

    def _cookie(self, url):
        path = requests.utils.urlparse(url).path
        return "; ".join(f"{n}={v}" for (n, p), v in self.jar.items() if path.startswith(p.rstrip("/")))

    def request(self, method, url, allow_redirects=False, **kw):
        while True:
            h = dict(kw.pop("headers", {}) or {})
            c = self._cookie(url)
            if c:
                h["Cookie"] = c
            r = self.s.request(method, url, headers=h, allow_redirects=False, **kw)
            for raw in r.raw.headers.get_all("Set-Cookie") or []:
                nv, *attrs = raw.split(";")
                n, _, v = nv.partition("=")
                path = next((a.split("=", 1)[1] for a in attrs if a.strip().lower().startswith("path=")), "/")
                maxage = next((a.split("=", 1)[1] for a in attrs if a.strip().lower().startswith("max-age=")), None)
                if maxage == "0" or v == "":
                    self.jar.pop((n.strip(), path.strip()), None)
                else:
                    self.jar[(n.strip(), path.strip())] = v.strip()
            if not allow_redirects or r.status_code not in (301, 302, 303, 307):
                return r
            url, method, kw = requests.compat.urljoin(url, r.headers["Location"]), "GET", {}

    def get(self, url, allow_redirects=True, **kw):
        return self.request("GET", url, allow_redirects=allow_redirects, **kw)

    def post(self, url, allow_redirects=True, **kw):
        return self.request("POST", url, allow_redirects=allow_redirects, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)


def sess():
    return Browser()


def admin():
    s = sess()
    t = s.post(f"{KC}/realms/master/protocol/openid-connect/token",
               data={"client_id": "admin-cli", "username": "admin", "password": "admin", "grant_type": "password"}).json()
    s.headers["Authorization"] = "Bearer " + t["access_token"]
    return s


A = admin()


def kc_user(realm, email, password):
    r = A.post(f"{KC}/admin/realms/{realm}/users", json={"username": email, "email": email, "emailVerified": True,
               "enabled": True, "firstName": "Test", "lastName": "User",
               "credentials": [{"type": "password", "value": password, "temporary": False}]})
    assert r.status_code in (201, 409), r.text
    return A.get(f"{KC}/admin/realms/{realm}/users", params={"email": email, "exact": "true"}).json()[0]["id"]


def totp(secret_b32, t=None):
    key = secret_b32.encode()  # Keycloak's totpSecret field is the raw key
    counter = int((t or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def start_login(s, extra=None):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": "matura-console", "redirect_uri": "http://localhost:8080/invitations/accept",
              "response_type": "code", "scope": "openid", "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "x"}
    params.update(extra or {})
    url = f"{KC}/realms/matura/protocol/openid-connect/auth?" + requests.compat.urlencode(params)
    return s.get(url, allow_redirects=True)


def form_post(s, page, data, form_id=None):
    soup = BeautifulSoup(page.text, "html.parser")
    form = soup.find("form", id=form_id) if form_id else soup.find("form")
    assert form is not None, page.text[:2000]
    fields = {i.get("name"): i.get("value", "") for i in form.find_all("input") if i.get("name")}
    fields.update(data)
    return s.post(form["action"], data=fields, allow_redirects=False)


def follow(s, r):
    while r.status_code in (302, 303) and not r.headers["Location"].startswith("http://localhost:8080"):
        r = s.get(r.headers["Location"], allow_redirects=False)
    return r


def done(r):
    return r.status_code in (302, 303) and r.headers["Location"].startswith("http://localhost:8080/invitations/accept") \
        and "code=" in r.headers["Location"]


ok = True


def check(cond, msg):
    global ok
    print(("PASS " if cond else "FAIL ") + msg)
    ok = ok and cond


# --- MFA policy ---------------------------------------------------------------------------------------------------
RUN = uuid.uuid4().hex[:6]
DOMAIN = f"acme-{RUN}.test"
email = f"mfa-{RUN}@{DOMAIN}"
uid = kc_user("matura", email, "correct-horse-battery")
tid = str(uuid.uuid4())
sql(f"""INSERT INTO app_user (id, email, email_verified, status, version) VALUES ('{uid}', '{email}', true, 'active', nextval('matura_version_seq'));
INSERT INTO tenant (id, slug, name, kind, status, version) VALUES ('{tid}', 'acme-{tid[:6]}', 'Acme', 'company', 'active', nextval('matura_version_seq'));
INSERT INTO membership (tenant_id, user_id, tenant_role, status, version) VALUES ('{tid}', '{uid}', 'owner', 'active', nextval('matura_version_seq'));""")

s = sess()
r = form_post(s, start_login(s), {"username": email, "password": "correct-horse-battery"})
r = follow(s, r)
check(done(r), "no MFA policy: password alone signs in")

sql(f"INSERT INTO security_policy (tenant_id, require_mfa, version) VALUES ('{tid}', true, nextval('matura_version_seq'))")
s = sess()
r = form_post(s, start_login(s), {"username": email, "password": "correct-horse-battery"})
r = follow(s, r)
page = s.get(r.headers["Location"]) if r.status_code in (302, 303) else r
check("totp" in page.text.lower() and not done(r), "MFA required: sign-in stops at TOTP enrolment")
soup = BeautifulSoup(page.text, "html.parser")
secret_input = soup.find("input", {"name": "totpSecret"})
secret = secret_input["value"] if secret_input else None
check(secret is not None, "TOTP secret offered")
if secret:
    r = follow(s, form_post(s, page, {"totp": totp(secret), "userLabel": "phone"}))
    check(done(r), "after enrolling TOTP the sign-in finishes")
    s = sess()
    r = follow(s, form_post(s, start_login(s), {"username": email, "password": "correct-horse-battery"}))
    page = s.get(r.headers["Location"]) if r.status_code in (302, 303) else r
    check(not done(r) and BeautifulSoup(page.text, "html.parser").find("input", {"name": "otp"}) is not None,
          "next sign-in asks for the one-time code")
    time.sleep(31 - time.time() % 30)  # a code may be used only once
    r = follow(s, form_post(s, page, {"otp": totp(secret)}))
    check(done(r), "with the code the sign-in finishes")

# --- maturad session and MFA endpoints with a real token ----------------------------------------------------------
A.put(f"{KC}/admin/realms/matura/clients/" +
      A.get(f"{KC}/admin/realms/matura/clients", params={"clientId": "matura-console"}).json()[0]["id"],
      json={"clientId": "matura-console", "directAccessGrantsEnabled": True})
owner_email = f"owner-{RUN}@{DOMAIN}"
oid = kc_user("matura", owner_email, "correct-horse-battery")
tok = sess().post(f"{KC}/realms/matura/protocol/openid-connect/token",
                  data={"client_id": "matura-console", "grant_type": "password", "username": owner_email,
                        "password": "correct-horse-battery", "scope": "openid"}).json()
check("access_token" in tok, "owner gets a token (direct grant enabled on the private instance)")
M = sess()
M.headers["Authorization"] = "Bearer " + tok["access_token"]
me = M.get(f"{MD}/v1/me/sessions").json()
check(len(me["items"]) == 1 and me["items"][0]["current"], f"GET /v1/me/sessions lists the current session: {me}")
mfa = M.get(f"{MD}/v1/me/mfa").json()
check(mfa["configured"] is False and mfa["required"] is False, f"GET /v1/me/mfa: {mfa}")
sql(f"INSERT INTO membership (tenant_id, user_id, tenant_role, status, version) VALUES ('{tid}', '{oid}', 'owner', 'active', nextval('matura_version_seq'))")
# the MFA user is in acme only: the owner governs them
r = M.get(f"{MD}/v1/tenants/{tid}/members/{uid}/sessions")
check(r.status_code == 200, f"owner lists a member's sessions: {r.status_code} {r.text[:200]}")
r = M.post(f"{MD}/v1/tenants/{tid}/members/{uid}:reset-mfa")
check(r.status_code == 200 and r.json()["removed"] == 1, f"owner resets the member's MFA: {r.status_code} {r.text[:200]}")
creds = A.get(f"{KC}/admin/realms/matura/users/{uid}/credentials").json()
check([c["type"] for c in creds] == ["password"], f"only the password is left: {[c['type'] for c in creds]}")

# --- SSO ----------------------------------------------------------------------------------------------------------
idp_realm = "wt-identity-acme-idp"
A.delete(f"{KC}/admin/realms/{idp_realm}")
A.post(f"{KC}/admin/realms", json={"realm": idp_realm, "enabled": True, "clients": [{
    "clientId": "matura", "enabled": True, "publicClient": False, "secret": "idp-secret",
    "standardFlowEnabled": True, "redirectUris": [f"{KC}/realms/matura/broker/*"]}]}).raise_for_status()
kc_user(idp_realm, f"dana@{DOMAIN}", "idp-password-123")
kc_user(idp_realm, "eve@evil.test", "idp-password-123")
slug = sql(f"SELECT slug FROM tenant WHERE id = '{tid}'")
sql(f"INSERT INTO tenant_domain (tenant_id, domain, challenge, verified_at, version) VALUES ('{tid}', '{DOMAIN}', 'c', now(), nextval('matura_version_seq'))")
r = M.post(f"{MD}/v1/tenants/{tid}/sso", json={"protocol": "oidc", "discovery_url": f"{KC}/realms/{idp_realm}",
                                                "client_id": "matura", "client_secret": "idp-secret"})
check(r.status_code == 201, f"connect an OIDC IdP: {r.status_code} {r.text[:300]}")
alias = f"t-{slug}"
d = sess().get(f"{MD}/v1/sso/discover", params={"email": f"dana@{DOMAIN}"}).json()
check(d.get("idp_hint") == alias, f"discovery: {d}")


def sso_login(user):
    s = sess()
    page = start_login(s, {"kc_idp_hint": alias})
    r = form_post(s, page, {"username": user, "password": "idp-password-123"})
    return s, follow(s, r)


s, r = sso_login(f"dana@{DOMAIN}")
check(done(r), f"dana signs in through the tenant IdP: {r.status_code} {r.headers.get('Location', '')[:120]}")
dana = A.get(f"{KC}/admin/realms/matura/users", params={"email": f"dana@{DOMAIN}", "exact": "true"}).json()
joined = dana and sql(f"SELECT tenant_role FROM membership WHERE tenant_id = '{tid}' AND user_id = '{dana[0]['id']}'")
check(joined == "member", f"dana joined the tenant just in time: {joined!r}")

s, r = sso_login("eve@evil.test")
page = r if r.status_code == 200 else s.get(r.headers["Location"]) if r.status_code in (302, 303) else r
check(not done(r) and "verified domains" in page.text, "eve@evil.test is refused by the tenant IdP check")
evil = A.get(f"{KC}/admin/realms/matura/users", params={"email": "eve@evil.test", "exact": "true"}).json()
check(evil == [], "no account was created for eve")

frank = kc_user("matura", f"frank@{DOMAIN}", "frank-local-password")
kc_user(idp_realm, f"frank@{DOMAIN}", "idp-password-123")
s, r = sso_login(f"frank@{DOMAIN}")
links = A.get(f"{KC}/admin/realms/matura/users/{frank}/federated-identity").json()
check(done(r) and [l["identityProvider"] for l in links] == [alias],
      f"an existing account with the verified-domain email is linked, not duplicated: {links}")

r = M.delete(f"{MD}/v1/tenants/{tid}/sso")
check(r.status_code == 204, "disconnect the IdP")
A.delete(f"{KC}/admin/realms/{idp_realm}")
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
