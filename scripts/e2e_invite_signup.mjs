// End-to-end check of M1's onboarding path against running services: an owner signs in, registers AgentCanvas,
// creates a tenant and invites a colleague; the colleague opens the emailed link, creates an account on the
// invitation page, verifies their email and lands in the tenant with the invited AgentCanvas role, which then shows
// in their AgentCanvas access token.
//
// Needs: Keycloak with the matura realm and the extension on :8180 (admin/admin), maturad on :8080 with
// MATURA_AUTH=oidc and MATURA_SMTP_ADDR pointing at Mailpit, Mailpit's API on :8025 (deploy/compose runs all three;
// switch maturad to MATURA_AUTH=oidc there). Run: node scripts/e2e_invite_signup.mjs
// PLAYWRIGHT_MODULE overrides where Playwright is imported from; AGENTCANVAS_MANIFEST where the manifest is.
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
import crypto from "node:crypto";
import fs from "node:fs";

const KC = "http://localhost:8180", REALM = KC + "/realms/matura", API = "http://localhost:8080", MAIL = "http://localhost:8025";
const log = (...a) => console.log("•", ...a);
const must = async (res, what) => { if (!res.ok) throw new Error(`${what}: ${res.status} ${await res.text()}`); return res.status === 204 ? null : res.json(); };
const form = (o) => ({ method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(o) });
const b64 = (b) => Buffer.from(b).toString("base64url");
const claims = (t) => JSON.parse(Buffer.from(t.split(".")[1], "base64url"));

// --- Keycloak admin: the owner account (sign-up for the invitee is tested through the browser below)
const admin = (await must(await fetch(KC + "/realms/master/protocol/openid-connect/token",
  form({ grant_type: "password", client_id: "admin-cli", username: "admin", password: "admin" })), "admin token")).access_token;
const ah = { Authorization: "Bearer " + admin, "Content-Type": "application/json" };
await fetch(KC + "/admin/realms/matura/users", { method: "POST", headers: ah, body: JSON.stringify({
  username: "alice@example.test", email: "alice@example.test", firstName: "Alice", lastName: "Owner", enabled: true,
  emailVerified: true, credentials: [{ type: "password", value: "Alice-pass-123", temporary: false }] }) });
const [alice] = await must(await fetch(KC + "/admin/realms/matura/users?email=alice@example.test", { headers: ah }), "find alice");
const opRole = await must(await fetch(KC + "/admin/realms/matura/roles/matura-operator", { headers: ah }), "operator role");
await must(await fetch(KC + `/admin/realms/matura/users/${alice.id}/role-mappings/realm`, { method: "POST", headers: ah, body: JSON.stringify([opRole]) }), "grant operator");
log("owner account ready", alice.id);

const browser = await chromium.launch();

// sign in with PKCE as a public client and return the access token (the redirect is caught, not loaded)
async function pkceLogin(ctx, clientId, redirectUri, creds) {
  const page = await ctx.newPage();
  const verifier = b64(crypto.randomBytes(32)), challenge = b64(crypto.createHash("sha256").update(verifier).digest());
  let code;
  page.on("request", (r) => { if (r.url().startsWith(redirectUri)) code = new URL(r.url()).searchParams.get("code"); });
  await page.goto(REALM + "/protocol/openid-connect/auth?" + new URLSearchParams({ client_id: clientId, response_type: "code",
    redirect_uri: redirectUri, scope: "openid email profile", code_challenge: challenge, code_challenge_method: "S256" })).catch(() => {});
  if (creds) { await page.fill("#username", creds.user); await page.fill("#password", creds.password); await page.click("#kc-login").catch(() => {}); }
  for (let i = 0; i < 50 && !code; i++) await page.waitForTimeout(100);
  if (!code) throw new Error("no code for " + clientId + " at " + page.url());
  await page.close();
  return (await must(await fetch(REALM + "/protocol/openid-connect/token", form({ grant_type: "authorization_code",
    client_id: clientId, code, redirect_uri: redirectUri, code_verifier: verifier })), "token " + clientId)).access_token;
}

const actx = await browser.newContext();
const aliceToken = await pkceLogin(actx, "matura-console", "http://localhost:5173/cb",
  { user: "alice@example.test", password: "Alice-pass-123" });
const asAlice = (method, path, body) => fetch(API + path, { method, headers: { Authorization: "Bearer " + aliceToken,
  "Content-Type": "application/json" }, body: body && JSON.stringify(body) });
log("owner signed in; token aud", claims(aliceToken).aud);

await must(await asAlice("PUT", "/admin/v1/apps/agentcanvas", JSON.parse(fs.readFileSync(process.env.AGENTCANVAS_MANIFEST ?? "../AgentCanvas/matura/manifest.json"))), "register app");
const acme = await must(await asAlice("POST", "/v1/tenants", { slug: "acme-" + Date.now() % 100000, name: "Acme" }), "create tenant");
await must(await asAlice("PUT", `/v1/tenants/${acme.id}/apps/agentcanvas`), "enable app");
const bobEmail = `bob${Date.now() % 100000}@example.test`;
const inv = await must(await asAlice("POST", `/v1/tenants/${acme.id}/invitations`, { email: bobEmail, tenant_role: "member",
  app_roles: [{ app: "agentcanvas", role: "builder" }] }), "invite");
log("tenant", acme.slug, "invited", bobEmail);

async function mailTo(addr, subjectPart) {
  for (let i = 0; i < 60; i++) {
    const list = await (await fetch(MAIL + "/api/v1/search?query=" + encodeURIComponent("to:" + addr))).json();
    const m = list.messages?.find((x) => x.Subject.includes(subjectPart));
    if (m) return (await (await fetch(MAIL + "/api/v1/message/" + m.ID)).json());
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("no email to " + addr + " about " + subjectPart);
}
const invMail = await mailTo(bobEmail, "invited you to Acme");
const link = invMail.Text.match(/http:\/\/localhost:8080\/invitations\/accept\?token=\S+/)[0];
if (link !== inv.accept_url) throw new Error("email link differs from accept_url");
log("invitation email arrived:", invMail.Subject);

// --- the invitee: open the link, create an account, verify the email, land back and accept
const bctx = await browser.newContext();
const page = await bctx.newPage();
const consoleErrors = []; page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
await page.goto(link);
await page.waitForSelector("text=Join Acme");
if (page.url().includes("token=")) throw new Error("token left in the address bar");
log("accept page:", await page.textContent("#title"), "/", await page.textContent("#message"));
await page.click("#signup");
await page.waitForSelector("#password");
log("registration form, email prefilled:", await page.inputValue("#email").catch(() => "?"));
await page.fill("#email", bobEmail);
await page.fill("#password", "Bob-pass-123456");
await page.fill("#password-confirm", "Bob-pass-123456");
if (await page.$("#firstName")) { await page.fill("#firstName", "Bob"); await page.fill("#lastName", "Builder"); }
await page.click("input[type=submit], button[type=submit]");
const verify = await mailTo(bobEmail, "erif");
const vlink = verify.Text.match(/http:\/\/localhost:8180\S+/)[0];
log("verification email arrived");
await page.goto(vlink);
await page.waitForSelector("text=You're in", { timeout: 20000 }).catch(async (e) => {
  console.log(await page.content()); throw e; });
log("accept page:", await page.textContent("#title"), "/", await page.textContent("#message"));

// --- results, as the owner sees them, and the invitee's AgentCanvas token
const members = await must(await asAlice("GET", `/v1/tenants/${acme.id}/members`), "members");
const bob = members.items.find((m) => m.email === bobEmail);
const grants = await must(await asAlice("GET", `/v1/tenants/${acme.id}/grants`), "grants");
const bobGrants = grants.items.filter((g) => g.subject_id === bob?.user_id && g.status === "active").map((g) => `${g.app}:${g.role}`);
log("member:", bob?.email, bob?.tenant_role, "grants:", bobGrants);
const invs = await must(await asAlice("GET", `/v1/tenants/${acme.id}/invitations`), "invitations");
log("invitation state:", invs.items[0].state);

const canvasToken = await pkceLogin(bctx, "agentcanvas", "http://localhost:7777/callback");
const c = claims(canvasToken);
log("AgentCanvas token:", JSON.stringify({ sub: c.sub, tid: c.tid, tenant: c.tenant, troles: c.troles, roles: c.roles, perms: c.perms, pmode: c.pmode }));

const ok = bob?.tenant_role === "member" && bobGrants.join() === "agentcanvas:builder" && invs.items[0].state === "accepted" &&
  c.tid === acme.id && c.sub === bob.user_id && c.roles?.includes("builder");
if (consoleErrors.length) log("page console errors:", consoleErrors);
await browser.close();
console.log(ok ? "E2E PASS" : "E2E FAIL");
process.exit(ok ? 0 : 1);
