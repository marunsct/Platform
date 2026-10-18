package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/access"
	"github.com/marunsct/Platform/internal/api"
	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/fga/fgatest"
	"github.com/marunsct/Platform/internal/ids"
	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/keycloak/keycloaktest"
	"github.com/marunsct/Platform/internal/secrets"
	"github.com/marunsct/Platform/internal/store"
	"github.com/marunsct/Platform/internal/testdb"
)

// scimClient calls a tenant's SCIM endpoint with a bearer token, as an identity provider does.
type scimClient struct {
	t     *testing.T
	base  string // http://…/scim/v2/tenants/<tid>
	token string
}

func (c scimClient) call(method, path string, body any, header ...string) (int, map[string]any, http.Header) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode >= 400 && out["schemas"] != nil {
		if s, _ := out["schemas"].([]any); len(s) != 1 || s[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
			c.t.Errorf("%s %s: error not in the SCIM error schema: %v", method, path, out)
		}
	}
	return res.StatusCode, out, res.Header
}

func (c scimClient) must(want int, method, path string, body any, header ...string) map[string]any {
	c.t.Helper()
	got, out, _ := c.call(method, path, body, header...)
	if got != want {
		c.t.Fatalf("%s %s: status %d, want %d (%v)", method, path, got, want, out)
	}
	return out
}

// fixture reads a request body recorded from an identity provider's documentation, with {{name}} filled in.
func fixture(t *testing.T, idp, name string, vars map[string]string) any {
	t.Helper()
	raw, err := os.ReadFile("testdata/scim/" + idp + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	body, ok := all[name]
	if !ok {
		t.Fatalf("no fixture %s/%s", idp, name)
	}
	s := string(body)
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type scimEnv struct {
	srv   *httptest.Server
	fake  *keycloaktest.Server
	dns   *fakeDNS
	owner client
	tid   string
	scim  scimClient
}

// setupSCIM makes tenant acme with verified domains acme.test and testuser.com, the devflow app enabled, and a SCIM
// token.
func setupSCIM(t *testing.T) scimEnv {
	srv, fake, dns := setupIdentity(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/devflow", manifest)
	alice := client{t: t, srv: srv, user: ids.New()}
	acme := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	tid := acme["id"].(string)
	alice.must(http.StatusOK, "PUT", "/v1/tenants/"+tid+"/apps/devflow", nil)
	verifyDomain(t, alice, dns, tid, "acme.test")
	verifyDomain(t, alice, dns, tid, "testuser.com")
	tok := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/scim/tokens", map[string]any{"name": "idp"})
	return scimEnv{srv: srv, fake: fake, dns: dns, owner: alice, tid: tid,
		scim: scimClient{t: t, base: tok["scim_base_url"].(string), token: tok["token"].(string)}}
}

func verifyDomain(t *testing.T, c client, dns *fakeDNS, tid, domain string) {
	t.Helper()
	d := c.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/domains", map[string]any{"domain": domain})
	dns.set(d["record_name"].(string), d["record_value"].(string))
	c.must(http.StatusOK, "POST", "/v1/tenants/"+tid+"/domains/"+domain+":verify", nil)
}

func memberStatus(t *testing.T, c client, tid, uid string) string {
	t.Helper()
	for _, m := range c.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/members", nil)["items"].([]any) {
		if m.(map[string]any)["user_id"] == uid {
			return m.(map[string]any)["status"].(string)
		}
	}
	return "none"
}

func grantedRoles(t *testing.T, c client, tid, uid string) []string {
	t.Helper()
	out := []string{}
	for _, g := range c.must(http.StatusOK, "GET", "/v1/tenants/"+tid+"/grants?user_id="+uid, nil)["items"].([]any) {
		out = append(out, g.(map[string]any)["app"].(string)+":"+g.(map[string]any)["role"].(string))
	}
	slices.Sort(out)
	return out
}

func filterQuery(f string) string { return "?filter=" + url.QueryEscape(f) }

func listed(out map[string]any) []any {
	r, _ := out["Resources"].([]any)
	return r
}

// TestSCIMTokens: owners create, list and revoke tokens (shown once, hash stored, audited); admins cannot; a token
// works only for its own tenant.
func TestSCIMTokens(t *testing.T) {
	e := setupSCIM(t)
	base := "/v1/tenants/" + e.tid + "/scim/tokens"
	list := e.owner.must(http.StatusOK, "GET", base, nil)["items"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["token"] != nil || !strings.HasPrefix(e.scim.token, "scim_") ||
		!strings.HasPrefix(e.scim.token, list[0].(map[string]any)["prefix"].(string)) {
		t.Fatalf("tokens: %v", list)
	}

	bob := client{t: t, srv: e.srv, user: ids.New()}
	bob.must(http.StatusOK, "GET", "/v1/me", nil)
	e.owner.must(http.StatusCreated, "POST", "/v1/tenants/"+e.tid+"/members",
		map[string]any{"user_id": bob.user, "tenant_role": "admin"})
	bob.must(http.StatusForbidden, "POST", base, map[string]any{"name": "mine"})
	bob.must(http.StatusForbidden, "GET", base, nil)
	e.owner.must(http.StatusUnprocessableEntity, "POST", base, map[string]any{"name": ""})

	e.scim.must(http.StatusOK, "GET", "/ServiceProviderConfig", nil)
	if n := e.scim.must(http.StatusOK, "GET", "/Schemas", nil)["totalResults"]; n != 3.0 {
		t.Fatalf("schemas: %v", n)
	}
	if n := e.scim.must(http.StatusOK, "GET", "/ResourceTypes", nil)["totalResults"]; n != 2.0 {
		t.Fatalf("resource types: %v", n)
	}
	none := e.scim
	none.token = ""
	code, out, h := none.call("GET", "/Users", nil)
	if code != http.StatusUnauthorized || h.Get("WWW-Authenticate") == "" || out["status"] != "401" {
		t.Fatalf("no token: %d %v", code, out)
	}
	wrong := e.scim
	wrong.token = "scim_not-a-real-token"
	wrong.must(http.StatusUnauthorized, "GET", "/Users", nil)

	// globex's token does not open acme, nor acme's globex
	gina := client{t: t, srv: e.srv, user: ids.New()}
	globex := gina.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	gtok := gina.must(http.StatusCreated, "POST", "/v1/tenants/"+globex["id"].(string)+"/scim/tokens",
		map[string]any{"name": "idp"})
	cross := e.scim
	cross.token = gtok["token"].(string)
	cross.must(http.StatusUnauthorized, "GET", "/Users", nil)
	other := scimClient{t: t, base: gtok["scim_base_url"].(string), token: e.scim.token}
	other.must(http.StatusUnauthorized, "GET", "/Users", nil)

	// rotation: a second token, then the first is revoked
	second := e.owner.must(http.StatusCreated, "POST", base, map[string]any{"name": "rotated"})
	id := list[0].(map[string]any)["id"].(string)
	e.owner.must(http.StatusNoContent, "DELETE", base+"/"+id, nil)
	e.owner.must(http.StatusNotFound, "DELETE", base+"/"+id, nil)
	e.scim.must(http.StatusUnauthorized, "GET", "/Users", nil)
	rotated := e.scim
	rotated.token = second["token"].(string)
	rotated.must(http.StatusOK, "GET", "/Users", nil)

	// a suspended tenant refuses provisioning
	op := client{t: t, srv: e.srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "POST", "/admin/v1/tenants/"+e.tid+":suspend", map[string]any{"reason": "unpaid"})
	rotated.must(http.StatusForbidden, "GET", "/Users", nil)

	actions := map[string]int{}
	for _, ev := range op.must(http.StatusOK, "GET", "/admin/v1/audit?tenant="+e.tid, nil)["items"].([]any) {
		actions[ev.(map[string]any)["action"].(string)]++
	}
	if actions["scim.token_created"] != 2 || actions["scim.token_revoked"] != 1 {
		t.Fatalf("audit: %v", actions)
	}
}

// TestSCIMOkta replays the requests Okta sends: user lookup, create, read, replace, deactivate and reactivate
// through PATCH, group push with rename, member add and remove, PUT and delete, then user deletion.
func TestSCIMOkta(t *testing.T) {
	e := setupSCIM(t)
	c := e.scim
	if got := c.must(http.StatusOK, "GET", "/Users"+filterQuery(`userName eq "test.user@acme.test"`)+
		"&startIndex=1&count=100", nil); got["totalResults"] != 0.0 || len(listed(got)) != 0 {
		t.Fatalf("lookup before create: %v", got)
	}
	code, user, h := c.call("POST", "/Users", fixture(t, "okta", "create_user", nil))
	if code != http.StatusCreated || h.Get("ETag") == "" || !strings.HasSuffix(h.Get("Location"), "/Users/"+user["id"].(string)) {
		t.Fatalf("create: %d %v %v", code, user, h)
	}
	uid := user["id"].(string)
	if user["userName"] != "test.user@acme.test" || user["active"] != true || user["password"] != nil ||
		user["externalId"] != "00ujl29u0le5T6Aj10h7" || user["locale"] != "en-US" {
		t.Fatalf("created user: %v", user)
	}
	acct := e.fake.Account(uid)
	if acct == nil || acct["email"] != "test.user@acme.test" || acct["firstName"] != "Test" || acct["emailVerified"] != true {
		t.Fatalf("keycloak account: %v", acct)
	}
	if memberStatus(t, e.owner, e.tid, uid) != "active" || !slices.Equal(grantedRoles(t, e.owner, e.tid, uid), []string{"devflow:operator"}) {
		t.Fatalf("membership: %s %v", memberStatus(t, e.owner, e.tid, uid), grantedRoles(t, e.owner, e.tid, uid))
	}
	// Okta retries a create it thinks failed: the user exists, 409 uniqueness, then it matches by filter
	code, out, _ := c.call("POST", "/Users", fixture(t, "okta", "create_user", nil))
	if code != http.StatusConflict || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	if got := c.must(http.StatusOK, "GET", "/Users"+filterQuery(`userName eq "TEST.USER@acme.test"`), nil); len(listed(got)) != 1 {
		t.Fatalf("lookup is case-insensitive: %v", got)
	}

	got := c.must(http.StatusOK, "GET", "/Users/"+uid, nil)
	etag := got["meta"].(map[string]any)["version"].(string)
	if code, _, _ := c.call("GET", "/Users/"+uid, nil, "If-None-Match", etag); code != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", code)
	}
	replaced := c.must(http.StatusOK, "PUT", "/Users/"+uid, fixture(t, "okta", "replace_user", map[string]string{"user_id": uid}))
	if replaced["displayName"] != "Another User" || replaced["name"].(map[string]any)["middleName"] != "Mid" ||
		e.fake.Account(uid)["firstName"] != "Another" {
		t.Fatalf("replace: %v %v", replaced, e.fake.Account(uid))
	}
	// the same PUT again changes nothing, not even the version
	again := c.must(http.StatusOK, "PUT", "/Users/"+uid, fixture(t, "okta", "replace_user", map[string]string{"user_id": uid}))
	if again["meta"].(map[string]any)["version"] != replaced["meta"].(map[string]any)["version"] {
		t.Fatalf("idempotent PUT moved the version")
	}
	c.must(http.StatusPreconditionFailed, "PUT", "/Users/"+uid, fixture(t, "okta", "replace_user",
		map[string]string{"user_id": uid}), "If-Match", etag)

	// deactivation signs the person out at once and deactivates the membership
	e.fake.AddSession(uid, "10.0.0.1", "devflow")
	off := c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "okta", "deactivate_user", nil))
	e.fake.Lock()
	loggedOut := slices.Contains(e.fake.Logouts, uid) && len(e.fake.Sessions[uid]) == 0
	e.fake.Unlock()
	if off["active"] != false || !loggedOut || memberStatus(t, e.owner, e.tid, uid) != "deactivated" {
		t.Fatalf("deactivate: %v logged out %v member %s", off, loggedOut, memberStatus(t, e.owner, e.tid, uid))
	}
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "okta", "reactivate_user", nil))
	if memberStatus(t, e.owner, e.tid, uid) != "active" {
		t.Fatal("reactivate")
	}

	// group push: the group's name maps to devflow admin
	e.owner.must(http.StatusCreated, "POST", "/v1/tenants/"+e.tid+"/scim/group-mappings",
		map[string]any{"group": "engineering", "app": "devflow", "role": "admin"})
	g := c.must(http.StatusCreated, "POST", "/Groups", fixture(t, "okta", "create_group", nil))
	gid := g["id"].(string)
	vars := map[string]string{"user_id": uid, "group_id": gid}
	code, _, _ = c.call("PATCH", "/Groups/"+gid, fixture(t, "okta", "add_members", vars))
	if code != http.StatusNoContent || len(grantedRoles(t, e.owner, e.tid, uid)) != 1 {
		t.Fatalf("add to an unmapped group: %d %v", code, grantedRoles(t, e.owner, e.tid, uid))
	}
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "okta", "rename_group", vars))
	if r := grantedRoles(t, e.owner, e.tid, uid); !slices.Equal(r, []string{"devflow:admin", "devflow:operator"}) {
		t.Fatalf("renamed to a mapped name: %v", r)
	}
	found := c.must(http.StatusOK, "GET", "/Groups"+filterQuery(`displayName eq "Engineering"`)+"&startIndex=1&count=100", nil)
	if len(listed(found)) != 1 || len(listed(found)[0].(map[string]any)["members"].([]any)) != 1 {
		t.Fatalf("group lookup: %v", found)
	}
	if u := c.must(http.StatusOK, "GET", "/Users/"+uid, nil); len(u["groups"].([]any)) != 1 {
		t.Fatalf("user's groups: %v", u["groups"])
	}
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "okta", "remove_members", vars))
	if r := grantedRoles(t, e.owner, e.tid, uid); !slices.Equal(r, []string{"devflow:operator"}) {
		t.Fatalf("removed from the group: %v", r)
	}
	put := c.must(http.StatusOK, "PUT", "/Groups/"+gid, fixture(t, "okta", "replace_group", vars))
	if len(put["members"].([]any)) != 1 || !slices.Contains(grantedRoles(t, e.owner, e.tid, uid), "devflow:admin") {
		t.Fatalf("PUT group: %v", put)
	}
	// a role the group gave is revoked with the group; deactivation also takes it away
	c.must(http.StatusNoContent, "DELETE", "/Groups/"+gid, nil)
	c.must(http.StatusNotFound, "GET", "/Groups/"+gid, nil)
	if r := grantedRoles(t, e.owner, e.tid, uid); !slices.Equal(r, []string{"devflow:operator"}) {
		t.Fatalf("group deleted: %v", r)
	}

	// deletion: SCIM created the account and the person belongs nowhere else, so it is erased
	c.must(http.StatusNoContent, "DELETE", "/Users/"+uid, nil)
	c.must(http.StatusNotFound, "GET", "/Users/"+uid, nil)
	c.must(http.StatusNotFound, "DELETE", "/Users/"+uid, nil)
	e.fake.Lock()
	erased := slices.Contains(e.fake.Deleted, uid)
	e.fake.Unlock()
	if !erased || memberStatus(t, e.owner, e.tid, uid) != "none" {
		t.Fatalf("delete: erased %v member %s", erased, memberStatus(t, e.owner, e.tid, uid))
	}
}

// TestSCIMEntra replays the requests Microsoft Entra ID sends, including its non-standard forms (string booleans,
// member removal by value list, manager as a plain id) and the enterprise extension.
func TestSCIMEntra(t *testing.T) {
	e := setupSCIM(t)
	c := e.scim
	c.must(http.StatusOK, "GET", "/Users"+filterQuery(`userName eq "Test_User_dfeef4c5-5681-4387-b016-bdf221e82081"`), nil)
	user := c.must(http.StatusCreated, "POST", "/Users", fixture(t, "entra", "create_user", nil))
	uid := user["id"].(string)
	if user["roles"] == nil || user["name"].(map[string]any)["formatted"] != "givenName familyName" {
		t.Fatalf("create: %v", user)
	}
	code, out, _ := c.call("POST", "/Users", fixture(t, "entra", "create_user", nil))
	if code != http.StatusConflict || out["scimType"] != "uniqueness" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	for _, f := range []string{`externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"`,
		`emails[type eq "work"].value eq "test_user_fd0ea19b-0777-472c-9f96-4f70d2226f2e@testuser.com"`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "Test_User_ab6490ee-1e48-479e-a20b-2d77186b5dd1"`,
		`id eq "` + uid + `" and active eq true`} {
		if got := c.must(http.StatusOK, "GET", "/Users"+filterQuery(f), nil); got["totalResults"] != 1.0 {
			t.Fatalf("filter %s: %v", f, got)
		}
	}
	code, out, _ = c.call("GET", "/Users"+filterQuery(`userName co "Test"`), nil)
	if code != http.StatusBadRequest || out["scimType"] != "invalidFilter" {
		t.Fatalf("unsupported filter: %d %v", code, out)
	}

	upd := c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "update_user", nil))
	if e.fake.Account(uid)["email"] != "updatedEmail@testuser.com" || e.fake.Account(uid)["lastName"] != "updatedFamilyName" ||
		upd["emails"].([]any)[0].(map[string]any)["value"] != "updatedEmail@testuser.com" {
		t.Fatalf("update: %v %v", upd, e.fake.Account(uid))
	}
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "rename_user", nil))
	ent := c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "enterprise", nil))
	ext := ent["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)
	if ext["employeeNumber"] != "701984" || ext["department"] != "Tour Operations" || ent["title"] != "Tour Guide" ||
		ext["manager"].(map[string]any)["value"] != "26118915-6090-4610-87e4-49d8ca9f808d" ||
		!slices.Contains(ent["schemas"].([]any), any("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")) {
		t.Fatalf("enterprise: %v", ent)
	}
	attrs := e.fake.Account(uid)["attributes"].(map[string]any)
	if attrs["employeeNumber"].([]any)[0] != "701984" || attrs["department"].([]any)[0] != "Tour Operations" {
		t.Fatalf("keycloak attributes: %v", attrs)
	}

	// groups: create, find without members, rename, add and remove members by value list
	e.owner.must(http.StatusCreated, "POST", "/v1/tenants/"+e.tid+"/scim/group-mappings",
		map[string]any{"group": "1879db59-3bdf-4490-ad68-ab880a269474updatedDisplayName", "app": "devflow", "role": "admin"})
	g := c.must(http.StatusCreated, "POST", "/Groups", fixture(t, "entra", "create_group", nil))
	gid := g["id"].(string)
	found := c.must(http.StatusOK, "GET", "/Groups?excludedAttributes=members&filter="+url.QueryEscape(`displayName eq "displayName"`), nil)
	if len(listed(found)) != 1 || listed(found)[0].(map[string]any)["members"] != nil {
		t.Fatalf("group lookup: %v", found)
	}
	if one := c.must(http.StatusOK, "GET", "/Groups/"+gid+"?excludedAttributes=members", nil); one["members"] != nil ||
		one["externalId"] != "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159" {
		t.Fatalf("group: %v", one)
	}
	vars := map[string]string{"user_id": uid}
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "entra", "rename_group", nil))
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "entra", "add_member", vars))
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "entra", "add_member", vars)) // a retry is harmless
	if r := grantedRoles(t, e.owner, e.tid, uid); !slices.Equal(r, []string{"devflow:admin", "devflow:operator"}) {
		t.Fatalf("added: %v", r)
	}
	if got := c.must(http.StatusOK, "GET", "/Groups"+filterQuery(`members[value eq "`+uid+`"]`), nil); got["totalResults"] != 1.0 {
		t.Fatalf("member filter: %v", got)
	}
	// disabling (also the older "False" string form) revokes group-made grants with the membership
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "disable_user_legacy", nil))
	if memberStatus(t, e.owner, e.tid, uid) != "deactivated" || slices.Contains(grantedRoles(t, e.owner, e.tid, uid), "devflow:admin") {
		t.Fatalf("disable: %s %v", memberStatus(t, e.owner, e.tid, uid), grantedRoles(t, e.owner, e.tid, uid))
	}
	e.fake.Lock()
	e.fake.Logouts = nil
	e.fake.Unlock()
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "disable_user", nil)) // retried: signs out again
	e.fake.Lock()
	again := slices.Contains(e.fake.Logouts, uid)
	e.fake.Unlock()
	if !again {
		t.Fatal("a repeated deactivation did not sign out")
	}
	c.must(http.StatusOK, "PATCH", "/Users/"+uid, fixture(t, "entra", "enable_user", nil))
	if !slices.Contains(grantedRoles(t, e.owner, e.tid, uid), "devflow:admin") {
		t.Fatal("re-enabled user did not get the group's role back")
	}
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "entra", "remove_member", vars))
	if slices.Contains(grantedRoles(t, e.owner, e.tid, uid), "devflow:admin") {
		t.Fatal("removed member kept the role")
	}
	// mapping removal revokes, mapping creation grants to current members
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, fixture(t, "entra", "add_member", vars))
	maps := e.owner.must(http.StatusOK, "GET", "/v1/tenants/"+e.tid+"/scim/group-mappings", nil)["items"].([]any)
	e.owner.must(http.StatusNoContent, "DELETE", "/v1/tenants/"+e.tid+"/scim/group-mappings/"+maps[0].(map[string]any)["id"].(string), nil)
	if slices.Contains(grantedRoles(t, e.owner, e.tid, uid), "devflow:admin") {
		t.Fatal("mapping removed, role kept")
	}
	c.must(http.StatusNoContent, "DELETE", "/Users/"+uid, nil)
	if got := c.must(http.StatusOK, "GET", "/Groups/"+gid, nil); len(got["members"].([]any)) != 0 {
		t.Fatalf("deleted user still a member: %v", got)
	}
}

// TestSCIMLinkingAndLimits: existing accounts are linked (and never erased), people who joined through SSO are
// adopted, addresses outside the verified domains are refused, the plan's member limit holds, and pagination works.
func TestSCIMLinkingAndLimits(t *testing.T) {
	e := setupSCIM(t)
	c := e.scim

	code, out, _ := c.call("POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "eve@elsewhere.test"})
	if code != http.StatusBadRequest || out["scimType"] != "invalidValue" {
		t.Fatalf("unverified domain: %d %v", code, out)
	}
	c.must(http.StatusBadRequest, "POST", "/Users", map[string]any{"userName": "no-email"})
	c.must(http.StatusBadRequest, "POST", "/Users", map[string]any{"schemas": []string{"urn:x"}, "userName": "a@acme.test"})

	// an account that exists already is linked, and survives deprovisioning
	kid := e.fake.AddAccount("Linda@acme.test", "Linda", "L")
	linked := c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "linda@acme.test",
		"name": map[string]any{"givenName": "Linda", "familyName": "Lee"}})
	if linked["id"] != kid || e.fake.Account(kid)["lastName"] != "Lee" {
		t.Fatalf("linked: %v", linked)
	}
	c.must(http.StatusNoContent, "DELETE", "/Users/"+kid, nil)
	e.fake.Lock()
	erased := slices.Contains(e.fake.Deleted, kid)
	e.fake.Unlock()
	if erased || e.fake.Account(kid) == nil {
		t.Fatal("a linked account was erased")
	}

	// someone who joined through SSO (here: added by the owner) is adopted, not added twice
	jid := e.fake.AddAccount("jit@acme.test", "Jit", "User")
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/me", nil)
	req.Header.Set("X-Matura-Dev-User", jid)
	req.Header.Set("X-Matura-Dev-Email", "jit@acme.test")
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 200 {
		t.Fatalf("jit sign-in: %v", err)
	}
	e.owner.must(http.StatusCreated, "POST", "/v1/tenants/"+e.tid+"/members", map[string]any{"user_id": jid})
	adopted := c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "jit@acme.test"})
	if adopted["id"] != jid || memberStatus(t, e.owner, e.tid, jid) != "active" {
		t.Fatalf("adopt: %v", adopted)
	}
	// the tenant's only owner, adopted, cannot be deactivated or deleted through SCIM
	verifyDomain(t, e.owner, e.dns, e.tid, "example.test")
	ownerEmail := e.owner.user.String()[24:] + "@example.test"
	e.fake.Lock()
	e.fake.Accounts[e.owner.user.String()] = map[string]any{"id": e.owner.user.String(), "email": ownerEmail,
		"username": ownerEmail, "enabled": true}
	e.fake.Unlock()
	own := c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": ownerEmail})
	code, out, _ = c.call("PATCH", "/Users/"+own["id"].(string), map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}}})
	if code != http.StatusBadRequest || memberStatus(t, e.owner, e.tid, own["id"].(string)) != "active" {
		t.Fatalf("last owner deactivated: %d %v", code, out)
	}
	c.must(http.StatusBadRequest, "DELETE", "/Users/"+own["id"].(string), nil)

	// plan limit: two seats are taken (alice, jit; removed members do not count); a plan of three allows one more
	op := client{t: t, srv: e.srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/plans/small", map[string]any{"name": "Small",
		"limits": map[string]any{"max_members": 3}})
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+e.tid+"/plan", map[string]any{"plan": "small"})
	c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "p1@acme.test"})
	code, out, _ = c.call("POST", "/Users", map[string]any{"userName": "p2@acme.test"})
	if code != http.StatusForbidden || !strings.Contains(out["detail"].(string), "plan") {
		t.Fatalf("plan limit: %d %v", code, out)
	}
	if e.fakeHasEmail("p2@acme.test") {
		t.Fatal("the Keycloak account made for a refused user was left behind")
	}
	op.must(http.StatusOK, "PUT", "/admin/v1/tenants/"+e.tid+"/plan", map[string]any{"plan": nil})

	// pagination
	for _, n := range []string{"a", "b", "c"} {
		c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": n + "@acme.test"},
			"Idempotency-Key", "create-"+n)
	}
	// a retry with the same Idempotency-Key replays the response instead of failing with 409
	_, _, h := c.call("POST", "/Users", map[string]any{"userName": "a@acme.test"}, "Idempotency-Key", "create-a")
	if h.Get("Idempotency-Replayed") != "true" {
		t.Fatal("Idempotency-Key was not honoured")
	}
	page := c.must(http.StatusOK, "GET", "/Users?startIndex=2&count=2", nil)
	if page["totalResults"] != 6.0 || page["startIndex"] != 2.0 || page["itemsPerPage"] != 2.0 {
		t.Fatalf("page: %v", page)
	}
	if n := c.must(http.StatusOK, "GET", "/Users?count=0", nil); n["totalResults"] != 6.0 || len(listed(n)) != 0 {
		t.Fatalf("count=0: %v", n)
	}
	if a := c.must(http.StatusOK, "GET", "/Users?attributes=userName&count=1", nil); len(listed(a)[0].(map[string]any)) != 4 {
		t.Fatalf("attributes=userName: %v", a)
	}
}

func (e scimEnv) fakeHasEmail(email string) bool {
	e.fake.Lock()
	defer e.fake.Unlock()
	for _, a := range e.fake.Accounts {
		if a["email"] == email {
			return true
		}
	}
	return false
}

// TestSCIMCrossTenant: one tenant's SCIM token never sees or changes another tenant's users and groups.
func TestSCIMCrossTenant(t *testing.T) {
	e := setupSCIM(t)
	gina := client{t: t, srv: e.srv, user: ids.New()}
	globex := gina.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	gtid := globex["id"].(string)
	verifyDomain(t, gina, e.dns, gtid, "globex.test")
	gtok := gina.must(http.StatusCreated, "POST", "/v1/tenants/"+gtid+"/scim/tokens", map[string]any{"name": "idp"})
	g := scimClient{t: t, base: gtok["scim_base_url"].(string), token: gtok["token"].(string)}

	u := e.scim.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "ann@acme.test"})
	uid := u["id"].(string)
	grp := e.scim.must(http.StatusCreated, "POST", "/Groups", map[string]any{"displayName": "Staff",
		"members": []any{map[string]any{"value": uid}}})
	gid := grp["id"].(string)

	// globex cannot provision acme's domain
	g.must(http.StatusBadRequest, "POST", "/Users", map[string]any{"userName": "bob@acme.test"})
	for _, p := range []string{"/Users/" + uid, "/Groups/" + gid} {
		g.must(http.StatusNotFound, "GET", p, nil)
		g.must(http.StatusNotFound, "PATCH", p, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}}})
		g.must(http.StatusNotFound, "DELETE", p, nil)
	}
	g.must(http.StatusNotFound, "PUT", "/Users/"+uid, map[string]any{"userName": "ann@globex.test"})
	if l := g.must(http.StatusOK, "GET", "/Users"+filterQuery(`userName eq "ann@acme.test"`), nil); l["totalResults"] != 0.0 {
		t.Fatalf("globex sees acme's user: %v", l)
	}
	if l := g.must(http.StatusOK, "GET", "/Groups", nil); l["totalResults"] != 0.0 {
		t.Fatalf("globex sees acme's groups: %v", l)
	}
	// nor put acme's user in its own group
	code, out, _ := g.call("POST", "/Groups", map[string]any{"displayName": "Mixed", "members": []any{map[string]any{"value": uid}}})
	if code != http.StatusBadRequest {
		t.Fatalf("cross-tenant member: %d %v", code, out)
	}
	// globex's owner cannot use acme's admin endpoints
	gina.must(http.StatusNotFound, "GET", "/v1/tenants/"+e.tid+"/scim/tokens", nil)
	gina.must(http.StatusNotFound, "GET", "/v1/tenants/"+e.tid+"/scim/group-mappings", nil)
	if memberStatus(t, e.owner, e.tid, uid) != "active" {
		t.Fatal("acme's user changed")
	}
}

// TestSCIMGroupsInOpenFGA: SCIM group membership is mirrored as group#member tuples by the permissions syncer.
func TestSCIMGroupsInOpenFGA(t *testing.T) {
	fake := fgatest.New(t)
	kcFake := keycloaktest.New(t)
	kc, err := keycloak.New(keycloak.Config{BaseURL: kcFake.URL, Realm: keycloaktest.Realm,
		ClientID: keycloaktest.ClientID, ClientSecret: keycloaktest.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	st := store.New(testdb.New(t))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := api.New(st, api.DevAuthenticator{}, keys, log)
	svc := &access.Service{Client: &fga.Client{URL: fake.URL}, Store: st, StoreName: "matura-" + ids.New().String()[:8], Log: log}
	server.SetAccess(svc)
	server.SetKeycloak(kc, kcFake.Issuer())
	dns := &fakeDNS{txt: map[string][]string{}}
	server.SetResolver(dns)
	srv := httptest.NewServer(server.Handler())
	t.Cleanup(srv.Close)
	syncer := &access.Syncer{Service: svc}
	round := func() {
		t.Helper()
		if err := syncer.Round(context.Background()); err != nil {
			t.Fatalf("sync round: %v", err)
		}
	}

	alice := client{t: t, srv: srv, user: ids.New()}
	tid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	verifyDomain(t, alice, dns, tid, "acme.test")
	tok := alice.must(http.StatusCreated, "POST", "/v1/tenants/"+tid+"/scim/tokens", map[string]any{"name": "idp"})
	c := scimClient{t: t, base: tok["scim_base_url"].(string), token: tok["token"].(string)}
	round()
	uid := c.must(http.StatusCreated, "POST", "/Users", map[string]any{"userName": "ann@acme.test"})["id"].(string)
	gid := c.must(http.StatusCreated, "POST", "/Groups", map[string]any{"displayName": "Staff",
		"members": []any{map[string]any{"value": uid}}})["id"].(string)
	round()
	tuple := func() bool {
		return fake.Has(fga.UserSubject(uuid.MustParse(tid), uuid.MustParse(uid)), "member",
			fga.GroupObject(uuid.MustParse(tid), uuid.MustParse(gid)))
	}
	if !tuple() {
		t.Fatalf("group member not mirrored: %v", fake.Tuples())
	}
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "remove", "path": `members[value eq "` + uid + `"]`}}})
	round()
	if tuple() {
		t.Fatal("removed member still mirrored")
	}
	// a full resync writes current group members again
	c.must(http.StatusNoContent, "PATCH", "/Groups/"+gid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": uid}}}}})
	fake.Wipe()
	_ = syncer.Round(context.Background()) // finds the store gone; the next round sets it up and writes every fact
	round()
	if !tuple() {
		t.Fatalf("resync lost the group member: %v", fake.Tuples())
	}
}
