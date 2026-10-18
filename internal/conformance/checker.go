package conformance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Config is what a Checker needs.
type Config struct {
	App           string // base URL of the running app, e.g. http://localhost:8000
	Manifest      *Manifest
	Issuer        *Issuer
	Audience      string // defaults to Manifest.Audience()
	WebhookSecret string // required when the manifest has a webhook path
	Client        *http.Client
	Now           func() time.Time
}

// Check statuses.
const (
	Pass = "pass"
	Fail = "fail"
	Skip = "skip"
)

// Result is one check's outcome.
type Result struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// Report is the outcome of a run. OK is true when no check failed.
type Report struct {
	App      string   `json:"app"`
	Issuer   string   `json:"issuer"`
	Audience string   `json:"audience"`
	OK       bool     `json:"ok"`
	Passed   int      `json:"passed"`
	Failed   int      `json:"failed"`
	Skipped  int      `json:"skipped"`
	Checks   []Result `json:"checks"`
}

// Failures lists the ids of the failed checks.
func (r Report) Failures() []string {
	var out []string
	for _, c := range r.Checks {
		if c.Status == Fail {
			out = append(out, c.ID)
		}
	}
	return out
}

// WriteText prints one line per check and a summary.
func (r Report) WriteText(w io.Writer) {
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%-4s  %-14s %s: %s\n", strings.ToUpper(c.Status), c.Group, c.Title, c.Reason)
	}
	verdict := "PASSED"
	if !r.OK {
		verdict = "FAILED"
	}
	fmt.Fprintf(w, "\n%s: %d passed, %d failed, %d skipped\n", verdict, r.Passed, r.Failed, r.Skipped)
}

// principal is a test user in a test tenant, with the versions its seeded rows have.
type principal struct {
	label                   string
	tenantID, slug, wid     string
	userID, email, name     string
	grantID                 string
	tver, wver, uver, mver  int64
	gver                    int64
	tenantRole, appRoleName string
}

// Checker runs the conformance checks against one app.
type Checker struct {
	cfg     Config
	a, b    *principal
	perms   []string
	version int64
	seq     int64
	results []Result
}

// New prepares a checker with two fresh random tenants.
func New(cfg Config) (*Checker, error) {
	if cfg.Manifest == nil || cfg.Manifest.Conformance == nil {
		return nil, errors.New("conformance: manifest with a conformance section is required")
	}
	if cfg.Issuer == nil {
		return nil, errors.New("conformance: issuer is required")
	}
	if _, err := url.ParseRequestURI(cfg.App); err != nil {
		return nil, fmt.Errorf("conformance: app URL: %w", err)
	}
	cfg.App = strings.TrimRight(cfg.App, "/")
	if cfg.Audience == "" {
		cfg.Audience = cfg.Manifest.Audience()
	}
	if cfg.Manifest.Conformance.WebhookPath != "" && cfg.WebhookSecret == "" {
		return nil, errors.New("conformance: a webhook secret is required when the manifest has a webhook_path")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Checker{cfg: cfg, perms: cfg.Manifest.AllPermissions()}
	c.a = c.newPrincipal("A")
	c.b = c.newPrincipal("B")
	return c, nil
}

func (c *Checker) newPrincipal(label string) *principal {
	short := randomHex(4)
	p := &principal{
		label: label, tenantID: uuid.NewString(), slug: "conformance-" + strings.ToLower(label) + "-" + short,
		wid: uuid.NewString(), userID: uuid.NewString(), grantID: uuid.NewString(),
		email: "user-" + strings.ToLower(label) + "-" + short + "@conformance.test", name: "Conformance User " + label,
		tenantRole: "member", appRoleName: c.cfg.Manifest.role(),
	}
	p.tver, p.wver, p.uver, p.mver, p.gver = c.nextVersion(), c.nextVersion(), c.nextVersion(), c.nextVersion(), c.nextVersion()
	return p
}

func (c *Checker) nextVersion() int64 { c.version++; return c.version }

// GenerateSecret returns a fresh webhook secret.
func GenerateSecret() string { return "whsec_conformance_" + randomHex(24) }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run executes every check in order and returns the report. It never panics on a misbehaving app: every
// failure becomes a failed check.
func (c *Checker) Run(ctx context.Context) Report {
	c.results = nil
	conf := c.cfg.Manifest.Conformance
	if conf.WebhookPath != "" {
		c.seed(ctx, c.a)
		c.seed(ctx, c.b)
	} else {
		c.add("seed", "seed", "seed tenants and users with events", Skip, "no conformance.webhook_path in the manifest")
	}
	for _, r := range conf.Resources {
		c.authentication(ctx, r)
	}
	for _, r := range conf.Resources {
		c.permissions(ctx, r)
	}
	for _, r := range conf.Resources {
		c.isolation(ctx, r)
	}
	if conf.WebhookPath != "" {
		c.eventChecks(ctx)
	} else {
		c.add("events", "events", "webhook signature and idempotency", Skip, "no conformance.webhook_path in the manifest")
	}
	rep := Report{App: c.cfg.App, Issuer: c.cfg.Issuer.URL(), Audience: c.cfg.Audience, Checks: c.results}
	for _, r := range c.results {
		switch r.Status {
		case Pass:
			rep.Passed++
		case Fail:
			rep.Failed++
		default:
			rep.Skipped++
		}
	}
	rep.OK = rep.Failed == 0
	return rep
}

func (c *Checker) add(id, group, title, status, reason string) {
	c.results = append(c.results, Result{ID: id, Group: group, Title: title, Status: status, Reason: reason})
}

func (c *Checker) check(id, group, title string, ok bool, reason string) {
	status := Fail
	if ok {
		status = Pass
	}
	c.add(id, group, title, status, reason)
}

// ---- tokens ----

type tokenOpt func(jwt.MapClaims)

func (c *Checker) claims(p *principal, perms []string, opts ...tokenOpt) jwt.MapClaims {
	now := c.cfg.Now()
	m := jwt.MapClaims{
		"iss": c.cfg.Issuer.URL(), "aud": c.cfg.Audience, "azp": c.cfg.Audience, "sub": p.userID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": p.email, "email_verified": true, "name": p.name,
		"tid": p.tenantID, "tenant": p.slug, "wid": p.wid,
		"troles": []string{p.tenantRole}, "roles": []string{p.appRoleName}, "perms": perms,
		"ver":   map[string]int64{"u": p.uver, "m": p.mver, "t": p.tver},
		"pmode": "shared", "sid": uuid.NewString(),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

func (c *Checker) token(p *principal, perms []string, opts ...tokenOpt) string {
	t, err := c.cfg.Issuer.Sign(c.claims(p, perms, opts...))
	if err != nil {
		return "unsignable-" + err.Error()
	}
	return t
}

func without(perms []string, drop string) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if p != drop {
			out = append(out, p)
		}
	}
	return out
}

// ---- HTTP ----

type response struct {
	status int
	body   []byte
	err    error
}

func (r response) describe() string {
	if r.err != nil {
		return "request failed: " + r.err.Error()
	}
	return "got " + strconv.Itoa(r.status)
}

func (r response) is2xx() bool { return r.err == nil && r.status >= 200 && r.status < 300 }
func (r response) is4xx() bool { return r.err == nil && r.status >= 400 && r.status < 500 }

func (c *Checker) do(ctx context.Context, method, path, token string, body []byte, header http.Header) response {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.App+path, rd)
	if err != nil {
		return response{err: err}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		return response{err: err}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return response{status: resp.StatusCode, body: b, err: err}
}

func (c *Checker) call(ctx context.Context, e Endpoint, token, marker, id string) response {
	path := strings.ReplaceAll(e.Path, "{{marker}}", marker)
	path = strings.ReplaceAll(path, "{id}", url.PathEscape(id))
	var body []byte
	if len(e.Body) > 0 {
		body = []byte(strings.ReplaceAll(string(e.Body), "{{marker}}", marker))
	}
	return c.do(ctx, e.Method, path, token, body, nil)
}

func newMarker() string { return "mconf" + randomHex(8) }

// ---- 2. authentication ----

func (c *Checker) authentication(ctx context.Context, r Resource) {
	g := "authentication"
	ep := r.List
	what := r.Name + " list (" + ep.Method + " " + ep.Path + ")"
	id := "auth/" + r.Name + "/"
	now := c.cfg.Now()

	res := c.call(ctx, ep, c.token(c.a, c.perms), "", "")
	c.check(id+"valid-token", g, what+" with a valid token → 2xx", res.is2xx(), res.describe()+want(res.is2xx(), "2xx"))

	cases := []struct {
		key, title string
		token      func() string
	}{
		{"no-token", "without a token", func() string { return "" }},
		{"expired", "with an expired token", func() string {
			return c.token(c.a, c.perms, func(m jwt.MapClaims) {
				m["iat"] = now.Add(-20 * time.Minute).Unix()
				m["exp"] = now.Add(-10 * time.Minute).Unix()
			})
		}},
		{"wrong-audience", "with a token for another audience", func() string {
			return c.token(c.a, c.perms, func(m jwt.MapClaims) {
				m["aud"] = "not-" + c.cfg.Audience
				m["azp"] = "not-" + c.cfg.Audience
			})
		}},
		{"unknown-key", "with a token signed by an unknown key", func() string {
			t, err := c.cfg.Issuer.SignUnknown(c.claims(c.a, c.perms))
			if err != nil {
				return "unsignable"
			}
			return t
		}},
		{"other-issuer", "with a token from another issuer", func() string {
			return c.token(c.a, c.perms, func(m jwt.MapClaims) {
				m["iss"] = strings.TrimSuffix(c.cfg.Issuer.URL(), RealmPath) + "/realms/other"
			})
		}},
	}
	for _, tc := range cases {
		res := c.call(ctx, ep, tc.token(), "", "")
		ok := res.err == nil && res.status == http.StatusUnauthorized
		c.check(id+tc.key, g, what+" "+tc.title+" → 401", ok, res.describe()+want(ok, "401"))
	}
}

func want(ok bool, w string) string {
	if ok {
		return ""
	}
	return ", want " + w
}

// ---- 3. permissions ----

func (c *Checker) permissions(ctx context.Context, r Resource) {
	g := "permissions"
	for _, k := range []struct {
		key string
		ep  Endpoint
	}{{"create", r.Create}, {"list", r.List}} {
		id := "perm/" + r.Name + "/" + k.key
		title := r.Name + " " + k.key + " (" + k.ep.Method + " " + k.ep.Path + ") without its permission → 403"
		if k.ep.Permission == "" {
			c.add(id, g, title, Skip, "no permission given for this endpoint in the manifest")
			continue
		}
		res := c.call(ctx, k.ep, c.token(c.a, without(c.perms, k.ep.Permission)), newMarker(), "")
		ok := res.err == nil && res.status == http.StatusForbidden
		c.check(id, g, strings.Replace(title, "its permission", k.ep.Permission, 1), ok, res.describe()+want(ok, "403"))
	}
}

// ---- 4. isolation ----

func (c *Checker) isolation(ctx context.Context, r Resource) {
	g := "isolation"
	id := "isolation/" + r.Name + "/"
	marker := newMarker()
	ta, tb := c.token(c.a, c.perms), c.token(c.b, c.perms)

	title := map[string]string{
		"create":     "tenant A creates a " + r.Name + " record → 2xx",
		"list-own":   "tenant A's " + r.Name + " list contains A's record",
		"list-other": "tenant B's " + r.Name + " list does not contain A's record",
		"read-own":   "tenant A reads its " + r.Name + " record by id → 2xx",
		"read-other": "tenant B reads A's " + r.Name + " record by id → 403 or 404",
	}
	res := c.call(ctx, r.Create, ta, marker, "")
	recID, idErr := recordID(res.body)
	created := res.is2xx()
	reason := res.describe() + want(created, "2xx")
	if created && r.Read != nil && idErr != nil {
		reason += "; " + idErr.Error()
	}
	c.check(id+"create", g, title["create"], created, reason)
	if !created {
		for _, k := range []string{"list-own", "list-other", "read-own", "read-other"} {
			if strings.HasPrefix(k, "read") && r.Read == nil {
				continue
			}
			c.add(id+k, g, title[k], Skip, "tenant A could not create a record")
		}
		return
	}

	res = c.call(ctx, r.List, ta, marker, "")
	ok := res.is2xx() && bytes.Contains(res.body, []byte(marker))
	c.check(id+"list-own", g, title["list-own"], ok, listReason(res, ok, true))

	res = c.call(ctx, r.List, tb, marker, "")
	ok = res.is2xx() && !bytes.Contains(res.body, []byte(marker))
	c.check(id+"list-other", g, title["list-other"], ok, listReason(res, ok, false))

	if r.Read == nil {
		return
	}
	if idErr != nil {
		c.add(id+"read-own", g, title["read-own"], Fail, idErr.Error())
		c.add(id+"read-other", g, title["read-other"], Skip, "no record id")
		return
	}
	res = c.call(ctx, *r.Read, ta, marker, recID)
	c.check(id+"read-own", g, title["read-own"], res.is2xx(),
		res.describe()+want(res.is2xx(), "2xx")+" (id "+recID+")")
	res = c.call(ctx, *r.Read, tb, marker, recID)
	ok = res.err == nil && (res.status == http.StatusForbidden || res.status == http.StatusNotFound)
	c.check(id+"read-other", g, title["read-other"], ok,
		res.describe()+want(ok, "403 or 404")+" (id "+recID+")")
}

func listReason(res response, ok, wantMarker bool) string {
	if !res.is2xx() {
		return res.describe() + ", want 2xx"
	}
	switch {
	case ok && wantMarker:
		return res.describe() + ", marker found"
	case ok:
		return res.describe() + ", marker absent"
	case wantMarker:
		return res.describe() + ", but the marker is missing from the response"
	}
	return res.describe() + ", but the response contains tenant A's marker: data leaks across tenants"
}

// recordID reads "id" or "data.id" (string or number) from a create response.
func recordID(body []byte) (string, error) {
	var v struct {
		ID   json.RawMessage `json:"id"`
		Data struct {
			ID json.RawMessage `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", errors.New("create response is not a JSON object with an id")
	}
	for _, raw := range []json.RawMessage{v.ID, v.Data.ID} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s, nil
		}
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			return n.String(), nil
		}
	}
	return "", errors.New(`create response has no "id" or "data.id"`)
}

// ---- events ----

// event builds a CloudEvents envelope as maturad sends it (contract §5).
func (c *Checker) event(typ, subject, tenantID, object string, version int64, payload any) (string, []byte) {
	c.seq++
	id := "evt_conformance_" + uuid.NewString()
	env := map[string]any{
		"specversion": "1.0", "id": id, "source": "matura://conformance", "type": typ,
		"time": c.cfg.Now().UTC().Format(time.RFC3339), "subject": subject, "sequence": strconv.FormatInt(c.seq, 10),
		"datacontenttype": "application/json",
		"data":            map[string]any{"object": object, "version": version, object: payload},
	}
	if tenantID != "" {
		env["tenantid"] = tenantID
	}
	b, _ := json.Marshal(env)
	return id, b
}

// Sign returns a Matura-Signature header value: t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>.
func Sign(secret string, at time.Time, body []byte) string {
	t := strconv.FormatInt(at.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(t + "."))
	m.Write(body)
	return "t=" + t + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

func (c *Checker) post(ctx context.Context, id string, body []byte, signature string) response {
	h := http.Header{}
	h.Set("Content-Type", "application/cloudevents+json")
	h.Set("Matura-Event-Id", id)
	if signature != "" {
		h.Set("Matura-Signature", signature)
	}
	return c.do(ctx, http.MethodPost, c.cfg.Manifest.Conformance.WebhookPath, "", body, h)
}

func (c *Checker) postSigned(ctx context.Context, id string, body []byte) response {
	return c.post(ctx, id, body, Sign(c.cfg.WebhookSecret, c.cfg.Now(), body))
}

// ---- 1. seeding ----

func (c *Checker) seed(ctx context.Context, p *principal) {
	now := c.cfg.Now().UTC().Format(time.RFC3339)
	tenantSubj := "tenants/" + p.tenantID
	type ev struct {
		typ, subject, object string
		version              int64
		payload              any
	}
	evs := []ev{
		{"matura.tenant.created", tenantSubj, "tenant", p.tver, map[string]any{
			"id": p.tenantID, "slug": p.slug, "name": "Conformance Tenant " + p.label, "kind": "company",
			"status": "active", "plan": nil, "data_mode_default": "shared", "data_mode": "shared",
			"version": p.tver, "created_at": now, "updated_at": now}},
		{"matura.workspace.created", tenantSubj + "/workspaces/" + p.wid, "workspace", p.wver, map[string]any{
			"id": p.wid, "tenant_id": p.tenantID, "name": "Default", "status": "active", "is_default": true,
			"version": p.wver, "updated_at": now}},
		{"matura.user.updated", "users/" + p.userID, "user", p.uver, map[string]any{
			"id": p.userID, "email": p.email, "email_verified": true, "display_name": p.name, "locale": nil,
			"kind": "human", "status": "active", "version": p.uver, "updated_at": now}},
		{"matura.membership.added", tenantSubj + "/members/" + p.userID, "membership", p.mver, map[string]any{
			"tenant_id": p.tenantID, "user_id": p.userID, "tenant_role": p.tenantRole, "status": "active",
			"joined_at": now, "version": p.mver, "updated_at": now}},
		{"matura.grant.added", tenantSubj + "/grants/" + p.grantID, "grant", p.gver, map[string]any{
			"id": p.grantID, "tenant_id": p.tenantID, "app": c.cfg.Manifest.Slug, "workspace_id": nil,
			"subject_type": "user", "subject_id": p.userID, "role": p.appRoleName, "status": "active",
			"version": p.gver, "updated_at": now}},
	}
	for _, e := range evs {
		tid := p.tenantID
		if e.object == "user" {
			tid = ""
		}
		id, body := c.event(e.typ, e.subject, tid, e.object, e.version, e.payload)
		res := c.postSigned(ctx, id, body)
		if !res.is2xx() {
			c.check("seed/tenant-"+strings.ToLower(p.label), "seed", "seed tenant "+p.label+" with signed events → 2xx",
				false, e.typ+": "+res.describe()+", want 2xx")
			return
		}
	}
	c.check("seed/tenant-"+strings.ToLower(p.label), "seed", "seed tenant "+p.label+" with signed events → 2xx",
		true, fmt.Sprintf("%d events accepted", len(evs)))
}

// ---- 5. events ----

func (c *Checker) eventChecks(ctx context.Context) {
	g := "events"
	p := c.a
	userEvent := func(name string) (string, []byte) {
		v := c.nextVersion()
		now := c.cfg.Now().UTC().Format(time.RFC3339)
		return c.event("matura.user.updated", "users/"+p.userID, "", "user", v, map[string]any{
			"id": p.userID, "email": p.email, "email_verified": true, "display_name": name, "locale": nil,
			"kind": "human", "status": "active", "version": v, "updated_at": now})
	}

	id, body := userEvent(p.name)
	sig := Sign(c.cfg.WebhookSecret, c.cfg.Now(), body)
	res := c.post(ctx, id, body, sig)
	c.check("events/valid", g, "a validly signed event → 2xx", res.is2xx(), res.describe()+want(res.is2xx(), "2xx"))

	res = c.post(ctx, id, body, Sign(c.cfg.WebhookSecret, c.cfg.Now(), body))
	c.check("events/duplicate", g, "the same event delivered again → 2xx (idempotent)", res.is2xx(),
		res.describe()+want(res.is2xx(), "2xx"))

	// A changed body under the first event's signature. It gets its own id so de-duplication cannot hide a
	// missing signature check.
	id2, body2 := userEvent("Tampered " + p.name)
	res = c.post(ctx, id2, body2, sig)
	c.check("events/changed-body", g, "a changed body with the old signature → 4xx", res.is4xx(),
		res.describe()+want(res.is4xx(), "4xx"))

	id3, body3 := userEvent(p.name)
	res = c.post(ctx, id3, body3, Sign(c.cfg.WebhookSecret, c.cfg.Now().Add(-10*time.Minute), body3))
	c.check("events/stale-timestamp", g, "a signature timestamped 10 minutes ago → 4xx", res.is4xx(),
		res.describe()+want(res.is4xx(), "4xx"))

	id4, body4 := userEvent(p.name)
	res = c.post(ctx, id4, body4, Sign(GenerateSecret(), c.cfg.Now(), body4))
	c.check("events/other-secret", g, "a signature made with another secret → 4xx", res.is4xx(),
		res.describe()+want(res.is4xx(), "4xx"))

	id5, body5 := userEvent(p.name)
	res = c.post(ctx, id5, body5, "")
	c.check("events/unsigned", g, "an event without a Matura-Signature header → 4xx", res.is4xx(),
		res.describe()+want(res.is4xx(), "4xx"))
}

// WaitForApp polls url until it answers any HTTP response, or the timeout passes.
func WaitForApp(ctx context.Context, appURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	var last error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, appURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("app at %s did not answer within %s: %w", appURL, timeout, last)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
