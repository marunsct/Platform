package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// matura import: people, their organisations and roles from another identity system (TS27, technical
// specification §5.4). Each source's export is converted to Matura's import format and sent to
// POST /admin/v1/users:import in batches, owners first so their organisations exist before others join.

// ImportUser is one person in Matura's import format.
type ImportUser struct {
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	FirstName     string         `json:"first_name,omitempty"`
	LastName      string         `json:"last_name,omitempty"`
	Disabled      bool           `json:"disabled,omitempty"`
	Source        string         `json:"source"`
	ExternalID    string         `json:"external_id,omitempty"`
	Tenants       []ImportTenant `json:"tenants,omitempty"`
}

// ImportTenant is a membership of an ImportUser.
type ImportTenant struct {
	Slug       string          `json:"slug"`
	Name       string          `json:"name,omitempty"`
	TenantRole string          `json:"tenant_role,omitempty"`
	AppRoles   []ImportAppRole `json:"app_roles,omitempty"`
}

// ImportAppRole is an app role in a membership.
type ImportAppRole struct {
	App  string `json:"app"`
	Role string `json:"role"`
}

// importOptions shape a conversion.
type importOptions struct {
	Tenant      string            // put everyone in this tenant (slug) when the export has no organisations
	TenantName  string            // its name
	Role        string            // tenant role for them (default member)
	Owners      map[string]bool   // emails made owners of --tenant
	RoleMap     map[string]string // source role → tenant role (owner, admin, billing, member)
	AppRole     string            // app:role given to everyone imported into a tenant
	GroupPrefix string            // keycloak: groups under this path become tenants (e.g. /orgs/)
}

func (o importOptions) tenantRole(src string) string {
	if r, ok := o.RoleMap[strings.ToLower(src)]; ok {
		return r
	}
	switch strings.ToLower(strings.TrimPrefix(strings.ToLower(src), "org:")) {
	case "owner":
		return "owner"
	case "admin", "administrator":
		return "admin"
	case "billing":
		return "billing"
	}
	return "member"
}

func (o importOptions) single(u *ImportUser) {
	if o.Tenant == "" || len(u.Tenants) > 0 {
		return
	}
	role := o.Role
	if role == "" {
		role = "member"
	}
	if o.Owners[strings.ToLower(u.Email)] {
		role = "owner"
	}
	u.Tenants = []ImportTenant{{Slug: o.Tenant, Name: o.TenantName, TenantRole: role}}
}

func (o importOptions) appRoles(users []ImportUser) error {
	if o.AppRole == "" {
		return nil
	}
	app, role, ok := strings.Cut(o.AppRole, ":")
	if !ok || app == "" || role == "" {
		return errors.New("--app-role must be app:role")
	}
	for i := range users {
		for j := range users[i].Tenants {
			users[i].Tenants[j].AppRoles = append(users[i].Tenants[j].AppRoles, ImportAppRole{App: app, Role: role})
		}
	}
	return nil
}

// readRecords reads a JSON array, JSON lines (Auth0's bulk export) or a single object holding an array under key.
func readRecords(raw []byte, key string) ([]map[string]any, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\ufeff")))
	if len(raw) == 0 {
		return nil, errors.New("the file is empty")
	}
	var list []map[string]any
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		return list, nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err == nil && key != "" {
			if arr, ok := obj[key].([]any); ok {
				for _, it := range arr {
					if m, ok := it.(map[string]any); ok {
						list = append(list, m)
					}
				}
				return list, nil
			}
		}
		dec := json.NewDecoder(bytes.NewReader(raw)) // JSON lines
		for dec.More() {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				return nil, err
			}
			list = append(list, m)
		}
		return list, nil
	}
	return nil, errors.New("expected JSON (an array, JSON lines or an object)")
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func boolean(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// fromAuth0 converts Auth0's user export (bulk export job, JSON or JSON lines). Organisations are not in it: use
// --tenant, or app_metadata.tenant (slug) and app_metadata.tenant_role when the app kept them there.
func fromAuth0(raw []byte, o importOptions) ([]ImportUser, error) {
	recs, err := readRecords(raw, "users")
	if err != nil {
		return nil, err
	}
	out := make([]ImportUser, 0, len(recs))
	for _, r := range recs {
		u := ImportUser{Email: str(r, "email"), EmailVerified: boolean(r, "email_verified"), FirstName: str(r, "given_name"),
			LastName: str(r, "family_name"), Disabled: boolean(r, "blocked"), Source: "auth0", ExternalID: str(r, "user_id")}
		if u.FirstName == "" && u.LastName == "" {
			u.FirstName = str(r, "name")
		}
		if slug := str(r, "app_metadata", "tenant"); slug != "" {
			u.Tenants = []ImportTenant{{Slug: slug, TenantRole: o.tenantRole(str(r, "app_metadata", "tenant_role"))}}
		}
		o.single(&u)
		out = append(out, u)
	}
	return out, o.appRoles(out)
}

// fromClerk converts Clerk's Backend API users (GET /v1/users, JSON) or the dashboard's CSV export, with the
// organisation memberships (GET /v1/organization_memberships, JSON) when given.
func fromClerk(raw, memberships []byte, o importOptions) ([]ImportUser, error) {
	var out []ImportUser
	byID := map[string]int{}
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] != '[' && t[0] != '{' {
		rd := csv.NewReader(bytes.NewReader(t))
		rows, err := rd.ReadAll()
		if err != nil {
			return nil, err
		}
		if len(rows) < 1 {
			return nil, errors.New("empty CSV")
		}
		col := map[string]int{}
		for i, h := range rows[0] {
			col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
		}
		get := func(row []string, k string) string {
			if i, ok := col[k]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		for _, row := range rows[1:] {
			u := ImportUser{Email: get(row, "primary_email_address"), EmailVerified: true, FirstName: get(row, "first_name"),
				LastName: get(row, "last_name"), Source: "clerk", ExternalID: get(row, "id")}
			byID[u.ExternalID] = len(out)
			out = append(out, u)
		}
	} else {
		recs, err := readRecords(raw, "data")
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			primary := str(r, "primary_email_address_id")
			u := ImportUser{FirstName: str(r, "first_name"), LastName: str(r, "last_name"), Disabled: boolean(r, "banned") ||
				boolean(r, "locked"), Source: "clerk", ExternalID: str(r, "id")}
			if list, ok := r["email_addresses"].([]any); ok {
				for _, e := range list {
					em, _ := e.(map[string]any)
					if em == nil || (primary != "" && str(em, "id") != primary) {
						continue
					}
					u.Email = str(em, "email_address")
					u.EmailVerified = str(em, "verification", "status") == "verified"
					break
				}
			}
			byID[u.ExternalID] = len(out)
			out = append(out, u)
		}
	}
	if len(memberships) > 0 {
		recs, err := readRecords(memberships, "data")
		if err != nil {
			return nil, fmt.Errorf("memberships: %w", err)
		}
		for _, m := range recs {
			i, ok := byID[str(m, "public_user_data", "user_id")]
			if !ok {
				continue
			}
			slug := str(m, "organization", "slug")
			if slug == "" {
				continue
			}
			out[i].Tenants = append(out[i].Tenants, ImportTenant{Slug: slug, Name: str(m, "organization", "name"),
				TenantRole: o.tenantRole(str(m, "role"))})
		}
	}
	for i := range out {
		o.single(&out[i])
	}
	return out, o.appRoles(out)
}

// fromKeycloak converts a realm export (realm-export.json, its users) or a users export (*-users-*.json). Groups
// under --group-prefix become tenants (a group /orgs/acme makes tenant acme); a group /orgs/acme/admins makes its
// members admins of it.
func fromKeycloak(raw []byte, o importOptions) ([]ImportUser, error) {
	recs, err := readRecords(raw, "users")
	if err != nil {
		return nil, err
	}
	out := make([]ImportUser, 0, len(recs))
	for _, r := range recs {
		if str(r, "serviceAccountClientId") != "" {
			continue // service accounts become agents, not people
		}
		enabled := true
		if v, ok := r["enabled"].(bool); ok {
			enabled = v
		}
		email := str(r, "email")
		if email == "" && strings.Contains(str(r, "username"), "@") {
			email = str(r, "username")
		}
		u := ImportUser{Email: email, EmailVerified: boolean(r, "emailVerified"), FirstName: str(r, "firstName"),
			LastName: str(r, "lastName"), Disabled: !enabled, Source: "keycloak", ExternalID: str(r, "id")}
		if o.GroupPrefix != "" {
			roles := map[string]string{}
			var order []string
			groups, _ := r["groups"].([]any)
			for _, g := range groups {
				path, _ := g.(string)
				rest, ok := strings.CutPrefix(path, strings.TrimRight(o.GroupPrefix, "/")+"/")
				if !ok || rest == "" {
					continue
				}
				slug, sub, _ := strings.Cut(rest, "/")
				if _, seen := roles[slug]; !seen {
					order = append(order, slug)
					roles[slug] = "member"
				}
				if sub != "" {
					if role := o.tenantRole(strings.TrimSuffix(sub, "s")); role != "member" {
						roles[slug] = role
					}
				}
			}
			for _, slug := range order {
				u.Tenants = append(u.Tenants, ImportTenant{Slug: slug, TenantRole: roles[slug]})
			}
		}
		o.single(&u)
		out = append(out, u)
	}
	return out, o.appRoles(out)
}

// batches orders users so each tenant's owners come first, then splits into requests of at most size.
func batches(users []ImportUser, size int) [][]ImportUser {
	rank := func(u ImportUser) int {
		for _, t := range u.Tenants {
			if t.TenantRole == "owner" {
				return 0
			}
		}
		return 1
	}
	sorted := append([]ImportUser{}, users...)
	sort.SliceStable(sorted, func(i, j int) bool { return rank(sorted[i]) < rank(sorted[j]) })
	var out [][]ImportUser
	for len(sorted) > 0 {
		n := min(size, len(sorted))
		out = append(out, sorted[:n])
		sorted = sorted[n:]
	}
	return out
}

func importCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("matura import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: matura import <auth0|clerk|keycloak> --users FILE [flags]

Moves people, their organisations and roles into Matura (POST /admin/v1/users:import). Passwords are not moved:
people set a new one (--send-password-email mails them the link). Run with --dry-run first.

`)
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		return 2
	}
	source := args[0]
	base := fs.String("url", envOr("MATURA_URL", "http://localhost:8080"), "maturad's address")
	usersFile := fs.String("users", "", "the export file")
	membersFile := fs.String("memberships", "", "clerk: organization memberships (GET /v1/organization_memberships)")
	tenant := fs.String("tenant", "", "put everyone without an organisation in the export into this tenant (slug)")
	tenantName := fs.String("tenant-name", "", "the name of --tenant when it is created")
	role := fs.String("role", "member", "tenant role for people put in --tenant")
	owners := fs.String("owners", "", "comma-separated emails made owners of --tenant (one is needed to create it)")
	roleMap := setFlags{}
	fs.Var(roleMap, "map-role", "map a source role to a tenant role, source=target (repeatable), e.g. org:lead=admin")
	appRole := fs.String("app-role", "", "app:role given to everyone in every tenant they join, e.g. devflow:viewer")
	groupPrefix := fs.String("group-prefix", "", "keycloak: groups under this path become tenants, e.g. /orgs")
	sendEmail := fs.Bool("send-password-email", false, "email new accounts a link to set their password")
	dryRun := fs.Bool("dry-run", false, "print what would be imported (JSON) and send nothing")
	size := fs.Int("batch", 500, "people per request (at most 1000)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for maturad")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *usersFile == "" {
		fmt.Fprintln(stderr, "matura import: --users is required")
		return 2
	}
	raw, err := os.ReadFile(*usersFile)
	if err != nil {
		fmt.Fprintln(stderr, "matura import:", err)
		return 2
	}
	o := importOptions{Tenant: *tenant, TenantName: *tenantName, Role: *role, Owners: map[string]bool{}, RoleMap: map[string]string{},
		AppRole: *appRole, GroupPrefix: *groupPrefix}
	for _, e := range strings.Split(*owners, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			o.Owners[e] = true
		}
	}
	for k, v := range roleMap {
		o.RoleMap[strings.ToLower(k)] = v
	}
	var users []ImportUser
	switch source {
	case "auth0":
		users, err = fromAuth0(raw, o)
	case "clerk":
		var members []byte
		if *membersFile != "" {
			if members, err = os.ReadFile(*membersFile); err != nil {
				break
			}
		}
		if err == nil {
			users, err = fromClerk(raw, members, o)
		}
	case "keycloak":
		users, err = fromKeycloak(raw, o)
	default:
		fmt.Fprintf(stderr, "matura import: unknown source %q (auth0, clerk or keycloak)\n", source)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "matura import:", err)
		return 2
	}
	if *dryRun {
		writeIndented(stdout, map[string]any{"users": users, "send_password_email": *sendEmail})
		return 0
	}
	if *size <= 0 || *size > 1000 {
		*size = 500
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	token := os.Getenv("MATURA_TOKEN")
	total := map[string]int{}
	failed := false
	for _, b := range batches(users, *size) {
		res, err := sendImport(ctx, *base, token, b, *sendEmail)
		if err != nil {
			fmt.Fprintln(stderr, "matura import:", err)
			return 2
		}
		for _, k := range []string{"created", "existing", "failed"} {
			total[k] += res.counts[k]
		}
		for _, r := range res.Results {
			if r.Status == "error" {
				failed = true
				fmt.Fprintf(stdout, "error    %s: %s\n", r.Email, r.Error)
			}
			for _, issue := range r.Issues {
				failed = true
				fmt.Fprintf(stdout, "issue    %s: %s\n", r.Email, issue)
			}
		}
	}
	fmt.Fprintf(stdout, "imported %d people: %d created, %d already there, %d failed\n", len(users), total["created"],
		total["existing"], total["failed"])
	if failed {
		return 1
	}
	return 0
}

type importResponse struct {
	Results []struct {
		Email  string   `json:"email"`
		Status string   `json:"status"`
		Error  string   `json:"error"`
		Issues []string `json:"issues"`
	} `json:"results"`
	counts map[string]int
}

func sendImport(ctx context.Context, base, token string, users []ImportUser, sendEmail bool) (importResponse, error) {
	body, _ := json.Marshal(map[string]any{"users": users, "send_password_email": sendEmail})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/admin/v1/users:import",
		bytes.NewReader(body))
	if err != nil {
		return importResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return importResponse{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if res.StatusCode != http.StatusOK {
		var p struct{ Detail string }
		_ = json.Unmarshal(raw, &p)
		return importResponse{}, fmt.Errorf("maturad answered %d: %s", res.StatusCode, p.Detail)
	}
	var out importResponse
	var counts map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	_ = json.Unmarshal(raw, &counts)
	out.counts = map[string]int{}
	for _, k := range []string{"created", "existing", "failed"} {
		if f, ok := counts[k].(float64); ok {
			out.counts[k] = int(f)
		}
	}
	return out, nil
}
