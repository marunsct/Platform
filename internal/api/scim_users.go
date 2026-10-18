package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// SCIM Users: people provisioned into the tenant, backed by Keycloak accounts (created, or linked by email when the
// address is in one of the tenant's verified domains) and tenant memberships.

// scimUserExtra are the core User attributes kept as sent, besides the ones Matura models.
var scimUserExtra = map[string]string{}

func init() {
	for _, k := range []string{"name", "nickName", "profileUrl", "title", "userType", "preferredLanguage", "locale",
		"timezone", "phoneNumbers", "addresses", "ims", "photos", "roles", "entitlements", "x509Certificates"} {
		scimUserExtra[strings.ToLower(k)] = k
	}
}

var scimEnterpriseAttrs = []string{"employeeNumber", "costCenter", "organization", "division", "department", "manager"}

func scimString(v any, field string) (*string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		if x = strings.TrimSpace(x); x == "" {
			return nil, nil
		}
		return &x, nil
	}
	return nil, scimErr(http.StatusBadRequest, "invalidValue", field+" must be a string")
}

func scimBool(v any, field string) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string: // Entra ID has sent "True" and "False"
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, scimErr(http.StatusBadRequest, "invalidValue", field+" must be true or false")
}

func validEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-1 && len(s) <= 320 && !strings.ContainsAny(s, " \t\r\n<>")
}

// parseSCIMUser reads a User resource. Read-only and unknown attributes (id, meta, groups, password, other
// extensions) are ignored.
func parseSCIMUser(res map[string]any) (store.SCIMUser, error) {
	u := store.SCIMUser{Active: true, Extra: map[string]any{}}
	if _, v, ok := getCI(res, "schemas"); ok {
		list, _ := v.([]any)
		found := false
		for _, s := range list {
			found = found || strings.EqualFold(fmt.Sprint(s), scimCoreUser)
		}
		if !found {
			return u, scimErr(http.StatusBadRequest, "invalidSyntax", "schemas must include "+scimCoreUser)
		}
	}
	for k, v := range res {
		lk := strings.ToLower(k)
		var err error
		switch {
		case lk == "username":
			var p *string
			if p, err = scimString(v, "userName"); err == nil && p != nil {
				u.UserName = *p
			}
		case lk == "externalid":
			u.ExternalID, err = scimString(v, "externalId")
		case lk == "active":
			if v != nil {
				u.Active, err = scimBool(v, "active")
			}
		case lk == "displayname":
			u.DisplayName, err = scimString(v, "displayName")
		case lk == "emails":
			u.Emails, err = parseEmails(v)
		case lk == strings.ToLower(scimEnterprise):
			u.Enterprise, err = parseEnterprise(v)
		case scimUserExtra[lk] != "":
			if v != nil {
				u.Extra[scimUserExtra[lk]] = v
			}
		}
		if err != nil {
			return u, err
		}
	}
	if u.UserName == "" || len(u.UserName) > 256 {
		return u, scimErr(http.StatusBadRequest, "invalidValue", "userName is required (at most 256 characters)")
	}
	if name, ok := u.Extra["name"].(map[string]any); ok {
		_, g, _ := getCI(name, "givenName")
		_, f, _ := getCI(name, "familyName")
		u.GivenName, _ = scimString(g, "name.givenName")
		u.FamilyName, _ = scimString(f, "name.familyName")
		if u.DisplayName == nil {
			_, formatted, _ := getCI(name, "formatted")
			u.DisplayName, _ = scimString(formatted, "name.formatted")
		}
	} else if u.Extra["name"] != nil {
		return u, scimErr(http.StatusBadRequest, "invalidValue", "name must be an object")
	}
	if u.DisplayName == nil {
		u.DisplayName, _ = scimString(strings.TrimSpace(deref(u.GivenName)+" "+deref(u.FamilyName)), "")
	}
	u.Email = primaryEmail(u.Emails)
	if u.Email == "" && strings.Contains(u.UserName, "@") {
		u.Email = u.UserName
		u.Emails = []map[string]any{{"value": u.UserName, "type": "work", "primary": true}}
	}
	if !validEmail(u.Email) {
		return u, scimErr(http.StatusBadRequest, "invalidValue", "an email address is required (emails, or a userName "+
			"that is one)")
	}
	return u, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseEmails(v any) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, scimErr(http.StatusBadRequest, "invalidValue", "emails must be a list")
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, scimErr(http.StatusBadRequest, "invalidValue", "each email must be an object")
		}
		_, val, _ := getCI(m, "value")
		s, err := scimString(val, "emails.value")
		if err != nil {
			return nil, err
		}
		if s == nil {
			continue
		}
		email := map[string]any{"value": *s}
		if _, t, ok := getCI(m, "type"); ok && t != nil {
			email["type"] = t
		}
		if _, p, ok := getCI(m, "primary"); ok && p != nil {
			b, err := scimBool(p, "emails.primary")
			if err != nil {
				return nil, err
			}
			email["primary"] = b
		}
		if _, d, ok := getCI(m, "display"); ok && d != nil {
			email["display"] = d
		}
		out = append(out, email)
	}
	return out, nil
}

// primaryEmail picks the account's address: the primary email, else the work one, else the first.
func primaryEmail(emails []map[string]any) string {
	for _, e := range emails {
		if e["primary"] == true {
			return e["value"].(string)
		}
	}
	for _, e := range emails {
		if t, _ := e["type"].(string); strings.EqualFold(t, "work") {
			return e["value"].(string)
		}
	}
	if len(emails) > 0 {
		return emails[0]["value"].(string)
	}
	return ""
}

func parseEnterprise(v any) (map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, scimErr(http.StatusBadRequest, "invalidValue", "the enterprise extension must be an object")
	}
	out := map[string]any{}
	for _, name := range scimEnterpriseAttrs {
		_, val, ok := getCI(m, name)
		if !ok || val == nil {
			continue
		}
		if name == "manager" {
			switch x := val.(type) {
			case string: // Entra ID sends the manager's id as a plain string
				if x != "" {
					out[name] = map[string]any{"value": x}
				}
			case map[string]any:
				if _, id, _ := getCI(x, "value"); id != nil && id != "" {
					out[name] = x
				}
			default:
				return nil, scimErr(http.StatusBadRequest, "invalidValue", "manager must be an object")
			}
			continue
		}
		s, err := scimString(val, name)
		if err != nil {
			return nil, err
		}
		if s != nil {
			out[name] = *s
		}
	}
	return out, nil
}

func scimTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (s *Server) scimUserResource(base string, u store.SCIMUser) map[string]any {
	res := map[string]any{}
	for k, v := range u.Extra {
		res[k] = v
	}
	schemas := []string{scimCoreUser}
	if len(u.Enterprise) > 0 {
		schemas = append(schemas, scimEnterprise)
		res[scimEnterprise] = u.Enterprise
	}
	res["schemas"] = schemas
	res["id"] = u.UserID.String()
	res["userName"] = u.UserName
	res["active"] = u.Active
	if u.ExternalID != nil {
		res["externalId"] = *u.ExternalID
	}
	if u.DisplayName != nil {
		res["displayName"] = *u.DisplayName
	}
	if len(u.Emails) > 0 {
		res["emails"] = u.Emails
	} else {
		res["emails"] = []map[string]any{{"value": u.Email, "type": "work", "primary": true}}
	}
	groups := make([]map[string]any, 0, len(u.Groups))
	for _, g := range u.Groups {
		groups = append(groups, map[string]any{"value": g.ID.String(), "display": g.Display,
			"$ref": base + "/Groups/" + g.ID.String(), "type": "direct"})
	}
	res["groups"] = groups
	res["meta"] = map[string]any{"resourceType": "User", "created": scimTime(u.CreatedAt),
		"lastModified": scimTime(u.UpdatedAt), "version": scimETag(u.Version),
		"location": base + "/Users/" + u.UserID.String()}
	return res
}

// asJSONMap gives a resource the shape decoded JSON has, for PATCH.
func asJSONMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(b, &out)
}

func (s *Server) writeSCIMUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID, status int, u store.SCIMUser) {
	res := s.scimUserResource(s.scimBase(r, tid), u)
	w.Header().Set("ETag", scimETag(u.Version))
	if status == http.StatusCreated {
		w.Header().Set("Location", res["meta"].(map[string]any)["location"].(string))
	}
	writeSCIM(w, status, projectSCIM(r, res))
}

func (s *Server) scimNeedKeycloak(w http.ResponseWriter) bool {
	if s.kc == nil {
		writeSCIMError(w, scimErr(http.StatusServiceUnavailable, "", "this installation has not configured "+
			"Keycloak's admin API, which provisioning needs"))
		return false
	}
	return true
}

func scimUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, scimErr(http.StatusNotFound, "", "resource not found"))
		return id, false
	}
	return id, true
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	conds, start, count, err := scimListParams(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	sc, err := toStoreConds(conds, false)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	list, total, err := s.store.ListSCIMUsers(r.Context(), tid, store.SCIMQuery{Conds: sc, Offset: start - 1, Limit: count})
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	base := s.scimBase(r, tid)
	res := make([]map[string]any, 0, len(list))
	for _, u := range list {
		res = append(res, s.scimUserResource(base, u))
	}
	writeSCIM(w, http.StatusOK, scimListResponse(r, total, start, res))
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	uid, ok := scimUserID(w, r)
	if !ok {
		return
	}
	u, err := s.store.GetSCIMUser(r.Context(), tid, uid)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if notModified(w, r, u.Version) {
		return
	}
	s.writeSCIMUser(w, r, tid, http.StatusOK, u)
}

var errNotVerifiedDomain = scimErr(http.StatusBadRequest, "invalidValue",
	"the email address is not in one of this organisation's verified domains")

// checkSCIMDomain refuses addresses outside the tenant's verified domains.
func (s *Server) checkSCIMDomain(ctx context.Context, tid uuid.UUID, email string) error {
	ok, err := s.store.IsVerifiedDomain(ctx, tid, email)
	if err == nil && !ok {
		err = errNotVerifiedDomain
	}
	return err
}

// accountChange is what a SCIM user sets on the Keycloak account: email, names, employee number and department.
func accountChange(u store.SCIMUser) keycloak.AccountChange {
	email, first, last := u.Email, deref(u.GivenName), deref(u.FamilyName)
	attr := func(name string) string { s, _ := u.Enterprise[name].(string); return s }
	return keycloak.AccountChange{Email: &email, FirstName: &first, LastName: &last,
		Attributes: map[string]string{"employeeNumber": attr("employeeNumber"), "department": attr("department")}}
}

func accountFieldsChanged(a, b store.SCIMUser) bool {
	x, y := accountChange(a), accountChange(b)
	return !strings.EqualFold(*x.Email, *y.Email) || *x.FirstName != *y.FirstName || *x.LastName != *y.LastName ||
		x.Attributes["employeeNumber"] != y.Attributes["employeeNumber"] ||
		x.Attributes["department"] != y.Attributes["department"]
}

// scimCreateUser provisions a person: their Keycloak account is linked by email or created (email verified, no
// password: they sign in through the tenant's SSO), and they join the tenant. A userName or externalId that is
// already provisioned answers 409 uniqueness.
func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	var res map[string]any
	if err := readSCIMBody(w, r, &res); err != nil {
		s.scimFail(w, r, err)
		return
	}
	in, err := parseSCIMUser(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	in.TenantID = tid
	if !s.scimNeedKeycloak(w) {
		return
	}
	ctx := r.Context()
	if err := s.checkSCIMDomain(ctx, tid, in.Email); err != nil {
		s.scimFail(w, r, err)
		return
	}
	if _, err := s.store.FindSCIMUser(ctx, tid, in.UserName, deref(in.ExternalID)); err == nil {
		writeSCIMError(w, scimErr(http.StatusConflict, "uniqueness", "a user with this userName or externalId is "+
			"already provisioned"))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.scimFail(w, r, err)
		return
	}
	acct, err := s.kc.AccountByEmail(ctx, in.Email)
	switch {
	case err == nil:
		if err := s.kc.UpdateAccount(ctx, acct.ID, accountChange(in)); err != nil {
			s.scimFail(w, r, err)
			return
		}
	case errors.Is(err, keycloak.ErrNotFound):
		ch := accountChange(in)
		attrs := map[string][]string{}
		for k, v := range ch.Attributes {
			if v != "" {
				attrs[k] = []string{v}
			}
		}
		acct = keycloak.Account{Username: strings.ToLower(in.Email), Email: in.Email, EmailVerified: true,
			Enabled: true, FirstName: *ch.FirstName, LastName: *ch.LastName, Attributes: attrs}
		if acct.ID, err = s.kc.CreateAccount(ctx, acct); err != nil {
			s.scimFail(w, r, err)
			return
		}
		in.CreatedAccount = true
	default:
		s.scimFail(w, r, err)
		return
	}
	if in.UserID, err = uuid.Parse(acct.ID); err != nil {
		s.scimFail(w, r, fmt.Errorf("keycloak account id %q is not a UUID", acct.ID))
		return
	}
	undo := func() {
		if in.CreatedAccount {
			if err := s.kc.DeleteUser(context.WithoutCancel(ctx), in.UserID); err != nil {
				s.log.ErrorContext(ctx, "removing a Keycloak account after a failed provisioning", "err", err)
			}
		}
	}
	if u, err := s.store.GetUser(ctx, in.UserID); err == nil && u.Kind != "human" {
		undo()
		s.scimFail(w, r, scimErr(http.StatusConflict, "uniqueness", "this address belongs to an agent or service "+
			"account, which SCIM does not manage"))
		return
	} else if errors.Is(err, store.ErrNotFound) {
		if _, err := s.store.UpsertUser(ctx, store.UserProfile{ID: in.UserID, Email: in.Email, EmailVerified: true,
			DisplayName: deref(in.DisplayName)}); err != nil {
			undo()
			s.scimFail(w, r, err)
			return
		}
	} else if err != nil {
		undo()
		s.scimFail(w, r, err)
		return
	}
	out, err := s.store.ProvisionSCIMUser(ctx, in)
	if err != nil {
		undo()
		s.scimFail(w, r, err)
		return
	}
	if !out.Active {
		if err := s.scimSignOut(r, tid, out.UserID); err != nil {
			s.scimFail(w, r, err)
			return
		}
	}
	s.writeSCIMUser(w, r, tid, http.StatusCreated, out)
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	uid, ok := scimUserID(w, r)
	if !ok {
		return
	}
	ifv, err := scimIfMatch(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	var res map[string]any
	if err := readSCIMBody(w, r, &res); err != nil {
		s.scimFail(w, r, err)
		return
	}
	in, err := parseSCIMUser(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	cur, err := s.store.GetSCIMUser(r.Context(), tid, uid)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.scimSaveUser(w, r, cur, in, ifv, !in.Active)
}

// scimPatchUser applies the operations to the current resource and saves the result like a PUT. Without If-Match
// the version read here is required, so a concurrent change is not lost (412).
func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	uid, ok := scimUserID(w, r)
	if !ok {
		return
	}
	ifv, err := scimIfMatch(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	var req scimPatchRequest
	if err := readSCIMBody(w, r, &req); err != nil {
		s.scimFail(w, r, err)
		return
	}
	cur, err := s.store.GetSCIMUser(r.Context(), tid, uid)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if ifv != 0 && ifv != cur.Version {
		s.scimFail(w, r, store.ErrVersion)
		return
	}
	res, err := asJSONMap(s.scimUserResource(s.scimBase(r, tid), cur))
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if err := applySCIMPatch(res, req.Operations); err != nil {
		s.scimFail(w, r, err)
		return
	}
	in, err := parseSCIMUser(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.scimSaveUser(w, r, cur, in, cur.Version, !in.Active && patchTouches(req.Operations, "active"))
}

// patchTouches says whether an operation names the attribute, by path or as a key of a path-less value.
func patchTouches(ops []scimPatchOperation, attr string) bool {
	for _, op := range ops {
		if strings.EqualFold(stripCoreURN(op.Path), attr) {
			return true
		}
		if m, ok := op.Value.(map[string]any); ok && op.Path == "" {
			if _, _, found := getCI(m, attr); found {
				return true
			}
		}
	}
	return false
}

// scimSaveUser stores a replacement. The account in Keycloak follows when the person's domain is verified by the
// tenant (the tenant governs them). Deactivation signs the person out everywhere; so does a repeated request to
// deactivate (deactivating), so a retry after a failed sign-out completes it.
func (s *Server) scimSaveUser(w http.ResponseWriter, r *http.Request, cur, in store.SCIMUser, ifv int64, deactivating bool) {
	ctx := r.Context()
	in.TenantID, in.UserID, in.CreatedAccount = cur.TenantID, cur.UserID, cur.CreatedAccount
	if ifv != 0 && ifv != cur.Version {
		s.scimFail(w, r, store.ErrVersion)
		return
	}
	if !strings.EqualFold(cur.Email, in.Email) {
		if err := s.checkSCIMDomain(ctx, cur.TenantID, in.Email); err != nil {
			s.scimFail(w, r, err)
			return
		}
	}
	governed, err := s.store.IsVerifiedDomain(ctx, cur.TenantID, cur.Email)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if governed && accountFieldsChanged(cur, in) {
		if !s.scimNeedKeycloak(w) {
			return
		}
		if err := s.kc.UpdateAccount(ctx, cur.UserID.String(), accountChange(in)); err != nil {
			s.scimFail(w, r, err)
			return
		}
	}
	before, out, err := s.store.ReplaceSCIMUser(ctx, in, ifv)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.seen.Delete(out.UserID)
	if !out.Active && (before.Active || deactivating) && governed {
		if err := s.scimSignOut(r, cur.TenantID, out.UserID); err != nil {
			s.scimFail(w, r, err)
			return
		}
	}
	s.writeSCIMUser(w, r, cur.TenantID, http.StatusOK, out)
}

// scimSignOut ends every Keycloak session of a deprovisioned person (refresh tokens stop at once).
func (s *Server) scimSignOut(r *http.Request, tid, uid uuid.UUID) error {
	if s.kc == nil {
		return nil
	}
	if err := s.kc.LogoutUser(r.Context(), uid.String()); err != nil && !errors.Is(err, keycloak.ErrNotFound) {
		return err
	}
	ctx := context.WithoutCancel(r.Context())
	if err := s.store.RecordAudit(ctx, store.Scope{TenantID: tid}, tid, "member.signed_out",
		"tenants/"+tid.String()+"/members/"+uid.String(), map[string]any{"by": "scim"}); err != nil {
		s.log.ErrorContext(ctx, "recording a SCIM sign-out", "err", err)
	}
	return nil
}

// scimDeleteUser deprovisions a person: they leave the tenant (grants revoked) and are signed out. Their account is
// erased only when SCIM created it, the tenant governs them and they belong to no other tenant (personal ones
// included); otherwise it stays for their other organisations.
func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	uid, ok := scimUserID(w, r)
	if !ok {
		return
	}
	ifv, err := scimIfMatch(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	ctx := r.Context()
	cur, err := s.store.GetSCIMUser(ctx, tid, uid)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	governed, err := s.store.IsVerifiedDomain(ctx, tid, cur.Email)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if _, err := s.store.DeleteSCIMUser(ctx, tid, uid, ifv); err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.seen.Delete(uid)
	if governed {
		if err := s.scimSignOut(r, tid, uid); err != nil {
			// the membership is gone either way; a retry would only find 404, so record the failure
			s.log.ErrorContext(ctx, "signing out a deprovisioned user failed", "user", uid, "err", err)
			_ = s.store.RecordAudit(context.WithoutCancel(ctx), store.Scope{TenantID: tid}, tid,
				"scim.sign_out_failed", "tenants/"+tid.String()+"/members/"+uid.String(),
				map[string]any{"error": err.Error()})
		}
	}
	if governed && cur.CreatedAccount {
		s.scimEraseIfAlone(r, tid, uid)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimEraseIfAlone(r *http.Request, tid, uid uuid.UUID) {
	ctx := context.WithoutCancel(r.Context())
	n, err := s.store.OtherMemberships(ctx, tid, uid)
	if err != nil || n > 0 {
		return
	}
	if err := s.store.DeleteUser(ctx, store.Scope{Operator: true}, uid); err != nil {
		s.log.ErrorContext(ctx, "erasing a deprovisioned user", "user", uid, "err", err)
		return
	}
	if s.kc != nil {
		if err := s.kc.DeleteUser(ctx, uid); err != nil {
			s.log.ErrorContext(ctx, "deleting a deprovisioned user's account", "user", uid, "err", err)
			_ = s.store.RecordAudit(ctx, store.Scope{Operator: true}, uuid.Nil, "user.directory_delete_failed",
				"users/"+uid.String(), map[string]any{"error": err.Error()})
		}
	}
}
