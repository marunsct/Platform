package api

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/keycloak"
	"github.com/marunsct/Platform/internal/store"
)

// SCIM 2.0 service provider per tenant (TS14, RFC 7643/7644, technical specification §19), served at
// /scim/v2/tenants/{tid}/ and authenticated with the tenant's SCIM bearer tokens.

const scimContentType = "application/scim+json"

// scimError is an error response in the SCIM error schema (RFC 7644 §3.12).
type scimError struct {
	status   int
	scimType string
	detail   string
}

func (e *scimError) Error() string { return e.detail }

func scimErr(status int, scimType, detail string) *scimError {
	return &scimError{status: status, scimType: scimType, detail: detail}
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, e *scimError) {
	body := map[string]any{"schemas": []string{scimErrorURN}, "status": strconv.Itoa(e.status), "detail": e.detail}
	if e.scimType != "" {
		body["scimType"] = e.scimType
	}
	writeSCIM(w, e.status, body)
}

// scimFail turns store, Keycloak and SCIM errors into SCIM error responses.
func (s *Server) scimFail(w http.ResponseWriter, r *http.Request, err error) {
	var se *scimError
	var inv *store.InvalidError
	var lim *store.LimitError
	var kerr *keycloak.Error
	switch {
	case errors.As(err, &se):
		writeSCIMError(w, se)
	case errors.As(err, &lim):
		writeSCIMError(w, scimErr(http.StatusForbidden, "", "plan limit: "+lim.Msg))
	case errors.As(err, &inv):
		writeSCIMError(w, scimErr(http.StatusBadRequest, "invalidValue", inv.Msg))
	case errors.Is(err, store.ErrNotFound), errors.Is(err, keycloak.ErrNotFound):
		writeSCIMError(w, scimErr(http.StatusNotFound, "", "resource not found"))
	case errors.Is(err, store.ErrConflict), errors.Is(err, keycloak.ErrConflict):
		writeSCIMError(w, scimErr(http.StatusConflict, "uniqueness", "a resource with this userName, externalId, "+
			"email or displayName already exists"))
	case errors.Is(err, store.ErrVersion):
		writeSCIMError(w, scimErr(http.StatusPreconditionFailed, "", "the resource changed; read it again"))
	case errors.Is(err, keycloak.ErrUnavailable):
		s.log.WarnContext(r.Context(), "keycloak unavailable", "err", err)
		writeSCIMError(w, scimErr(http.StatusServiceUnavailable, "", "the identity service is not answering; retry"))
	case errors.As(err, &kerr):
		s.log.ErrorContext(r.Context(), "keycloak refused", "err", err)
		writeSCIMError(w, scimErr(http.StatusBadGateway, "", "the identity service refused: "+kerr.Body))
	default:
		s.log.ErrorContext(r.Context(), "scim request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeSCIMError(w, scimErr(http.StatusInternalServerError, "", "something went wrong"))
	}
}

type scimTokenKey struct{}

// scimTokenFrom is the SCIM token of the request (zero outside /scim/v2).
func scimTokenFrom(ctx context.Context) store.SCIMToken {
	t, _ := ctx.Value(scimTokenKey{}).(store.SCIMToken)
	return t
}

func hashSCIMToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// scim authenticates a SCIM request with a bearer token of the tenant in the path. A token of another tenant is
// unknown here (401). Changes are audited with actor kind `system`, the token's id as actor id and `scim` as the
// actor email (the audit log has no actor kind of its own for directories yet).
func (s *Server) scim(h func(http.ResponseWriter, *http.Request, uuid.UUID)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := store.Actor{Kind: "system", Email: "scim", RequestID: requestID(r), IP: s.clientIP(r).String(), UserAgent: r.UserAgent()}
		w.Header().Set("X-Request-Id", actor.RequestID)
		tid, err := uuid.Parse(r.PathValue("tid"))
		if err != nil {
			writeSCIMError(w, scimErr(http.StatusNotFound, "", "resource not found"))
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			raw, ok = strings.CutPrefix(r.Header.Get("Authorization"), "bearer ")
		}
		raw = strings.TrimSpace(raw)
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="matura-scim"`)
			writeSCIMError(w, scimErr(http.StatusUnauthorized, "", "send Authorization: Bearer <SCIM token>"))
			return
		}
		tok, err := s.store.AuthenticateSCIMToken(r.Context(), tid, hashSCIMToken(raw))
		switch {
		case errors.Is(err, store.ErrNotFound):
			w.Header().Set("WWW-Authenticate", `Bearer realm="matura-scim", error="invalid_token"`)
			writeSCIMError(w, scimErr(http.StatusUnauthorized, "", "the token is unknown, revoked or expired"))
			return
		case errors.Is(err, store.ErrSCIMTenantInactive):
			writeSCIMError(w, scimErr(http.StatusForbidden, "", err.Error()))
			return
		case err != nil:
			s.scimFail(w, r, err)
			return
		}
		actor.ID = tok.ID
		ctx := context.WithValue(store.WithActor(r.Context(), actor), scimTokenKey{}, tok)
		r = r.WithContext(ctx)
		if r.Method == http.MethodPost && r.Header.Get("Idempotency-Key") != "" {
			s.idempotent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(w, r, tid) })).ServeHTTP(w, r)
			return
		}
		h(w, r, tid)
	}
}

// scimBase is the absolute URL of the tenant's SCIM endpoint, for meta.location.
func (s *Server) scimBase(r *http.Request, tid uuid.UUID) string {
	base := s.invites.PublicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	return strings.TrimRight(base, "/") + "/scim/v2/tenants/" + tid.String()
}

// readSCIMBody decodes a SCIM request body (application/scim+json or application/json, at most 1 MB) into a map;
// unknown attributes are allowed.
func readSCIMBody(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return scimErr(http.StatusRequestEntityTooLarge, "", "the request body is over 1 MB")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return scimErr(http.StatusBadRequest, "invalidSyntax", "the body is not valid JSON: "+err.Error())
	}
	return nil
}

func scimETag(version int64) string { return `W/"` + strconv.FormatInt(version, 10) + `"` }

// scimIfMatch reads If-Match: a resource version from a previous ETag; 0 when absent or `*`.
func scimIfMatch(r *http.Request) (int64, error) {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return 0, nil
	}
	v, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(h, "W/"), `"`), 10, 64)
	if err != nil {
		return 0, scimErr(http.StatusBadRequest, "invalidValue", "If-Match must be an ETag this server returned")
	}
	return v, nil
}

// notModified answers 304 when If-None-Match names the current version.
func notModified(w http.ResponseWriter, r *http.Request, version int64) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" && (inm == scimETag(version) || inm == "*") {
		w.Header().Set("ETag", scimETag(version))
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	return false
}

// scimListParams reads filter, startIndex and count (RFC 7644 §3.4.2.4): startIndex is 1-based, count defaults to
// 100 and is capped at scimMaxResults.
func scimListParams(r *http.Request) ([]scimCond, int, int, error) {
	q := r.URL.Query()
	var conds []scimCond
	if f := strings.TrimSpace(q.Get("filter")); f != "" {
		var err error
		if conds, err = parseSCIMFilter(f); err != nil {
			return nil, 0, 0, scimErr(http.StatusBadRequest, "invalidFilter", err.Error())
		}
	}
	start, count := 1, 100
	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, 0, scimErr(http.StatusBadRequest, "invalidValue", "startIndex must be an integer")
		}
		start = max(n, 1)
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, 0, scimErr(http.StatusBadRequest, "invalidValue", "count must be an integer")
		}
		count = min(max(n, 0), scimMaxResults)
	}
	return conds, start, count, nil
}

const scimMaxResults = 200

// toStoreConds maps parsed comparisons onto what the store can query; anything else is an invalid filter.
func toStoreConds(conds []scimCond, group bool) ([]store.SCIMCond, error) {
	out := make([]store.SCIMCond, 0, len(conds))
	for _, c := range conds {
		attr := strings.ToLower(c.Attr)
		sc := store.SCIMCond{Attr: attr, Value: jsonScalar(c.Value)}
		switch {
		case !group && (attr == "emails.value" || (attr == "emails" && c.Bracket == nil && c.Op == "eq")):
			sc.Attr = "emails"
		case !group && attr == "emails" && c.Bracket != nil && strings.EqualFold(c.Sub, "value") && c.Op == "eq":
			for _, b := range c.Bracket {
				switch strings.ToLower(b.Attr) {
				case "type":
					sc.Type = jsonScalar(b.Value)
				case "primary":
				default:
					return nil, scimErr(http.StatusBadRequest, "invalidFilter", "emails[…] filters on type only")
				}
			}
		case group && (attr == "members.value" || (attr == "members" && c.Bracket == nil && c.Op == "eq")):
			sc.Attr = "members"
		case group && attr == "members" && c.Bracket != nil && c.Op == "":
			if len(c.Bracket) != 1 || !strings.EqualFold(c.Bracket[0].Attr, "value") {
				return nil, scimErr(http.StatusBadRequest, "invalidFilter", "members[…] filters on value only")
			}
			sc.Attr, sc.Value = "members", jsonScalar(c.Bracket[0].Value)
		case c.Bracket == nil && c.Op == "eq" && !group && (attr == "id" || attr == "username" || attr == "externalid" || attr == "active"):
		case c.Bracket == nil && c.Op == "eq" && group && (attr == "id" || attr == "displayname" || attr == "externalid"):
		default:
			return nil, scimErr(http.StatusBadRequest, "invalidFilter", "filtering on "+c.Attr+" is not supported")
		}
		out = append(out, sc)
	}
	return out, nil
}

func jsonScalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// projectSCIM applies attributes= and excludedAttributes= (top-level names) to a resource. id, schemas and meta are
// always returned.
func projectSCIM(r *http.Request, res map[string]any) map[string]any {
	q := r.URL.Query()
	if attrs := splitAttrs(q.Get("attributes")); len(attrs) > 0 {
		out := map[string]any{}
		for _, k := range []string{"id", "schemas", "meta"} {
			if v, ok := res[k]; ok {
				out[k] = v
			}
		}
		for _, a := range attrs {
			top := strings.SplitN(stripCoreURN(a), ".", 2)[0]
			if k, v, ok := getCI(res, top); ok {
				out[k] = v
			}
		}
		return out
	}
	for _, a := range splitAttrs(q.Get("excludedAttributes")) {
		top := strings.SplitN(stripCoreURN(a), ".", 2)[0]
		if !strings.EqualFold(top, "id") && !strings.EqualFold(top, "schemas") {
			deleteCI(res, top)
		}
	}
	return res
}

func splitAttrs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// wantsAttr says whether a projection keeps a top-level attribute (to skip loading group members).
func wantsAttr(r *http.Request, name string) bool {
	q := r.URL.Query()
	if attrs := splitAttrs(q.Get("attributes")); len(attrs) > 0 {
		for _, a := range attrs {
			if strings.EqualFold(strings.SplitN(stripCoreURN(a), ".", 2)[0], name) {
				return true
			}
		}
		return false
	}
	for _, a := range splitAttrs(q.Get("excludedAttributes")) {
		if strings.EqualFold(strings.SplitN(stripCoreURN(a), ".", 2)[0], name) {
			return false
		}
	}
	return true
}

func scimListResponse(r *http.Request, total, start int, resources []map[string]any) map[string]any {
	items := make([]any, 0, len(resources))
	for _, res := range resources {
		items = append(items, projectSCIM(r, res))
	}
	return map[string]any{"schemas": []string{scimListResp}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(items), "Resources": items}
}

// --- discovery (RFC 7644 §4) --------------------------------------------------------------------------------------

//go:embed scim_schemas.json
var scimSchemasJSON []byte

func (s *Server) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://github.com/marunsct/Platform/blob/main/docs/guide/scim.md",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "A SCIM token created by a tenant owner (POST /v1/tenants/{tid}/scim/tokens)",
			"primary":     true}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig",
			"location": s.scimBase(r, tid) + "/ServiceProviderConfig"},
	})
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	base := s.scimBase(r, tid)
	types := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "description": "People in the organisation", "schema": scimCoreUser,
			"schemaExtensions": []any{map[string]any{"schema": scimEnterprise, "required": false}},
			"meta":             map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "description": "Groups, mapped to app roles", "schema": scimCoreGroup,
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"}},
	}
	writeSCIM(w, http.StatusOK, scimListResponse(r, len(types), 1, types))
}

func (s *Server) scimSchemas(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	var schemas []map[string]any
	if err := json.Unmarshal(scimSchemasJSON, &schemas); err != nil {
		s.scimFail(w, r, err)
		return
	}
	for _, sc := range schemas {
		sc["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}
		sc["meta"] = map[string]any{"resourceType": "Schema",
			"location": s.scimBase(r, tid) + "/Schemas/" + url.PathEscape(sc["id"].(string))}
	}
	writeSCIM(w, http.StatusOK, scimListResponse(r, len(schemas), 1, schemas))
}
