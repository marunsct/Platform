package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// SCIM bulk operations (RFC 7644 §3.7, technical specification §19.6). Each operation runs through the same handler
// as the single request would, in the order sent, with the caller's SCIM token as actor; there is no transaction
// across operations, exactly as the RFC allows. `bulkId:<id>` in a later operation's path or data is replaced by the
// id of the resource an earlier POST with that bulkId created.

const (
	scimBulkRequestURN  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	scimBulkResponseURN = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	scimBulkMaxOps      = 1000
	scimBulkMaxPayload  = 1 << 20
)

type scimBulkOp struct {
	Method  string          `json:"method"`
	BulkID  string          `json:"bulkId,omitempty"`
	Version string          `json:"version,omitempty"`
	Path    string          `json:"path"`
	Data    json.RawMessage `json:"data,omitempty"`
}

var bulkRef = regexp.MustCompile(`bulkId:([A-Za-z0-9._~-]+)`)

// scimBulkPath checks an operation path: /Users, /Groups, /Users/{id} or /Groups/{id}.
func scimBulkPath(method, path string) (resource, id string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || (parts[0] != "Users" && parts[0] != "Groups") || len(parts) > 2 {
		return "", "", false
	}
	if method == http.MethodPost {
		return parts[0], "", len(parts) == 1
	}
	if len(parts) != 2 || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (s *Server) scimBulk(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, scimBulkMaxPayload))
	if err != nil {
		writeSCIMError(w, scimErr(http.StatusRequestEntityTooLarge, "", "the bulk request is over "+
			strconv.Itoa(scimBulkMaxPayload)+" bytes"))
		return
	}
	var req struct {
		Schemas      []string     `json:"schemas"`
		FailOnErrors int          `json:"failOnErrors"`
		Operations   []scimBulkOp `json:"Operations"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeSCIMError(w, scimErr(http.StatusBadRequest, "invalidSyntax", "the body is not a BulkRequest: "+err.Error()))
		return
	}
	if !containsFold(req.Schemas, scimBulkRequestURN) {
		writeSCIMError(w, scimErr(http.StatusBadRequest, "invalidSyntax", "schemas must include "+scimBulkRequestURN))
		return
	}
	if len(req.Operations) > scimBulkMaxOps {
		writeSCIMError(w, scimErr(http.StatusRequestEntityTooLarge, "tooMany", "at most "+
			strconv.Itoa(scimBulkMaxOps)+" operations per request"))
		return
	}
	created := map[string]string{} // bulkId -> resource id
	seen := map[string]bool{}
	results := make([]map[string]any, 0, len(req.Operations))
	errorsSoFar := 0
	for _, op := range req.Operations {
		if req.FailOnErrors > 0 && errorsSoFar >= req.FailOnErrors {
			break
		}
		res := s.scimBulkOne(r, tid, op, created, seen)
		if st, _ := strconv.Atoi(res["status"].(string)); st >= 400 {
			errorsSoFar++
		}
		results = append(results, res)
	}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{scimBulkResponseURN}, "Operations": results})
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// scimBulkOne runs one operation and returns its BulkResponse entry.
func (s *Server) scimBulkOne(r *http.Request, tid uuid.UUID, op scimBulkOp, created map[string]string, seen map[string]bool) map[string]any {
	method := strings.ToUpper(op.Method)
	out := map[string]any{"method": method}
	if op.BulkID != "" {
		out["bulkId"] = op.BulkID
	}
	fail := func(status int, scimType, detail string) map[string]any {
		body := map[string]any{"schemas": []string{scimErrorURN}, "status": strconv.Itoa(status), "detail": detail}
		if scimType != "" {
			body["scimType"] = scimType
		}
		out["status"] = strconv.Itoa(status)
		out["response"] = body
		return out
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return fail(http.StatusBadRequest, "invalidSyntax", "method must be POST, PUT, PATCH or DELETE")
	}
	if method == http.MethodPost {
		if op.BulkID == "" {
			return fail(http.StatusBadRequest, "invalidSyntax", "a POST operation needs a bulkId")
		}
		if seen[op.BulkID] {
			return fail(http.StatusBadRequest, "uniqueness", "bulkId "+op.BulkID+" is used twice")
		}
		seen[op.BulkID] = true
	}
	// Resolve bulkId references in the path and the data; one that names no earlier successful POST fails.
	var missing string
	resolve := func(b []byte) []byte {
		return bulkRef.ReplaceAllFunc(b, func(m []byte) []byte {
			ref := string(bulkRef.FindSubmatch(m)[1])
			if id, ok := created[ref]; ok {
				return []byte(id)
			}
			if missing == "" {
				missing = ref
			}
			return m
		})
	}
	path := string(resolve([]byte(op.Path)))
	data := resolve(op.Data)
	if missing != "" {
		return fail(http.StatusConflict, "invalidValue", "bulkId:"+missing+" names no resource created earlier in this request")
	}
	resource, id, ok := scimBulkPath(method, path)
	if !ok {
		return fail(http.StatusBadRequest, "invalidPath", "path must be /Users, /Groups, /Users/{id} or /Groups/{id}")
	}
	if method != http.MethodDelete && len(bytes.TrimSpace(data)) == 0 {
		return fail(http.StatusBadRequest, "invalidSyntax", "data is required for "+method)
	}

	var body io.Reader
	if method != http.MethodDelete {
		body = bytes.NewReader(data)
	}
	sub, err := http.NewRequestWithContext(r.Context(), method, "/scim/v2/tenants/"+tid.String()+"/"+strings.TrimPrefix(path, "/"), body)
	if err != nil {
		return fail(http.StatusBadRequest, "invalidPath", err.Error())
	}
	sub.Host, sub.TLS, sub.RemoteAddr = r.Host, r.TLS, r.RemoteAddr
	for _, h := range []string{"X-Forwarded-Proto", "X-Forwarded-For", "User-Agent", "X-Request-Id"} {
		if v := r.Header.Get(h); v != "" {
			sub.Header.Set(h, v)
		}
	}
	sub.Header.Set("Content-Type", scimContentType)
	if op.Version != "" {
		sub.Header.Set("If-Match", op.Version)
	}
	sub.SetPathValue("tid", tid.String())
	if id != "" {
		sub.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	s.scimBulkHandler(method, resource)(rec, sub, tid)

	out["status"] = strconv.Itoa(rec.Code)
	if loc := rec.Header().Get("Location"); loc != "" {
		out["location"] = loc
	}
	if et := rec.Header().Get("ETag"); et != "" {
		out["version"] = et
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code >= 400 {
		out["response"] = resp
		return out
	}
	if method == http.MethodPost {
		if newID, _ := resp["id"].(string); newID != "" {
			created[op.BulkID] = newID
			if _, ok := out["location"]; !ok {
				out["location"] = s.scimBase(r, tid) + "/" + resource + "/" + newID
			}
		}
	}
	if _, ok := out["location"]; !ok && id != "" {
		out["location"] = s.scimBase(r, tid) + "/" + resource + "/" + id
	}
	return out
}

func (s *Server) scimBulkHandler(method, resource string) func(http.ResponseWriter, *http.Request, uuid.UUID) {
	users := map[string]func(http.ResponseWriter, *http.Request, uuid.UUID){
		http.MethodPost: s.scimCreateUser, http.MethodPut: s.scimReplaceUser,
		http.MethodPatch: s.scimPatchUser, http.MethodDelete: s.scimDeleteUser}
	groups := map[string]func(http.ResponseWriter, *http.Request, uuid.UUID){
		http.MethodPost: s.scimCreateGroup, http.MethodPut: s.scimReplaceGroup,
		http.MethodPatch: s.scimPatchGroup, http.MethodDelete: s.scimDeleteGroup}
	if resource == "Users" {
		return users[method]
	}
	return groups[method]
}
