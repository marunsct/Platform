package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/store"
)

// SCIM Groups: the tenant's directory groups. Membership changes grant and revoke the app roles the tenant mapped
// to the group's name (POST /v1/tenants/{tid}/scim/group-mappings).

func parseSCIMGroup(res map[string]any) (store.SCIMGroup, error) {
	var g store.SCIMGroup
	if _, v, ok := getCI(res, "schemas"); ok {
		list, _ := v.([]any)
		found := false
		for _, s := range list {
			found = found || strings.EqualFold(fmt.Sprint(s), scimCoreGroup)
		}
		if !found {
			return g, scimErr(http.StatusBadRequest, "invalidSyntax", "schemas must include "+scimCoreGroup)
		}
	}
	_, name, _ := getCI(res, "displayName")
	p, err := scimString(name, "displayName")
	if err != nil {
		return g, err
	}
	if p == nil {
		return g, scimErr(http.StatusBadRequest, "invalidValue", "displayName is required")
	}
	g.DisplayName = *p
	_, ext, _ := getCI(res, "externalId")
	if g.ExternalID, err = scimString(ext, "externalId"); err != nil {
		return g, err
	}
	_, members, _ := getCI(res, "members")
	if members == nil {
		g.Members = []store.SCIMRef{}
		return g, nil
	}
	list, ok := members.([]any)
	if !ok {
		return g, scimErr(http.StatusBadRequest, "invalidValue", "members must be a list")
	}
	g.Members = make([]store.SCIMRef, 0, len(list))
	for _, m := range list {
		v, ok := elemValue(m)
		if !ok {
			return g, scimErr(http.StatusBadRequest, "invalidValue", "each member needs a value (a user id)")
		}
		id, err := uuid.Parse(v)
		if err != nil {
			return g, scimErr(http.StatusBadRequest, "invalidValue", fmt.Sprintf("member %q is not a user id of "+
				"this organisation", v))
		}
		g.Members = append(g.Members, store.SCIMRef{ID: id})
	}
	return g, nil
}

func (s *Server) scimGroupResource(base string, g store.SCIMGroup) map[string]any {
	res := map[string]any{"schemas": []string{scimCoreGroup}, "id": g.ID.String(), "displayName": g.DisplayName,
		"meta": map[string]any{"resourceType": "Group", "created": scimTime(g.CreatedAt),
			"lastModified": scimTime(g.UpdatedAt), "version": scimETag(g.Version),
			"location": base + "/Groups/" + g.ID.String()}}
	if g.ExternalID != nil {
		res["externalId"] = *g.ExternalID
	}
	if g.Members != nil {
		members := make([]map[string]any, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, map[string]any{"value": m.ID.String(), "display": m.Display,
				"$ref": base + "/Users/" + m.ID.String(), "type": "User"})
		}
		res["members"] = members
	}
	return res
}

func (s *Server) writeSCIMGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID, status int, g store.SCIMGroup) {
	res := s.scimGroupResource(s.scimBase(r, tid), g)
	w.Header().Set("ETag", scimETag(g.Version))
	if status == http.StatusCreated {
		w.Header().Set("Location", res["meta"].(map[string]any)["location"].(string))
	}
	writeSCIM(w, status, projectSCIM(r, res))
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	conds, start, count, err := scimListParams(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	sc, err := toStoreConds(conds, true)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	list, total, err := s.store.ListSCIMGroups(r.Context(), tid, store.SCIMQuery{Conds: sc, Offset: start - 1,
		Limit: count}, wantsAttr(r, "members"))
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	base := s.scimBase(r, tid)
	res := make([]map[string]any, 0, len(list))
	for _, g := range list {
		res = append(res, s.scimGroupResource(base, g))
	}
	writeSCIM(w, http.StatusOK, scimListResponse(r, total, start, res))
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	id, ok := scimUserID(w, r)
	if !ok {
		return
	}
	g, err := s.store.GetSCIMGroup(r.Context(), tid, id, wantsAttr(r, "members"))
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if notModified(w, r, g.Version) {
		return
	}
	s.writeSCIMGroup(w, r, tid, http.StatusOK, g)
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	var res map[string]any
	if err := readSCIMBody(w, r, &res); err != nil {
		s.scimFail(w, r, err)
		return
	}
	in, err := parseSCIMGroup(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	in.TenantID = tid
	g, err := s.store.CreateSCIMGroup(r.Context(), in)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.writeSCIMGroup(w, r, tid, http.StatusCreated, g)
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	id, ok := scimUserID(w, r)
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
	in, err := parseSCIMGroup(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	in.TenantID, in.ID = tid, id
	g, err := s.store.ReplaceSCIMGroup(r.Context(), in, ifv)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	s.writeSCIMGroup(w, r, tid, http.StatusOK, g)
}

// scimPatchGroup applies the operations (rename, add and remove members) and answers 204, as Okta and Entra ID
// expect; the response would otherwise carry every member.
func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	id, ok := scimUserID(w, r)
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
	cur, err := s.store.GetSCIMGroup(r.Context(), tid, id, true)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if ifv != 0 && ifv != cur.Version {
		s.scimFail(w, r, store.ErrVersion)
		return
	}
	res, err := asJSONMap(s.scimGroupResource(s.scimBase(r, tid), cur))
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if err := applySCIMPatch(res, req.Operations); err != nil {
		s.scimFail(w, r, err)
		return
	}
	in, err := parseSCIMGroup(res)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	in.TenantID, in.ID = tid, id
	g, err := s.store.ReplaceSCIMGroup(r.Context(), in, cur.Version)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if len(splitAttrs(r.URL.Query().Get("attributes"))) > 0 {
		s.writeSCIMGroup(w, r, tid, http.StatusOK, g)
		return
	}
	w.Header().Set("ETag", scimETag(g.Version))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request, tid uuid.UUID) {
	id, ok := scimUserID(w, r)
	if !ok {
		return
	}
	ifv, err := scimIfMatch(r)
	if err != nil {
		s.scimFail(w, r, err)
		return
	}
	if err := s.store.DeleteSCIMGroup(r.Context(), tid, id, ifv); err != nil {
		s.scimFail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
