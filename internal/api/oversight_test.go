package api_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/marunsct/Platform/internal/ids"
)

// TestAgentOversight (technical specification §20.6): apps record people's approvals, overrides and stops of agent
// actions as audit events mapped to the EU AI Act; tenants with agents keep their audit log six months at least.
func TestAgentOversight(t *testing.T) {
	srv, _ := setupAgents(t)
	op := client{t: t, srv: srv, user: ids.New(), op: true}
	op.must(http.StatusOK, "PUT", "/admin/v1/apps/agentcanvas", agentCanvasManifest)
	sec := op.must(http.StatusCreated, "POST", "/admin/v1/apps/agentcanvas/secrets", map[string]any{"label": "b"})
	app := appClient{t: t, srv: srv, clientID: "agentcanvas", pass: sec["secret"].(string)}
	alice := client{t: t, srv: srv, user: ids.New()}
	outsider := client{t: t, srv: srv, user: ids.New()}
	outsider.must(http.StatusOK, "GET", "/v1/me", nil)
	aid := alice.must(http.StatusCreated, "POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})["id"].(string)
	base := "/v1/tenants/" + aid
	alice.must(http.StatusOK, "PUT", base+"/apps/agentcanvas", nil)
	alice.must(http.StatusOK, "PUT", base+"/retention", map[string]any{"retention_days": 90}) // fine before agents

	ag := alice.must(http.StatusCreated, "POST", base+"/agents", map[string]any{"kind": "agent", "name": "Report bot",
		"grants": []map[string]any{{"app": "agentcanvas", "role": "runner"}}})
	agentID := ag["id"].(string)
	if code, out := alice.do("PUT", base+"/retention", map[string]any{"retention_days": 90}); code != http.StatusUnprocessableEntity {
		t.Fatalf("an organisation with agents lowered retention below six months: %d %v", code, out)
	}
	alice.must(http.StatusOK, "PUT", base+"/retention", map[string]any{"retention_days": 183})

	path := "/v1/apps/agentcanvas/tenants/" + aid + "/oversight"
	ev := map[string]any{"id": "run-42-approval", "kind": "approval", "agent_id": agentID, "person_id": alice.user,
		"action": "send the weekly report to the board", "target": "workflow/weekly-report"}
	if code, out := app.post(path, ev); code != http.StatusCreated || out["recorded"] != true {
		t.Fatalf("record: %d %v", code, out)
	}
	if code, out := app.post(path, ev); code != http.StatusOK || out["recorded"] != false {
		t.Fatalf("retry: %d %v", code, out)
	}
	for name, bad := range map[string]map[string]any{
		"unknown kind":   {"id": "x1", "kind": "maybe", "agent_id": agentID, "person_id": alice.user, "action": "a"},
		"not an agent":   {"id": "x2", "kind": "stop", "agent_id": alice.user, "person_id": alice.user, "action": "a"},
		"not a member":   {"id": "x3", "kind": "stop", "agent_id": agentID, "person_id": outsider.user, "action": "a"},
		"agent overseer": {"id": "x4", "kind": "stop", "agent_id": agentID, "person_id": agentID, "action": "a"},
		"no action":      {"id": "x5", "kind": "stop", "agent_id": agentID, "person_id": alice.user},
	} {
		if code, _ := app.post(path, bad); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", name, code)
		}
	}
	app.post(path, map[string]any{"id": "run-43-stop", "kind": "stop", "agent_id": agentID, "person_id": alice.user,
		"action": "stopped a run that was emailing customers"})

	events := alice.must(http.StatusOK, "GET", base+"/audit?action=agent.oversight", nil)["items"].([]any)
	if len(events) != 2 {
		t.Fatalf("oversight events: %d", len(events))
	}
	var approval map[string]any
	for _, e := range events {
		if e.(map[string]any)["action"] == "agent.oversight.approval" {
			approval = e.(map[string]any)
		}
	}
	data := approval["data"].(map[string]any)
	arts := []string{}
	for _, a := range data["eu_ai_act"].([]any) {
		arts = append(arts, a.(string))
	}
	if approval["actor"].(map[string]any)["id"] != alice.user.String() || data["agent_id"] != agentID ||
		!slices.Equal(arts, []string{"Art. 12", "Art. 14(4)(d)", "Art. 26(5)"}) {
		t.Fatalf("approval event: %v", approval)
	}
	if v := alice.must(http.StatusOK, "GET", base+"/audit:verify", nil); v["ok"] != true {
		t.Fatalf("chain: %v", v)
	}

	// readiness: the AI controls apply to this tenant now
	rep := op.must(http.StatusOK, "GET", "/admin/v1/readiness", nil)
	got := map[string]string{}
	for _, c := range rep["controls"].([]any) {
		c := c.(map[string]any)
		if c["scope"] == "tenant" {
			for _, tt := range c["tenants"].([]any) {
				if tt.(map[string]any)["slug"] == "acme" {
					got[c["id"].(string)] = tt.(map[string]any)["status"].(string)
				}
			}
		}
	}
	for _, id := range []string{"tenant-agent-accountability", "tenant-agent-oversight", "tenant-agent-logs"} {
		if got[id] != "pass" {
			t.Errorf("%s: %s (%v)", id, got[id], got)
		}
	}
}
