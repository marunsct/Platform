package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAuditCanonical pins the canonical form, so a verifier in another language can reproduce hashes.
func TestAuditCanonical(t *testing.T) {
	tid := uuid.MustParse("01a14a50-b077-7caa-9aa3-f00e3cb38121")
	e := AuditEvent{TenantID: &tid, Seq: 2, Time: time.Date(2026, 10, 17, 12, 0, 0, 1500, time.UTC),
		Actor: AuditActor{Kind: "system"}, Action: "workspace.created", Target: "t",
		Data:     json.RawMessage(`{"z": 1.50, "a": "R&D <ü>", "n": [1e2, -0, null, true]}`),
		PrevHash: "00"}
	got, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"workspace.created","actor":{"email":"","id":"","kind":"system"},` +
		`"data":{"a":"R&D <ü>","n":[100,0,null,true],"z":1.5},"ip":"","prev_hash":"00","request_id":"",` +
		`"seq":2,"target":"t","tenant_id":"01a14a50-b077-7caa-9aa3-f00e3cb38121",` +
		`"time":"2026-10-17T12:00:00.000001Z","user_agent":""}`
	if string(got) != want {
		t.Fatalf("canonical form\n got %s\nwant %s", got, want)
	}
}
