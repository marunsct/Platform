package matura_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	matura "github.com/marunsct/Platform/sdk/go"
)

// TestPermissions runs the permission helpers against a fake maturad that keeps tuples and answers direct checks.
func TestPermissions(t *testing.T) {
	tuples := map[matura.Tuple]bool{}
	var last map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, sec, ok := r.BasicAuth(); !ok || id != "notes" || sec != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		last = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&last)
		raw, _ := json.Marshal(last)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/apps/notes/tenants/t1/relations":
			var in struct{ Writes, Deletes []matura.Tuple }
			_ = json.Unmarshal(raw, &in)
			for _, k := range in.Writes {
				tuples[k] = true
			}
			for _, k := range in.Deletes {
				delete(tuples, k)
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"written": len(in.Writes), "deleted": len(in.Deletes)})
		case "/v1/apps/notes/tenants/t1:check":
			var k matura.Tuple
			_ = json.Unmarshal(raw, &k)
			_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": tuples[k]})
		case "/v1/apps/notes/tenants/t1:batch-check":
			var in struct{ Checks []matura.Tuple }
			_ = json.Unmarshal(raw, &in)
			var res []map[string]any
			for _, k := range in.Checks {
				res = append(res, map[string]any{"allowed": tuples[k]})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case "/v1/apps/notes/tenants/t1:list-objects":
			var objs []string
			for k := range tuples {
				if k.User == last["user"] && k.Relation == last["relation"] {
					objs = append(objs, k.Object)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"objects": objs})
		default:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(`{"type":"https://matura.dev/problems/permissions-not-configured","status":501,"detail":"no OpenFGA"}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c := matura.NewClient(srv.URL, "notes", "secret")

	d1 := matura.Tuple{User: "user:u1", Relation: "editor", Object: "document:d1"}
	if err := c.WriteRelations(ctx, "notes", "t1", []matura.Tuple{d1}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Check(ctx, "notes", "t1", "user:u1", "editor", "document:d1",
		matura.CheckOptions{Fresh: true}); !ok || err != nil {
		t.Fatalf("check: %v %v", ok, err)
	}
	if last["consistency"] != "higher" {
		t.Fatalf("Fresh not sent: %v", last)
	}
	if ok, _ := c.Check(ctx, "notes", "t1", "user:u2", "editor", "document:d1"); ok {
		t.Fatal("u2 allowed")
	}
	res, err := c.BatchCheck(ctx, "notes", "t1", []matura.Tuple{d1, {User: "user:u2", Relation: "editor", Object: "document:d1"}})
	if err != nil || len(res) != 2 || !res[0].Allowed || res[1].Allowed {
		t.Fatalf("batch: %+v %v", res, err)
	}
	objs, err := c.ListObjects(ctx, "notes", "t1", "user:u1", "editor", "document")
	if err != nil || len(objs) != 1 || objs[0] != "document:d1" {
		t.Fatalf("list: %v %v", objs, err)
	}
	if err := c.WriteRelations(ctx, "notes", "t1", nil, []matura.Tuple{d1}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Check(ctx, "notes", "t1", "user:u1", "editor", "document:d1"); ok {
		t.Fatal("still allowed after delete")
	}
	var apiErr *matura.APIError
	if _, err := c.Check(ctx, "notes", "t2", "user:u1", "editor", "document:d1"); !errors.As(err, &apiErr) ||
		apiErr.Status != http.StatusNotImplemented || apiErr.Detail != "no OpenFGA" {
		t.Fatalf("501: %v", err)
	}
}
