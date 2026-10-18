package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSCIMFilterParsing(t *testing.T) {
	ok := map[string][]scimCond{
		`userName eq "a@b.test"`: {{Attr: "userName", Op: "eq", Value: "a@b.test"}},
		`emails[type eq "work"].value eq "x\"y"`: {{Attr: "emails", Bracket: []scimCond{{Attr: "type", Op: "eq",
			Value: "work"}}, Sub: "value", Op: "eq", Value: `x"y`}},
		`members[value eq "u1"]`: {{Attr: "members", Bracket: []scimCond{{Attr: "value", Op: "eq", Value: "u1"}}}},
		`id eq "g" AND members[value eq "u"]`: {{Attr: "id", Op: "eq", Value: "g"},
			{Attr: "members", Bracket: []scimCond{{Attr: "value", Op: "eq", Value: "u"}}}},
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "z"`: {{Attr: "userName", Op: "eq", Value: "z"}},
		`active eq false`: {{Attr: "active", Op: "eq", Value: false}},
	}
	for in, want := range ok {
		got, err := parseSCIMFilter(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{`userName sw "a"`, `a eq "x" or b eq "y"`, `(a eq "x")`, `userName eq`,
		`userName eq "open`, `emails[type eq "work"`, `userName`} {
		if _, err := parseSCIMFilter(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestSCIMPatchEngine(t *testing.T) {
	res := func() map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{"userName":"a","active":true,"name":{"givenName":"A"},
			"emails":[{"value":"a@x.test","type":"work","primary":true},{"value":"a@home.test","type":"home"}],
			"members":[{"value":"u1"},{"value":"u2"}]}`), &m)
		return m
	}
	cases := []struct {
		name  string
		ops   string
		check func(map[string]any) bool
	}{
		{"no path merges", `[{"op":"replace","value":{"active":false,"name":{"familyName":"B"}}}]`,
			func(m map[string]any) bool {
				n := m["name"].(map[string]any)
				return m["active"] == false && n["givenName"] == "A" && n["familyName"] == "B"
			}},
		{"filtered sub-attribute", `[{"op":"Replace","path":"emails[type eq \"work\"].value","value":"new@x.test"}]`,
			func(m map[string]any) bool { return m["emails"].([]any)[0].(map[string]any)["value"] == "new@x.test" }},
		{"filter without match adds", `[{"op":"add","path":"emails[type eq \"other\"].value","value":"o@x.test"}]`,
			func(m map[string]any) bool { return len(m["emails"].([]any)) == 3 }},
		{"remove by filter", `[{"op":"remove","path":"members[value eq \"u1\"]"}]`,
			func(m map[string]any) bool { return len(m["members"].([]any)) == 1 }},
		{"remove by value list", `[{"op":"Remove","path":"members","value":[{"value":"U2"}]}]`,
			func(m map[string]any) bool { return len(m["members"].([]any)) == 1 }},
		{"add de-duplicates", `[{"op":"add","path":"members","value":[{"value":"u2"},{"value":"u3"}]}]`,
			func(m map[string]any) bool { return len(m["members"].([]any)) == 3 }},
		{"extension attribute", `[{"op":"add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value","value":"m"}]`,
			func(m map[string]any) bool {
				return m[scimEnterprise].(map[string]any)["manager"].(map[string]any)["value"] == "m"
			}},
		{"case-insensitive names", `[{"op":"replace","path":"NAME.GIVENNAME","value":"Z"}]`,
			func(m map[string]any) bool { return m["name"].(map[string]any)["givenName"] == "Z" }},
		{"remove sub-attribute", `[{"op":"remove","path":"name.givenName"}]`,
			func(m map[string]any) bool { return len(m["name"].(map[string]any)) == 0 }},
	}
	for _, c := range cases {
		var ops []scimPatchOperation
		if err := json.Unmarshal([]byte(c.ops), &ops); err != nil {
			t.Fatal(err)
		}
		m := res()
		if err := applySCIMPatch(m, ops); err != nil || !c.check(m) {
			t.Errorf("%s: %v %v", c.name, m, err)
		}
	}
	for _, bad := range []string{`[]`, `[{"op":"move","path":"a"}]`, `[{"op":"remove"}]`, `[{"op":"add","value":3}]`} {
		var ops []scimPatchOperation
		_ = json.Unmarshal([]byte(bad), &ops)
		if err := applySCIMPatch(res(), ops); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}
