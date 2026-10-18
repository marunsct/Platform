package api_test

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/marunsct/Platform/internal/api"
)

// openAPIAliases maps operations the document lists as their own paths to the router pattern that serves them:
// colon actions inside a path segment are dispatched by one handler on the wildcard.
var openAPIAliases = map[string]string{
	"POST /v1/apps/{app}/placements/{tid}:ready":           "POST /v1/apps/{app}/placements/{tid}",
	"POST /v1/apps/{app}/placements/{tid}:deleted":         "POST /v1/apps/{app}/placements/{tid}",
	"POST /v1/tenants/{tid}/invitations/{id}:resend":       "POST /v1/tenants/{tid}/invitations/{id}",
	"POST /v1/tenants/{tid}:restore":                       "POST /v1/tenants/{tid}",
	"POST /v1/tenants/{tid}/support-access/{id}:approve":   "POST /v1/tenants/{tid}/support-access/{id}",
	"POST /v1/tenants/{tid}/support-access/{id}:deny":      "POST /v1/tenants/{tid}/support-access/{id}",
	"POST /v1/tenants/{tid}/support-access/{id}:revoke":    "POST /v1/tenants/{tid}/support-access/{id}",
	"POST /admin/v1/tenants/{tid}:suspend":                 "POST /admin/v1/tenants/{tid}",
	"POST /admin/v1/tenants/{tid}:resume":                  "POST /admin/v1/tenants/{tid}",
	"POST /admin/v1/tenants/{tid}:restore":                 "POST /admin/v1/tenants/{tid}",
	"POST /admin/v1/tenants/{tid}/support-access/{id}:end": "POST /admin/v1/tenants/{tid}/support-access/{id}",
	"POST /v1/apps/{app}/tenants/{tid}:check":              "POST /v1/apps/{app}/tenants/{tid}",
	"POST /v1/apps/{app}/tenants/{tid}:batch-check":        "POST /v1/apps/{app}/tenants/{tid}",
	"POST /v1/apps/{app}/tenants/{tid}:list-objects":       "POST /v1/apps/{app}/tenants/{tid}",
}

var openAPIMethods = []string{"get", "put", "post", "delete", "patch", "head", "options", "trace"}

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("api/openapi.yaml: %v", err)
	}
	return doc
}

// TestOpenAPIMatchesRoutes fails when a route is served but not documented, or documented but not served.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	doc := loadOpenAPI(t)
	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("api/openapi.yaml has no paths")
	}

	documented := map[string]bool{}
	ops := 0
	for path, item := range paths {
		pi, _ := item.(map[string]any)
		for _, m := range openAPIMethods {
			if _, ok := pi[m]; !ok {
				continue
			}
			ops++
			op := strings.ToUpper(m) + " " + path
			if target, ok := openAPIAliases[op]; ok {
				op = target
			}
			documented[op] = true
		}
	}
	for alias := range openAPIAliases {
		path := alias[strings.Index(alias, " ")+1:]
		if _, ok := paths[path]; !ok {
			t.Errorf("alias %q names a path the document does not have", alias)
		}
	}

	server := api.New(nil, nil, nil, nil)
	served := map[string]bool{}
	for _, r := range server.Routes() {
		if served[r] {
			t.Errorf("route %q registered twice", r)
		}
		served[r] = true
	}
	if !served["POST /internal/v1/token-context"] {
		t.Error("Routes() should list the internal routes even when they are not enabled")
	}

	for r := range served {
		if !documented[r] {
			t.Errorf("route %q is served but not in api/openapi.yaml", r)
		}
	}
	for r := range documented {
		if !served[r] {
			t.Errorf("api/openapi.yaml documents %q, which is not served", r)
		}
	}
	t.Logf("%d routes served, %d operations documented", len(served), ops)
}

// TestOpenAPIOperations checks every operation is complete enough for generated clients.
func TestOpenAPIOperations(t *testing.T) {
	doc := loadOpenAPI(t)
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1") {
		t.Errorf("openapi = %q, want 3.1.x", v)
	}
	paths, _ := doc["paths"].(map[string]any)
	ids := map[string]string{}
	wildcard := regexp.MustCompile(`\{([^}]+)\}`)
	for path, item := range paths {
		pi, _ := item.(map[string]any)
		for _, m := range openAPIMethods {
			raw, ok := pi[m]
			if !ok {
				continue
			}
			name := strings.ToUpper(m) + " " + path
			op, _ := raw.(map[string]any)
			id, _ := op["operationId"].(string)
			switch {
			case id == "":
				t.Errorf("%s has no operationId", name)
			case ids[id] != "":
				t.Errorf("operationId %q is used by %s and %s", id, ids[id], name)
			default:
				ids[id] = name
			}
			if s, _ := op["summary"].(string); strings.TrimSpace(s) == "" {
				t.Errorf("%s has no summary", name)
			}
			if rs, _ := op["responses"].(map[string]any); len(rs) == 0 {
				t.Errorf("%s has no responses", name)
			}

			// every path wildcard is declared as a path parameter, on the path or the operation
			declared := map[string]bool{}
			for _, list := range []any{pi["parameters"], op["parameters"]} {
				ps, _ := list.([]any)
				for _, p := range ps {
					pm, _ := p.(map[string]any)
					if ref, ok := pm["$ref"].(string); ok {
						pm, _ = resolveRef(doc, ref).(map[string]any)
					}
					if pm["in"] == "path" {
						declared[fmt.Sprint(pm["name"])] = true
					}
				}
			}
			for _, w := range wildcard.FindAllStringSubmatch(path, -1) {
				if !declared[w[1]] {
					t.Errorf("%s does not declare path parameter %q", name, w[1])
				}
			}
		}
	}
}

// TestOpenAPIRefsResolve checks every $ref points at something in the document.
func TestOpenAPIRefsResolve(t *testing.T) {
	doc := loadOpenAPI(t)
	var walk func(at string, v any)
	walk = func(at string, v any) {
		switch v := v.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				if !strings.HasPrefix(ref, "#/") {
					t.Errorf("%s: $ref %q is not local", at, ref)
				} else if resolveRef(doc, ref) == nil {
					t.Errorf("%s: $ref %q does not resolve", at, ref)
				}
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				walk(at+"/"+k, v[k])
			}
		case []any:
			for i, e := range v {
				walk(fmt.Sprintf("%s/%d", at, i), e)
			}
		}
	}
	walk("#", doc)
}

// resolveRef follows a local JSON pointer ("#/components/schemas/Tenant"); nil when it leads nowhere.
func resolveRef(doc map[string]any, ref string) any {
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}
