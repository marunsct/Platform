package readiness

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OSCALVersion is the OSCAL release the assessment results follow.
const OSCALVersion = "1.1.2"

// oscalNS seeds the name-based UUIDs, so the same report always gives the same document.
var oscalNS = uuid.MustParse("6f1c1d0e-5b7a-4c33-9a43-2f4f6e0c6a10")

func oscalUUID(r Report, parts ...string) string {
	name := r.GeneratedAt.Format(time.RFC3339Nano)
	for _, p := range parts {
		name += "/" + p
	}
	return uuid.NewSHA1(oscalNS, []byte(name)).String()
}

// OSCAL turns a report into a minimal OSCAL assessment-results document: one result, one observation per control
// with its evidence, and one finding per applicable control (satisfied or not-satisfied). Not-applicable controls
// get an observation only.
func OSCAL(r Report) map[string]any {
	at := r.GeneratedAt.UTC().Format(time.RFC3339)
	var observations, findings []map[string]any
	for _, c := range r.Controls {
		obsID := oscalUUID(r, c.ID, "observation")
		props := []map[string]any{{"name": "matura-status", "ns": "https://matura.dev/ns/oscal", "value": string(c.Status)}}
		for _, ref := range c.Refs {
			props = append(props, map[string]any{"name": "framework-reference", "ns": "https://matura.dev/ns/oscal",
				"value": ref.Framework + " " + ref.ID})
		}
		observations = append(observations, map[string]any{
			"uuid":        obsID,
			"title":       c.Title,
			"description": c.Evidence,
			"props":       props,
			"methods":     []string{"TEST"},
			"types":       []string{"control-objective"},
			"subjects": []map[string]any{{"subject-uuid": oscalUUID(r, "installation"), "type": "component",
				"title": r.Product}},
			"collected": at,
			"links":     []map[string]any{{"href": c.Docs, "rel": "reference"}},
		})
		if c.Status == NotApplicable {
			continue
		}
		state := "satisfied"
		if c.Status == Fail {
			state = "not-satisfied"
		}
		findings = append(findings, map[string]any{
			"uuid":        oscalUUID(r, c.ID, "finding"),
			"title":       c.Title,
			"description": fmt.Sprintf("%s. Fix: %s", c.Evidence, c.Fix),
			"target": map[string]any{
				"type":      "objective-id",
				"target-id": c.ID,
				"status":    map[string]any{"state": state},
			},
			"related-observations": []map[string]any{{"observation-uuid": obsID}},
		})
	}
	result := map[string]any{
		"uuid":  oscalUUID(r, "result"),
		"title": "Matura readiness check",
		"description": fmt.Sprintf("%d of %d applicable controls pass (%.1f%%). %s", r.Passed, r.Passed+r.Failed,
			r.Score, Notice),
		"start":             at,
		"end":               at,
		"reviewed-controls": map[string]any{"control-selections": []map[string]any{{"include-all": map[string]any{}}}},
		"observations":      observations,
	}
	if len(findings) > 0 {
		result["findings"] = findings
	}
	return map[string]any{"assessment-results": map[string]any{
		"uuid": oscalUUID(r, "assessment-results"),
		"metadata": map[string]any{
			"title":         r.Product + " readiness assessment results",
			"last-modified": at,
			"version":       at,
			"oscal-version": OSCALVersion,
			"remarks":       Notice,
		},
		"import-ap": map[string]any{"href": DocsBase},
		"results":   []map[string]any{result},
	}}
}
