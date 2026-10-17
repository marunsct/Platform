package readiness

import "time"

// Trust is the public view of a report for the trust page: only controls marked public, their status and their
// framework references. No evidence text, tenant names or counts per tenant leave the installation.
type Trust struct {
	Product         string         `json:"product"`
	GeneratedAt     time.Time      `json:"generated_at"`
	Notice          string         `json:"notice"`
	InPlace         int            `json:"in_place"`
	Applicable      int            `json:"applicable"`
	SecurityContact string         `json:"security_contact,omitempty"`
	Controls        []TrustControl `json:"controls"`
}

type TrustControl struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // in-place, not-in-place, not-applicable
	Refs   []Ref  `json:"refs"`
}

// Public builds the trust page's view of a report.
func Public(r Report, contact string) Trust {
	t := Trust{Product: r.Product, GeneratedAt: r.GeneratedAt, Notice: Notice, SecurityContact: contact,
		Controls: []TrustControl{}}
	for _, c := range r.Controls {
		if !c.Public {
			continue
		}
		st := "not-applicable"
		switch c.Status {
		case Pass:
			st = "in-place"
			t.InPlace++
			t.Applicable++
		case Fail:
			st = "not-in-place"
			t.Applicable++
		}
		t.Controls = append(t.Controls, TrustControl{ID: c.ID, Title: c.Title, Status: st, Refs: c.Refs})
	}
	return t
}
