// Package events turns outbox changes into CloudEvents, signs them, and runs the relay that sequences the outbox,
// delivers webhooks and prunes old rows (technical specification §8, contract §5–§7).
package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/marunsct/Platform/internal/store"
)

// Envelope is a CloudEvents 1.0 event in structured JSON mode.
type Envelope struct {
	SpecVersion     string    `json:"specversion"`
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Type            string    `json:"type"`
	Time            time.Time `json:"time"`
	Subject         string    `json:"subject"`
	TenantID        string    `json:"tenantid,omitempty"`
	Sequence        string    `json:"sequence"`
	DataContentType string    `json:"datacontenttype"`
	Data            Data      `json:"data"`
}

// Data carries the changed object under its own name, with the version the apply rule compares.
type Data struct {
	Object  string
	Version int64
	Payload json.RawMessage
}

func (d Data) MarshalJSON() ([]byte, error) {
	obj, _ := json.Marshal(d.Object)
	ver := strconv.FormatInt(d.Version, 10)
	return []byte(`{"object":` + string(obj) + `,"version":` + ver + `,` + string(obj) + `:` + string(d.Payload) + `}`), nil
}

// ObjectOf names the object a type is about: matura.membership.added → membership, matura.app.role.updated →
// app_role, matura.tenant_app.enabled → tenant_app.
func ObjectOf(typ string) string {
	parts := strings.Split(strings.TrimPrefix(typ, "matura."), ".")
	if len(parts) < 2 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], "_")
}

// FromChange builds the envelope for a change. The id is stable across the feed and every webhook delivery, so
// receivers can de-duplicate on it.
func FromChange(source string, c store.Change) Envelope {
	e := Envelope{
		SpecVersion: "1.0", ID: "evt_" + strconv.FormatInt(c.ID, 10), Source: source, Type: c.Type,
		Time: c.Time.UTC(), Subject: c.Subject, Sequence: strconv.FormatInt(c.Seq, 10),
		DataContentType: "application/json",
		Data:            Data{Object: ObjectOf(c.Type), Version: c.Version, Payload: c.Payload},
	}
	if c.TenantID != nil {
		e.TenantID = c.TenantID.String()
	}
	return e
}

// Sign returns the Matura-Signature header value: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">.
func Sign(secret []byte, at time.Time, body []byte) string {
	t := strconv.FormatInt(at.Unix(), 10)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac(secret, t, body))
}

func mac(secret []byte, t string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(t))
	m.Write([]byte("."))
	m.Write(body)
	return m.Sum(nil)
}

// Tolerance is how far a signature's timestamp may be from now.
const Tolerance = 5 * time.Minute

var ErrBadSignature = errors.New("webhook signature does not match")

// Verify checks a Matura-Signature header the way every receiver should (contract §10.2). Several v1 values are
// allowed, so a secret can be rotated.
func Verify(secret []byte, header string, body []byte, now time.Time) error {
	var t string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			t = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ErrBadSignature
	}
	if d := now.Sub(time.Unix(ts, 0)); d > Tolerance || d < -Tolerance {
		return errors.New("webhook signature timestamp is too old or in the future")
	}
	want := mac(secret, t, body)
	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrBadSignature
}
