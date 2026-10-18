package matura

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Event is a CloudEvents envelope as Matura sends it, by webhook, in the change feed or built from a snapshot
// (contract §5).
type Event struct {
	SpecVersion     string    `json:"specversion,omitempty"`
	ID              string    `json:"id,omitempty"`
	Source          string    `json:"source,omitempty"`
	Type            string    `json:"type,omitempty"`
	Time            string    `json:"time,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	TenantID        string    `json:"tenantid,omitempty"`
	Sequence        string    `json:"sequence,omitempty"`
	DataContentType string    `json:"datacontenttype,omitempty"`
	Data            EventData `json:"data"`
}

// EventData carries the changed object under its own name ({"object": "membership", "version": 41,
// "membership": {…}}), with the version the apply rule compares.
type EventData struct {
	Object  string
	Version int64
	Payload json.RawMessage
}

// Decode unmarshals the changed object into v.
func (e *Event) Decode(v any) error {
	return json.Unmarshal(e.Data.Payload, v)
}

func (d EventData) MarshalJSON() ([]byte, error) {
	m := map[string]any{"object": d.Object, "version": d.Version}
	if d.Object != "" && len(d.Payload) > 0 {
		m[d.Object] = d.Payload
	}
	return json.Marshal(m)
}

func (d *EventData) UnmarshalJSON(b []byte) error {
	*d = EventData{}
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	_ = json.Unmarshal(m["object"], &d.Object)
	var v any
	if json.Unmarshal(m["version"], &v) == nil {
		switch x := v.(type) {
		case float64:
			d.Version = int64(x)
		case string:
			d.Version, _ = strconv.ParseInt(x, 10, 64)
		}
	}
	if d.Object != "" {
		d.Payload = m[d.Object]
	}
	return nil
}
