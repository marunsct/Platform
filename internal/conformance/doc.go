// Package conformance is the Matura conformance kit (contract §10.4): a black-box checker that any app, written in
// any language, runs against itself to prove it follows the app integration contract.
//
// It serves a test OIDC issuer (Issuer) whose tokens carry exactly the claims a Matura access token carries
// (contract §2), signs webhooks the way maturad does (contract §6, §10.2), and drives the app through the endpoints
// its manifest lists. The checks are:
//
//  1. seeding: signed matura.tenant.created, matura.workspace.created, matura.user.updated,
//     matura.membership.added and matura.grant.added events for two random tenants A and B are answered 2xx;
//  2. authentication: every list endpoint answers 401 without a token, with an expired token, a token for another
//     audience, a token signed by an unknown key and a token from another issuer (and 2xx with a valid one);
//  3. permissions: a valid token whose perms lack the endpoint's permission gets 403 on create and list;
//  4. isolation: a record A creates shows up in A's list but not in B's, and B cannot read it by id;
//  5. events: a valid event is accepted, a repeat is accepted again (idempotent), and a changed body, a stale
//     timestamp, another secret's signature or no signature at all are refused with 4xx.
//
// Seeding and events run only when the manifest names a webhook path.
//
// # The manifest's conformance section
//
// The checker reads the app's manifest (JSON, or YAML when the file ends in .yaml or .yml) and its optional
// conformance section:
//
//	"conformance": {
//	  "webhook_path": "/matura/events",
//	  "resources": [{
//	    "name": "notes",
//	    "create": {"method": "POST", "path": "/api/notes", "body": {"title": "conformance {{marker}}"}, "permission": "note.write"},
//	    "list":   {"method": "GET",  "path": "/api/notes", "permission": "note.read"},
//	    "read":   {"method": "GET",  "path": "/api/notes/{id}", "permission": "note.read"}
//	  }]
//	}
//
// {{marker}} in a create path or body is replaced with a unique string; the created record's id is read from the
// create response's "id" field, or "data.id"; {id} in the read path is replaced with it. read is optional. Methods
// default to POST for create and GET for list and read.
package conformance
