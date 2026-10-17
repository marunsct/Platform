// Package matura is the Matura SDK for Go: verify Matura access tokens, check permissions, receive signed webhooks,
// and keep the matura_* contract tables current in PostgreSQL (contract: docs/spec/03-app-integration-contract.md).
//
// It mirrors the Python and TypeScript SDKs: Verifier and Principal (level 1), Contract, WebhookHandler, Client and
// Sync (level 2), the placement calls on Client (level 3), and WithTenant for row-level security in shared mode.
// Package maturatest mints tokens and signed events for tests.
package matura
