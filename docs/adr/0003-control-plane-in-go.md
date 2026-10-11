# 0003 — Control plane in Go

Status: proposed · 2026-10-11

## Context
The control plane drives Kubernetes (operator, Cluster API), Keycloak, OpenFGA, OpenBao and NATS, and must be easy for
others to run.

## Decision
Write `tenantryd`, workers, operator and CLI in Go. Keycloak extensions in Java. Consoles in React/TypeScript.
SDKs in Python, TypeScript, Go (and React UI kit).

## Alternatives
Python (FastAPI) like AgentCanvas: faster for the current team, weaker for operators and single-binary distribution.
TypeScript/Node: one language with the consoles, weaker Kubernetes ecosystem.

## Consequences
+ Native fit with Kubernetes tooling, small static binaries, good performance.
− A second backend language in the suite; mitigated by a language-neutral API and first-class Python SDK.
