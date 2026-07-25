# ADR-003: Azure OpenAI Network Posture — Staged Private Endpoint Adoption

**Status:** Accepted · **Date:** Week 2

## Context
Threat model T-06 calls for private endpoints on the model plane so inference traffic never traverses the public internet. However, during Weeks 2–3 the gateway is developed and tested from a local workstation, which sits outside the VNet. A private-only endpoint would make local development impossible, and the deployed Postgres is already VNet-isolated (no public access at all).

## Decision
Stage the network posture with a single flag, `openai_private_only` (default `false` in dev):

- **Development phase:** public network access enabled, but with `local_auth_enabled = false` — shared API keys are disabled entirely, so the only way to call the model is with an Entra ID token from an identity holding the `Cognitive Services OpenAI User` role.
- **Production posture:** set `openai_private_only = true` to deny public access, provision the private endpoint and `privatelink.openai.azure.com` DNS zone, and reach the model only from within the VNet.

Local development uses a container-local PostgreSQL (docker compose) rather than a tunnel to the deployed database.

## Rationale
Identity is the stronger control here. Disabling key auth removes the most common Azure OpenAI compromise path (leaked keys in code, configs, or notebooks — T-16) and means public *network* reachability alone grants nothing without a valid Entra token. The private endpoint then adds network-layer defence in depth when the gateway runs in Container Apps and no longer needs workstation access.

## Consequences
- (+) Zero API keys exist anywhere in the system at any phase.
- (+) A one-line variable change moves the platform to production posture; the private endpoint code is written and reviewed now, not retrofitted later.
- (−) During development the endpoint is publicly reachable (authenticated-only). Recorded as a time-boxed accepted risk in the threat model, closed at Week 6 deployment.
