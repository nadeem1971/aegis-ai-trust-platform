# ADR-005: Shared Model Plane (Consuming an Existing OpenAI Account)

**Status:** Accepted · **Date:** Week 2

## Context
The Azure subscription enforces `OpenAI.S0.AccountCount = 1` — a single
Cognitive Services OpenAI account is permitted, and one already exists,
serving a sibling project. Creating a second account for AEGIS fails with
`InsufficientQuota`. A quota increase is possible but takes hours-to-days.

## Decision
AEGIS consumes the existing OpenAI account as a **shared model plane** via a
Terraform `data` source, and provisions only its own resources onto it:
- its own model deployment (`gpt-5-4-mini`), isolated by deployment name;
- its own role assignment (`Cognitive Services OpenAI User`) for scoped,
  keyless access.

AEGIS never manages the account's lifecycle or network configuration — those
belong to the account owner.

## Rationale
This is not merely a workaround; it mirrors a realistic enterprise pattern.
Large organizations centralize the model plane (one governed, monitored,
cost-controlled OpenAI resource) and let individual applications deploy their
own models and hold their own scoped identities against it. That is precisely
the posture AEGIS is designed to govern — so the platform embodying it is
coherent rather than contradictory.

## Consequences
- (+) Zero wait, zero additional cost, no quota request.
- (+) Demonstrates shared-model-plane governance as a design choice.
- (+) Per-app deployment naming and per-app RBAC keep the projects isolated
  on a shared resource.
- (−) AEGIS depends on an account it does not own; documented as an
  operational dependency. In a real deployment the shared account would be
  a first-class platform resource with its own ownership and controls.
- (−) Cost attribution on a shared account requires deployment-level tagging
  or usage metrics rather than account-level billing separation.
