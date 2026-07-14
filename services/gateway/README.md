# AEGIS Gateway (L4) — lands Weeks 2–3

FastAPI middleware chain (in order): OIDC auth → RBAC → Presidio PII
redaction → injection defense (heuristics + Prompt Shields + spotlighting)
→ Azure OpenAI (private endpoint) → output validation → hash-chained audit.

Done-criteria and threat mappings: see roadmap and docs/architecture/threat-model.md (T-01..T-07, T-13).
