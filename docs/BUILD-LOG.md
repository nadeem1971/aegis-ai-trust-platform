# AEGIS Build Log — Field Notes

Raw notes captured during the build. Source material for the Week 8 write-up.
Honest record of what broke and why — the useful part of a portfolio.

## Week 1 — Foundations
- Threat model (18 threats, STRIDE+ATLAS) authored before first line of code.
- Terraform baseline to UAE North: RG, VNet, VNet-isolated Postgres (public
  access disabled — T-06 verified live), RBAC Key Vault, budget guard.
- DevSecOps CI green: gitleaks, Bandit, Trivy, terraform-validate.
- **Near-miss:** `terraform.tfstate` (containing the DB password) got staged
  for commit. Caught before push; history wiped and re-committed clean.
  gitleaks would have blocked it — a live demonstration of threat T-16.
- **Lesson:** `.gitignore` must exclude `*.tfstate` AND `*.tfplan` from day one.

## Week 2 — Gateway Foundations
Built: OIDC/RBAC, hash-chained audit log, keyless Azure OpenAI invocation.
13/13 tests pass including 3 tamper-detection scenarios.

### What broke, and the fix
1. **Model deprecation (T-15/T-18 made real).** Pinned `gpt-4o 2024-11-20`;
   Azure rejected it — the entire GPT-4o family had entered `Deprecating`
   state and cannot be deployed new. A plain model-list lookup showed the
   model present, hiding the block; only `lifecycleStatus` revealed it.
   → Switched to `gpt-5.4-mini 2026-03-17` (GA). Moved model name/version/SKU
   to Terraform variables. Documented as ADR-004.

2. **Sovereignty constraint discovered.** Every GA model in UAE North offers
   only `GlobalStandard` — inference can run in any region worldwide, which
   undercuts the in-region residency claim. Documented honestly in ADR-004
   with mitigation options (DataZone SKUs, self-hosted vLLM, contractual).
   This is the strongest interview point of the build: identifying exactly
   where a sovereignty claim breaks, rather than asserting it blindly.

3. **Account quota (turned into better architecture).** Subscription allows
   one OpenAI S0 account, already used by a sibling project. Instead of a
   quota request, AEGIS consumes the existing account as a shared model plane
   and adds its own deployment — a realistic enterprise pattern (shared,
   centrally-governed model plane; per-app deployments and access). ADR-005.

4. **GPT-5 API change.** The model rejected `max_tokens` — the GPT-5
   generation requires `max_completion_tokens`. The gateway's own audit trail
   captured the exact Azure error, tamper-evidently, and the auditor role
   retrieved it — a live demonstration of the platform's forensic value.
   → One-line fix.

5. **Windows tooling friction.** curl on the local terminal returned empty
   bodies / HTTP 000 for the chat endpoint while the server logged 200 OK.
   Not a gateway fault — a client-side piping quirk. A Python HTTP client
   confirmed the real 200 response with a genuine model completion.
   → Added `test_chat.py` as a reliable local smoke test.

### Week 2 done-criteria — met
- [x] Same prompt, two identities, two outcomes (business_user 200, auditor 403)
- [x] Tamper detection: modified/deleted/forged records all break the chain
- [x] Keyless model invocation (local_auth disabled; Entra identity only)
- [x] 13/13 tests passing; audit module coverage 95%
