# AEGIS Gateway (L4)

Every model call in the platform passes through this service. Middleware chain:

| # | Stage | Status | Threat |
|---|-------|--------|--------|
| 1 | OIDC authentication | ✅ Week 2 | T-07 |
| 2 | RBAC capability check | ✅ Week 2 | T-07 |
| 3 | PII redaction (Presidio) | 🔜 Week 3 | T-06 |
| 4 | Prompt injection defense (5-layer) | 🔜 Week 3 | T-01/T-02 |
| 5 | Model invocation (keyless, Entra ID) | ✅ Week 2 | T-16 |
| 6 | Output validation | 🔜 Week 3 | T-05 |
| 7 | Audit append (hash-chained) | ✅ Week 2 | T-13 |

Stages 3, 4, and 6 are explicitly marked pending in code rather than silently absent — a control that appears to exist but does nothing is worse than a documented gap (ADR-002).

## Local development

```powershell
docker compose up -d                      # local Postgres
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env               # then set OPENAI_ENDPOINT
uvicorn app.main:app --reload
```

Mint tokens for different personas and observe RBAC:

```powershell
$biz     = python ..\..\scripts\dev_token.py business_user
$auditor = python ..\..\scripts\dev_token.py auditor

# business_user CAN invoke the model
curl -H "Authorization: Bearer $biz" -H "Content-Type: application/json" `
     -d '{\"prompt\":\"Hello\"}' http://localhost:8000/v1/chat

# auditor CANNOT invoke the model (403) but CAN verify the audit chain
curl -H "Authorization: Bearer $auditor" http://localhost:8000/v1/audit/verify
```

## Endpoints

| Method | Path | Capability required |
|---|---|---|
| GET | `/health` | none |
| GET | `/v1/whoami` | authenticated |
| POST | `/v1/chat` | `model:invoke` |
| GET | `/v1/audit` | `audit:read` |
| GET | `/v1/audit/verify` | `audit:verify` |

## Tests

```powershell
python -m pytest
```

Includes the tamper-detection suite: modified payload, deleted record, and a forged record whose own hash was recomputed — all three must break chain verification.
