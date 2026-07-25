"""
AEGIS Gateway (L4) — every model call in the platform passes through here.

Middleware chain (executed in order for POST /v1/chat):

    1. OIDC authentication            [Week 2  — auth.py]        T-07
    2. RBAC capability check          [Week 2  — auth.py]        T-07
    3. PII redaction (Presidio)       [Week 3  — pending]        T-06
    4. Prompt injection defense       [Week 3  — pending]        T-01/T-02
    5. Model invocation (Azure OpenAI, keyless)                  T-16
    6. Output validation              [Week 3  — pending]        T-05
    7. Audit append (hash-chained)    [Week 2  — audit.py]       T-13

Stages 3, 4 and 6 are stubbed with explicit NotImplemented markers rather
than silently absent — a security control that appears to exist but does
nothing is worse than a documented gap (ADR-002).
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

import asyncpg
from azure.identity import AzureCliCredential, DefaultAzureCredential, get_bearer_token_provider
from fastapi import Depends, FastAPI, HTTPException, Request
from openai import AsyncAzureOpenAI
from pydantic import BaseModel, Field

from .audit import AuditChain
from .auth import Principal, get_principal, requires
from .config import settings

SCOPE = "https://cognitiveservices.azure.com/.default"


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=settings.max_prompt_chars)
    system: str | None = None


class ChatResponse(BaseModel):
    request_id: str
    response: str
    audit_sequence: int
    latency_ms: int
    controls_applied: list[str]


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=10)

    schema = (Path(__file__).parent / "schema.sql").read_text()
    async with app.state.pool.acquire() as conn:
        await conn.execute(schema)

    app.state.audit = AuditChain(app.state.pool)

    # Local dev authenticates via the Azure CLI session; deployed
    # environments use managed identity (T-16). The SYNC credential + token
    # provider is used deliberately: the async credential shells out to `az`
    # in a way that is unreliable under Windows' ProactorEventLoop.
    app.state.credential = (
        AzureCliCredential() if settings.aegis_env == "dev" else DefaultAzureCredential()
    )
    app.state.openai = AsyncAzureOpenAI(
        azure_endpoint=settings.openai_endpoint,
        azure_ad_token_provider=get_bearer_token_provider(app.state.credential, SCOPE),
        api_version=settings.openai_api_version,
    )

    await app.state.audit.append("gateway.started", {"env": settings.aegis_env})
    yield

    await app.state.openai.close()
    app.state.credential.close()
    await app.state.pool.close()


app = FastAPI(
    title="AEGIS Gateway",
    description="Defense-in-depth LLM security gateway",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    async with request.app.state.pool.acquire() as conn:
        await conn.execute("SELECT 1")
    return {"status": "ok", "env": settings.aegis_env, "auth_mode": settings.auth_mode}


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    request: Request,
    principal: Annotated[Principal, Depends(requires("model:invoke"))],
) -> ChatResponse:
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    audit: AuditChain = request.app.state.audit
    controls: list[str] = ["authn.oidc", "authz.rbac"]

    # ── Stage 3: PII redaction — Week 3 ──────────────────────────────
    # from .middleware.pii import redact
    # prompt, pii_findings = redact(body.prompt)
    prompt = body.prompt

    # ── Stage 4: injection defense — Week 3 ──────────────────────────
    # from .middleware.injection import screen
    # verdict = screen(prompt)
    # if verdict.blocked: audit + raise 403

    messages = [{"role": "system", "content": body.system or "You are a helpful assistant."},
                {"role": "user", "content": prompt}]

    try:
        completion = await request.app.state.openai.chat.completions.create(
            model=settings.openai_deployment,
            messages=messages,
            max_completion_tokens=settings.openai_max_tokens,
        )
    except Exception as exc:
        await audit.append(
            "model.invocation_failed",
            {"request_id": request_id, "subject": principal.subject, "error": str(exc)[:500]},
        )
        raise HTTPException(status_code=502, detail="Model invocation failed") from exc

    answer = completion.choices[0].message.content or ""

    # ── Stage 6: output validation — Week 3 ──────────────────────────
    # from .middleware.output import validate
    # answer = validate(answer, system_prompt=body.system)

    latency_ms = int((time.perf_counter() - started) * 1000)

    # ── Stage 7: audit (T-13) ────────────────────────────────────────
    # NOTE: `prompt` is recorded post-redaction from Week 3 onward. Until
    # then only a length and hash are stored, never raw user content.
    record = await audit.append(
        "model.invocation",
        {
            "request_id": request_id,
            "subject": principal.subject,
            "name": principal.name,
            "roles": sorted(principal.roles),
            "deployment": settings.openai_deployment,
            "prompt_chars": len(prompt),
            "completion_tokens": completion.usage.completion_tokens if completion.usage else None,
            "prompt_tokens": completion.usage.prompt_tokens if completion.usage else None,
            "latency_ms": latency_ms,
            "controls_applied": controls,
        },
    )

    return ChatResponse(
        request_id=request_id,
        response=answer,
        audit_sequence=record.sequence,
        latency_ms=latency_ms,
        controls_applied=controls,
    )


@app.get("/v1/audit")
async def read_audit(
    request: Request,
    principal: Annotated[Principal, Depends(requires("audit:read"))],
    limit: int = 50,
) -> dict[str, Any]:
    entries = await request.app.state.audit.tail(min(limit, 200))
    return {"count": len(entries), "entries": entries}


@app.get("/v1/audit/verify")
async def verify_audit(
    request: Request,
    principal: Annotated[Principal, Depends(requires("audit:verify"))],
) -> dict[str, Any]:
    """Recompute the entire hash chain. This is the live tamper-evidence demo."""
    result = await request.app.state.audit.verify_chain()
    return {
        "valid": result.valid,
        "records_checked": result.records_checked,
        "broken_at": result.broken_at,
        "reason": result.reason,
    }


@app.get("/v1/whoami")
async def whoami(principal: Annotated[Principal, Depends(get_principal)]) -> dict[str, Any]:
    return {
        "subject": principal.subject,
        "name": principal.name,
        "roles": sorted(principal.roles),
        "capabilities": [c for c in ("model:invoke", "audit:read", "audit:verify", "admin:config")
                         if principal.has(c)],
    }
