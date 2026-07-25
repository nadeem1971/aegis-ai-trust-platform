"""Audit chain tests (threat model T-13) and RBAC capability tests (T-07).

The chain tests use a real Postgres (docker compose provides one locally, and
CI spins up a service container) because the append path depends on
transactional locking that an in-memory fake would not reproduce faithfully.
"""

from __future__ import annotations

import json
import os

import asyncpg
import pytest
import pytest_asyncio

from app.audit import GENESIS_HASH, AuditChain, compute_hash
from app.auth import CAPABILITIES, Principal, Role

TEST_DSN = os.environ.get("TEST_DATABASE_URL", "postgresql://aegis:aegis@localhost:5432/aegis_test")


@pytest_asyncio.fixture
async def pool():
    pool = await asyncpg.create_pool(TEST_DSN, min_size=1, max_size=5)
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS audit_log CASCADE")
        await conn.execute(
            """
            CREATE TABLE audit_log (
                sequence    BIGINT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                payload     JSONB NOT NULL,
                prev_hash   CHAR(64) NOT NULL,
                record_hash CHAR(64) NOT NULL UNIQUE
            )
            """
        )
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def chain(pool):
    return AuditChain(pool)


# ── Chain construction ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_first_record_links_to_genesis(chain):
    record = await chain.append("test.event", {"a": 1})
    assert record.sequence == 1
    assert record.prev_hash == GENESIS_HASH


@pytest.mark.asyncio
async def test_records_link_sequentially(chain):
    first = await chain.append("test.one", {"n": 1})
    second = await chain.append("test.two", {"n": 2})
    third = await chain.append("test.three", {"n": 3})

    assert (first.sequence, second.sequence, third.sequence) == (1, 2, 3)
    assert second.prev_hash == first.record_hash
    assert third.prev_hash == second.record_hash


@pytest.mark.asyncio
async def test_clean_chain_verifies(chain):
    for i in range(10):
        await chain.append("model.invocation", {"i": i})

    result = await chain.verify_chain()
    assert result.valid is True
    assert result.records_checked == 10
    assert result.broken_at is None


@pytest.mark.asyncio
async def test_empty_chain_is_valid(chain):
    result = await chain.verify_chain()
    assert result.valid is True
    assert result.records_checked == 0


# ── Tamper detection — the control that must not fail ────────────────

@pytest.mark.asyncio
async def test_detects_modified_payload(chain, pool):
    """The live demo: alter a historical record, watch verification break."""
    for i in range(5):
        await chain.append("model.invocation", {"prompt_chars": i * 10})

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE audit_log SET payload = $1::jsonb WHERE sequence = 3",
            json.dumps({"prompt_chars": 999999}),
        )

    result = await chain.verify_chain()
    assert result.valid is False
    assert result.broken_at == 3
    assert "altered" in result.reason


@pytest.mark.asyncio
async def test_detects_deleted_record(chain, pool):
    for i in range(5):
        await chain.append("model.invocation", {"i": i})

    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM audit_log WHERE sequence = 3")

    result = await chain.verify_chain()
    assert result.valid is False
    assert result.broken_at == 4
    assert "sequence gap" in result.reason


@pytest.mark.asyncio
async def test_detects_forged_record_with_recomputed_hash(chain, pool):
    """A sophisticated attacker recomputes the tampered record's own hash.
    The chain still breaks, because every subsequent prev_hash no longer
    matches — tampering requires rewriting the entire tail."""
    for i in range(5):
        await chain.append("model.invocation", {"i": i})

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM audit_log WHERE sequence = 2")
        forged_payload = {"i": 42}
        forged_hash = compute_hash(2, row["timestamp"], forged_payload, row["prev_hash"])
        await conn.execute(
            "UPDATE audit_log SET payload = $1::jsonb, record_hash = $2 WHERE sequence = 2",
            json.dumps(forged_payload),
            forged_hash,
        )

    result = await chain.verify_chain()
    assert result.valid is False
    assert result.broken_at == 3  # the *next* record exposes the forgery


@pytest.mark.asyncio
async def test_concurrent_appends_do_not_break_chain(chain):
    import asyncio

    await asyncio.gather(*(chain.append("concurrent", {"i": i}) for i in range(20)))

    result = await chain.verify_chain()
    assert result.valid is True
    assert result.records_checked == 20


# ── RBAC capability model (T-07) ─────────────────────────────────────

def principal_with(*roles: Role) -> Principal:
    return Principal(subject="test", name="Test User", roles=frozenset(roles))


def test_business_user_can_invoke_model_but_not_read_audit():
    p = principal_with(Role.BUSINESS_USER)
    assert p.has("model:invoke") is True
    assert p.has("audit:read") is False
    assert p.has("audit:verify") is False


def test_auditor_is_read_only_and_cannot_invoke_model():
    """Separation of duties: the auditor must never be able to use the system
    it audits."""
    p = principal_with(Role.AUDITOR)
    assert p.has("model:invoke") is False
    assert p.has("audit:read") is True
    assert p.has("audit:verify") is True


def test_security_analyst_can_invoke_and_read_but_not_admin():
    p = principal_with(Role.SECURITY_ANALYST)
    assert p.has("model:invoke") is True
    assert p.has("audit:read") is True
    assert p.has("admin:config") is False


def test_platform_admin_has_all_capabilities():
    p = principal_with(Role.PLATFORM_ADMIN)
    assert all(p.has(cap) for cap in CAPABILITIES)


def test_no_roles_grants_nothing():
    p = Principal(subject="test", name="Nobody", roles=frozenset())
    assert not any(p.has(cap) for cap in CAPABILITIES)
