"""
Tamper-evident audit log (threat model T-13, T-14).

Design:
  Every audited event is appended to `audit_log` with a SHA-256 hash computed
  over (sequence, timestamp, canonical payload, previous record's hash).
  Any retroactive modification or deletion breaks the chain from that point
  forward, and `verify_chain()` reports the first broken sequence number.

  Immutability is enforced at two levels:
    1. Application: this module only ever INSERTs.
    2. Database: the `aegis_app` role is granted INSERT/SELECT only on this
       table (see schema.sql) — it cannot UPDATE or DELETE.

  Production note: this is a demonstrable, near-zero-cost integrity pattern.
  In production it would be backed by Azure Confidential Ledger (or an
  equivalent immutable ledger) with near-real-time SIEM streaming, so an
  independent copy exists outside the application's blast radius.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import asyncpg

GENESIS_HASH = "0" * 64


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic serialization — key order and separators must never vary,
    or a legitimate record would fail verification."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(sequence: int, timestamp: str, payload: dict[str, Any], prev_hash: str) -> str:
    material = f"{sequence}|{timestamp}|{canonical_json(payload)}|{prev_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    records_checked: int
    broken_at: int | None = None
    reason: str | None = None


class AuditChain:
    """Append-only, hash-chained audit log backed by PostgreSQL."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def append(self, event_type: str, payload: dict[str, Any]) -> AuditRecord:
        """Append one event. Serialized per-write so concurrent requests cannot
        interleave and produce two records claiming the same predecessor."""
        timestamp = datetime.now(timezone.utc).isoformat()

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Lock the table for the duration of the append: the chain is a
                # strictly ordered structure, so writes must not interleave.
                await conn.execute("LOCK TABLE audit_log IN EXCLUSIVE MODE")

                row = await conn.fetchrow(
                    "SELECT sequence, record_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
                )
                sequence = (row["sequence"] + 1) if row else 1
                prev_hash = row["record_hash"] if row else GENESIS_HASH

                record_hash = compute_hash(sequence, timestamp, payload, prev_hash)

                await conn.execute(
                    """
                    INSERT INTO audit_log
                        (sequence, timestamp, event_type, payload, prev_hash, record_hash)
                    VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                    """,
                    sequence,
                    timestamp,
                    event_type,
                    canonical_json(payload),
                    prev_hash,
                    record_hash,
                )

        return AuditRecord(sequence, timestamp, event_type, payload, prev_hash, record_hash)

    async def verify_chain(self) -> ChainVerification:
        """Recompute every hash in order. Reports the first divergence."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT sequence, timestamp, event_type, payload, prev_hash, record_hash
                FROM audit_log ORDER BY sequence ASC
                """
            )

        expected_prev = GENESIS_HASH
        for index, row in enumerate(rows, start=1):
            if row["sequence"] != index:
                return ChainVerification(
                    valid=False,
                    records_checked=index - 1,
                    broken_at=row["sequence"],
                    reason=f"sequence gap: expected {index}, found {row['sequence']} (record deleted?)",
                )

            if row["prev_hash"] != expected_prev:
                return ChainVerification(
                    valid=False,
                    records_checked=index - 1,
                    broken_at=row["sequence"],
                    reason="prev_hash does not match preceding record",
                )

            recomputed = compute_hash(
                row["sequence"],
                row["timestamp"],
                json.loads(row["payload"]),
                row["prev_hash"],
            )
            if recomputed != row["record_hash"]:
                return ChainVerification(
                    valid=False,
                    records_checked=index - 1,
                    broken_at=row["sequence"],
                    reason="record content altered — recomputed hash differs",
                )

            expected_prev = row["record_hash"]

        return ChainVerification(valid=True, records_checked=len(rows))

    async def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT sequence, timestamp, event_type, payload, record_hash
                FROM audit_log ORDER BY sequence DESC LIMIT $1
                """,
                limit,
            )
        return [
            {
                "sequence": r["sequence"],
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "payload": json.loads(r["payload"]),
                "record_hash": r["record_hash"],
            }
            for r in rows
        ]
