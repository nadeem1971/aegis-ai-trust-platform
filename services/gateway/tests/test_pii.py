"""PII redaction tests (T-06). Uses Presidio pattern recognizers only — no
spaCy, no native DLLs, no model download — so these run in hardened/CI
environments (ADR-006)."""

import pytest
from app.middleware.pii import redact


def test_email_redacted():
    r = redact("Contact me at john.doe@example.com please")
    assert r.had_pii
    assert "EMAIL_ADDRESS" in r.entities_found
    assert "john.doe@example.com" not in r.text


def test_credit_card_redacted():
    r = redact("My card number is 4532015112830366")
    assert "CREDIT_CARD" in r.entities_found
    assert "4532015112830366" not in r.text


def test_emirates_id_redacted():
    """GCC-specific custom recognizer (ADR-006)."""
    r = redact("Emirates ID 784-1990-1234567-8 on file")
    assert "EMIRATES_ID" in r.entities_found
    assert "784-1990-1234567-8" not in r.text


def test_ip_address_redacted():
    r = redact("The server IP is 192.168.1.100")
    assert "IP_ADDRESS" in r.entities_found


def test_clean_text_untouched():
    r = redact("What is AI governance and why does it matter?")
    assert not r.had_pii
    assert r.text == "What is AI governance and why does it matter?"


def test_multiple_pii_types():
    r = redact("Email admin@bank.ae, card 4532015112830366")
    assert r.count >= 2
    assert "admin@bank.ae" not in r.text
    assert "4532015112830366" not in r.text
