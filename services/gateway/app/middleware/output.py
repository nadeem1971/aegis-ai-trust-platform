"""
Output validation (threat model T-05, insecure output handling).

Layer 5 of the injection defense: screens the model's RESPONSE before it is
returned, catching cases where an attack partially succeeded despite input
controls — system-prompt leakage, credential echo, or the model announcing it
has adopted an injected persona.

Verdict is advisory-to-blocking depending on tier: a leaked-secret pattern is
always redacted; a system-prompt echo is flagged and the response withheld in
high-risk tiers. As with input screening, the goal is high-signal, explainable
checks, not exhaustive coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class OutputVerdict(StrEnum):
    CLEAN = "clean"
    REDACTED = "redacted"
    WITHHELD = "withheld"


@dataclass(frozen=True)
class ValidationResult:
    verdict: OutputVerdict
    text: str
    reasons: list[str] = field(default_factory=list)


_SECRET_ECHO = re.compile(
    r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_SYSTEM_PROMPT_LEAK = re.compile(
    r"(you are a helpful assistant|my (system )?(instructions|prompt) (are|is)|"
    r"here (is|are) my (system )?(instructions|prompt))",
    re.IGNORECASE,
)
_PERSONA_ADOPTION = re.compile(
    r"\b(i am now|i will now act as|developer mode (enabled|on)|"
    r"jailbreak successful|dan mode)\b",
    re.IGNORECASE,
)


def validate(response: str, *, high_risk: bool = False) -> ValidationResult:
    reasons: list[str] = []
    text = response

    if _SECRET_ECHO.search(text):
        text = _SECRET_ECHO.sub("[REDACTED_SECRET]", text)
        reasons.append("credential-like string redacted from output")
        return ValidationResult(OutputVerdict.REDACTED, text, reasons)

    if _PERSONA_ADOPTION.search(text):
        reasons.append("model announced adoption of injected persona")
        return ValidationResult(OutputVerdict.WITHHELD, "", reasons)

    if _SYSTEM_PROMPT_LEAK.search(text):
        reasons.append("possible system-prompt leakage")
        if high_risk:
            return ValidationResult(OutputVerdict.WITHHELD, "", reasons)
        return ValidationResult(OutputVerdict.REDACTED, text, reasons)

    return ValidationResult(OutputVerdict.CLEAN, text, reasons)
