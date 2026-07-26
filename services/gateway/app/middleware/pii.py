"""
PII redaction (threat model T-06).

Redacts PII from prompts BEFORE the model call and BEFORE any audit write, so
sensitive data never reaches the model provider and never lands in the audit
trail. This is a data-minimization control.

Engine: Presidio with PATTERN-BASED recognizers only (no spaCy NLP engine).
This is a deliberate portability choice (ADR-006): the spaCy backend requires
compiled C extensions that some hardened/locked-down environments (Application
Control policies, restricted CI runners) block from loading. Pattern
recognizers cover the structured identifiers enterprises most need to protect
— emails, phones, credit cards, IBANs, national IDs, IP addresses, and
GCC-specific Emirates IDs — with zero native-code dependency.

The NLP engine (for free-text PERSON/LOCATION detection) is pluggable: in an
environment that permits spaCy, adding it back is a registry configuration
change, not a rewrite. Documented in ADR-006.

Fail-closed: if analysis raises, the caller rejects the request rather than
forwarding unredacted content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngine
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IbanRecognizer,
    IpRecognizer,
    PhoneRecognizer,
    UsSsnRecognizer,
)
from presidio_anonymizer import AnonymizerEngine


@dataclass(frozen=True)
class RedactionResult:
    text: str
    entities_found: list[str] = field(default_factory=list)
    count: int = 0

    @property
    def had_pii(self) -> bool:
        return self.count > 0


DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "IP_ADDRESS",
    "EMIRATES_ID",
]


class _NoNlpEngine(NlpEngine):
    """A no-op NLP engine so Presidio runs without spaCy. Pattern recognizers
    do not use it; it exists only to satisfy the analyzer's constructor."""

    def load(self) -> None:
        return None

    def is_loaded(self) -> bool:
        return True

    def process_text(self, text, language):
        from presidio_analyzer.nlp_engine import NlpArtifacts
        return NlpArtifacts(entities=[], tokens=[], tokens_indices=[],
                            lemmas=[], nlp_engine=self, language=language)

    def process_batch(self, texts, language, **kwargs):
        for t in texts:
            yield t, self.process_text(t, language)

    def is_stopword(self, word, language) -> bool:
        return False

    def is_punct(self, word, language) -> bool:
        return False

    def get_supported_entities(self):
        return []

    def get_supported_languages(self):
        return ["en"]


def _emirates_id_recognizer() -> PatternRecognizer:
    """Emirates ID: 784-YYYY-NNNNNNN-N (15 digits, hyphenated)."""
    pattern = Pattern(name="emirates_id",
                      regex=r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b", score=0.85)
    return PatternRecognizer(supported_entity="EMIRATES_ID", patterns=[pattern])


@lru_cache
def _engines() -> tuple[AnalyzerEngine, AnonymizerEngine]:
    registry = RecognizerRegistry()
    for rec in (EmailRecognizer(), PhoneRecognizer(), CreditCardRecognizer(),
                IbanRecognizer(), UsSsnRecognizer(), IpRecognizer(),
                _emirates_id_recognizer()):
        registry.add_recognizer(rec)

    analyzer = AnalyzerEngine(registry=registry, nlp_engine=_NoNlpEngine(),
                              supported_languages=["en"])
    return analyzer, AnonymizerEngine()


def redact(text: str, entities: list[str] | None = None) -> RedactionResult:
    """Redact PII from text. Raises on failure (caller fails closed)."""
    analyzer, anonymizer = _engines()
    results = analyzer.analyze(text=text, entities=entities or DEFAULT_ENTITIES,
                               language="en")
    if not results:
        return RedactionResult(text=text, entities_found=[], count=0)

    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    found = sorted({r.entity_type for r in results})
    return RedactionResult(text=anonymized.text, entities_found=found, count=len(results))
