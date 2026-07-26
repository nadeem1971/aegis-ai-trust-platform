# ADR-006: PII Redaction Engine — Pattern-Based for Hardened Environments

**Status:** Accepted · **Date:** Week 3

## Context
The PII redaction control (T-06) was first implemented with Microsoft Presidio
using its default spaCy NLP engine, which adds ML-based detection of free-text
entities (PERSON, LOCATION). On a hardened development machine, spaCy failed to
load: its compiled C extensions were blocked by an OS Application Control
policy (`ImportError: DLL load failed ... blocked by an Application Control
policy`). This is not a one-off: government, banking, and critical-infrastructure
environments — AEGIS's target market — routinely run application-allowlisting
(e.g. WDAC, AppLocker) and network egress restrictions that block exactly this
class of native-code dependency and model downloads.

## Decision
Run Presidio with **pattern-based recognizers only**, no NLP engine:
EmailRecognizer, PhoneRecognizer, CreditCardRecognizer, IbanRecognizer,
UsSsnRecognizer, IpRecognizer, plus a custom Emirates ID recognizer. A no-op
NLP engine satisfies the analyzer's constructor. The NLP engine remains
**pluggable**: in an environment that permits spaCy (or a transformer backend),
re-enabling ML entity detection is a registry configuration change, not a
rewrite.

## Rationale
1. **Deployability where it matters.** A security control that cannot run in a
   locked-down environment is useless precisely where security matters most.
   Pattern recognizers have zero native-code dependency and need no model
   download, so they run under application-allowlisting and offline.
2. **Coverage where it counts.** The highest-risk PII in enterprise prompts is
   structured and regex-detectable: emails, phone numbers, payment cards,
   IBANs, national IDs, IP addresses. These are exactly what pattern
   recognizers catch deterministically.
3. **Honest limitation.** Free-text names and locations without structured
   markers are not caught in this mode. This is documented, not hidden, and the
   risk-triage rubric flags use cases handling unstructured personal narrative
   for the NLP-enabled deployment profile.

## Consequences
- (+) PII redaction runs on hardened, allowlisted, network-restricted hosts.
- (+) Deterministic, explainable, auditable — each redaction names the entity
  type without storing the value.
- (+) Custom GCC recognizer (Emirates ID) demonstrates jurisdiction extension.
- (\u2212) No ML-based PERSON/LOCATION detection in the default profile; mitigated
  by the pluggable engine and a documented deployment profile that adds it
  where the environment permits.
