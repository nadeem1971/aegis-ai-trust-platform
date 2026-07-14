# ADR-001: Azure as Primary Cloud Platform

**Status:** Accepted · **Date:** Week 1

## Context
AEGIS targets regulated enterprises in Government, Banking, Telecom, and Critical Infrastructure, with a GCC market focus (UAE, Qatar, KSA). These sectors demand in-region data residency, enterprise identity integration, and managed AI services with private networking. The author's prior platform work (retail-agentic-ai-platform) is GCP-based; a deliberate decision on cloud is needed.

## Decision
Build AEGIS Azure-native (UAE North primary; Qatar Central referenced in residency patterns), while keeping the application layer cloud-portable: all Azure dependencies sit behind interfaces (model client, secret store, identity, search) so the security and governance logic is not cloud-coupled.

## Rationale
1. **GCC data residency:** Azure operates in-country regions in UAE and Qatar — often the deciding factor for government and banking clients in these markets.
2. **Enterprise identity gravity:** Entra ID is the incumbent IdP in the target sectors; OIDC + Managed Identities give a zero-stored-credential design natively.
3. **AI security tooling alignment:** Azure AI Content Safety, Prompt Shields, and Microsoft PyRIT form a coherent first-party stack for the gateway and red-team planes.
4. **Portfolio complementarity:** a second-cloud flagship demonstrates multi-cloud architectural range alongside the existing GCP platform.

## Consequences
- (+) Strongest possible residency and identity story for GCC clients.
- (+) Private endpoints to Azure OpenAI keep model traffic off the public internet (mitigates T-06).
- (−) Some components (Prompt Shields, Content Safety) are Azure-specific; mitigated by the interface layer and by documenting open-source equivalents (Rebuff-style classifiers, NeMo Guardrails) in each pattern doc.
- (−) Azure OpenAI capacity/model availability per region must be verified at build time (lesson carried from SafeWatch AI's GPT-4o UAE North dependency).
