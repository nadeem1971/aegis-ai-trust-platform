# AEGIS — Enterprise AI Security, Governance & Trust Platform

> **Governed agents governing AI.** A production-grade reference platform that lets regulated enterprises approve AI use cases in days instead of weeks, block the attacks traditional security tooling cannot see, and generate compliance evidence continuously — mapped to NIST AI RMF, ISO/IEC 42001, OWASP LLM Top 10, and MITRE ATLAS.

**Status:** 🚧 Active build — Week 1 of 8 (foundations & threat model). See [Roadmap](#roadmap--built-vs-designed).

<!-- WEEK 8: metrics table + demo video go HERE, above the fold -->

| Target metric | Goal | Status |
|---|---|---|
| Adversarial attack success rate (gateway on vs off) | <5% vs ~70% baseline | Week 4 |
| Use case assessment cycle time | <48 hrs (low-risk tiers) | Week 6 |
| Audit chain integrity verification | 100%, live-demoable | Week 3 |
| Evidence generation for mapped controls | 100% automated | Week 6 |

---

## 1. The Problem

Every large enterprise is caught between two forces pulling in opposite directions.

**AI adoption is exploding without control.** Business teams deploy copilots, chatbots, and agents faster than anyone can track. Most CIOs cannot answer three basic questions: *How many AI systems are running in my organization? What data are they touching? Who approved them?* This is shadow AI — the new shadow IT, with a worse blast radius, because these systems make decisions, generate customer-facing content, and read sensitive data.

**The risk and regulatory wall is arriving.** The EU AI Act carries penalties up to 7% of global turnover. Regulators in banking, telecom, and government — including GCC bodies such as Qatar's NCSA and Saudi Arabia's SDAIA — increasingly expect demonstrable AI oversight. Meanwhile, the attacks are real and new: prompt injection, data leakage through RAG pipelines, agents manipulated into unauthorized actions. Traditional security tooling does not see any of this — a firewall cannot tell a legitimate prompt from a malicious one.

**The current enterprise answer is broken.** Organizations respond with one of two failure modes: govern by committee — a manual review board taking 6–8 weeks per use case, which teams simply bypass — or don't govern at all. The first kills innovation; the second is an incident waiting for a headline.

**The problem statement, in one sentence:**

> Enterprises cannot scale AI adoption because they have no systematic way to **approve it fast, secure it at runtime, and prove compliance continuously** — and every month of delay is either lost business value or accumulated unmanaged risk.

## 2. What AEGIS Does

AEGIS makes the **secure path the fast path**. Three planes, three outcomes:

| Plane | Capability | Executive outcome |
|---|---|---|
| **Governance** | AI use case registry, automated risk triage (incl. EU AI Act tiering), agent-generated threat models, human-in-the-loop approval gates, evidence vault | Know and approve every AI system — in under 48 hours for routine cases |
| **Security** | A defense-in-depth LLM gateway: identity & RBAC, PII redaction, 5-layer prompt injection defense, output validation, hash-chained tamper-evident audit trail | Every AI interaction passes through a checkpoint; attacks blocked and logged |
| **Assurance** | Continuous red teaming (Microsoft PyRIT + NVIDIA Garak) in CI, mapped to OWASP LLM Top 10 and MITRE ATLAS, findings auto-filed to the risk register | Security proven by measurement, not vendor claims; compliance evidence as a query, not a quarter |

**The signature differentiator:** the governance workflow itself is a supervised LangGraph multi-agent system — six agents that triage, threat-model, compliance-map, red-team, and audit every submitted use case — running **inside the same security controls they enforce**, with durable human-in-the-loop gates on every consequential decision. Governed agents governing AI.

## 3. The Anchor Use Case

**A retail bank wants to launch a customer-facing GenAI assistant** for account and product questions. High value (call deflection, 24/7 service) — but it touches PII, faces the public, and sits in high-risk regulatory territory.

**Without AEGIS:** the use case sits in legal/risk review for two months, launches with ad-hoc controls, and six months later a customer prompt-injects it into revealing another customer's data. Regulatory disclosure. Press story.

**With AEGIS:**
1. Business submits the use case Monday via the intake API/portal.
2. The **Intake** and **Risk Triage agents** classify it high-risk (customer-facing + financial + PII → EU AI Act high-risk obligations) within hours.
3. The **Threat Modeling agent** generates a STRIDE + MITRE ATLAS threat register specific to its architecture.
4. The workflow **pauses at a human approval gate** — the AI governance board reviews and approves with conditions Wednesday. The decision is signed into the audit chain.
5. The **Red Team Orchestrator** certifies the assistant against injection, jailbreak, and leakage suites before go-live — and re-tests on every release via CI.
6. It launches **behind the AEGIS gateway**: injection attempts blocked and logged, PII redacted, responses validated, every interaction on the tamper-evident audit trail.
7. When the central bank asks *"show me your AI oversight"* — the evidence pack is one export.

The same story transposes directly to a **telco** deploying agentic network-operations copilots or a **government entity** rolling out citizen-service AI under a national AI strategy.

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  L7  EXPERIENCE      Governance portal · approval screens · audit   │
├─────────────────────────────────────────────────────────────────────┤
│  L6  GOVERNANCE      Use case registry · risk triage (EU AI Act     │
│                      tiering) · evidence vault · policy-as-code     │
├─────────────────────────────────────────────────────────────────────┤
│  L5  AGENTIC RUNTIME LangGraph supervisor · 6 governance agents ·   │
│                      OPA tool-permission broker · durable HITL      │
├─────────────────────────────────────────────────────────────────────┤
│  L4  SECURITY        AI GATEWAY — OIDC/RBAC · Presidio PII          │
│      (all model      redaction · 5-layer injection defense ·        │
│       calls pass     output validation · hash-chained audit log     │
│       through here)                                                  │
├─────────────────────────────────────────────────────────────────────┤
│  L3  KNOWLEDGE       Secure RAG — ACL-trimmed retrieval ·           │
│                      ingestion scanning · citation grounding        │
├─────────────────────────────────────────────────────────────────────┤
│  L2  ASSURANCE       PyRIT + Garak harness · OWASP LLM Top 10 ·     │
│                      ATLAS scenarios · CI red-team regression       │
├─────────────────────────────────────────────────────────────────────┤
│  L1  OBSERVABILITY   OpenTelemetry · immutable audit · IR playbooks │
├─────────────────────────────────────────────────────────────────────┤
│  L0  INFRASTRUCTURE  Azure (UAE North) · Terraform · DevSecOps CI   │
└─────────────────────────────────────────────────────────────────────┘
```

Full architecture: [`docs/architecture/`](docs/architecture/) · Threat model: [`docs/architecture/threat-model.md`](docs/architecture/threat-model.md) · Decisions: [`docs/adr/`](docs/adr/)

## 5. Roadmap — Built vs Designed

This project deliberately follows a **depth-first strategy** ([ADR-002](docs/adr/ADR-002-depth-first-build-strategy.md)): a small number of capabilities built to production-demo quality, the remainder delivered as consulting-grade architecture patterns. Sequencing is the point.

| Capability | Status |
|---|---|
| Threat model & ADRs (this platform, before code) | ✅ Week 1 |
| Terraform baseline + DevSecOps CI | ✅ Week 1 |
| LLM Security Gateway (build) | 🔜 Weeks 2–3 |
| Red team harness + before/after metrics (build) | 🔜 Week 4 |
| Registry + agentic governance workflow with HITL (build) | 🔜 Weeks 5–6 |
| Secure RAG — poisoned-document defense demo (build) + full pattern (design) | 🔜 Week 7 |
| AI-SPM / shadow-AI discovery (design pattern) | 📐 Documented |
| Model supply chain security (design pattern) | 📐 Documented |
| Secure AI tooling vendor evaluation framework (design) | 📐 Documented |
| Incident response playbooks ×4 + tabletop | 📐 Week 7 |

## 6. Tech Stack

Azure (UAE North) · Azure OpenAI (private endpoints) · FastAPI · LangGraph (Postgres checkpointer) · Microsoft Presidio · Azure AI Content Safety / Prompt Shields · Open Policy Agent · PyRIT · Garak · PostgreSQL · Entra ID (OIDC, Managed Identities) · Key Vault · Terraform · GitHub Actions (gitleaks, Trivy, Bandit)

## 7. Compliance Mappings

Machine-readable control mappings live in [`docs/compliance/`](docs/compliance/) (from Week 7): **NIST AI RMF 1.0** (GOVERN/MAP/MEASURE/MANAGE) · **ISO/IEC 42001** Annex A + Statement of Applicability · **EU AI Act** risk tiering · **OWASP LLM Top 10 (2025)** · **MITRE ATLAS** · GCC overlays (Qatar NCSA, SDAIA, UAE AI Ethics).

---

**Author:** Nadeem Ahmad — Principal Enterprise AI Architect · Dubai, UAE
[LinkedIn](https://www.linkedin.com/in/nadeem-ahmad-0ba5b328/) · [GitHub](https://github.com/nadeem1971)

Related work: [retail-agentic-ai-platform](https://github.com/nadeem1971/retail-agentic-ai-platform) (7-agent LangGraph platform on GCP) · [ai-governance-patterns-gcp](https://github.com/nadeem1971/ai-governance-patterns-gcp) (the pattern library this platform implements) · [safewatch-ai](https://github.com/nadeem1971/safewatch-ai)

License: MIT
