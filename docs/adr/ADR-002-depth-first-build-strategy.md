# ADR-002: Depth-First Build Strategy (Build Two Things World-Class, Document the Rest)

**Status:** Accepted · **Date:** Week 1

## Context
The full AEGIS architecture spans seven layers and ~12 modules (gateway, red teaming, agentic workflow, registry, secure RAG, AI-SPM discovery, model supply chain, vendor evaluation, compliance engine, IR, observability, portal). Available capacity is ~8 weeks at 10–12 hrs/week. Building all modules in that window yields ~60% completeness everywhere — a platform that demonstrates breadth but proves nothing.

## Decision
Split every module into exactly one of two states, with no middle ground:

- **BUILD (demo-video quality):** LLM Security Gateway; Red Team Harness with CI regression and before/after metrics; Agentic Governance Workflow with durable HITL; plus the minimal registry/portal required to run these end-to-end, and one secure-RAG demonstration (poisoned-document defense).
- **DOCUMENT (consulting-grade pattern):** Secure RAG (full), AI-SPM/shadow-AI discovery, model supply chain security, vendor evaluation framework, dashboards/drift/SIEM, full compliance engine. Each delivered as a pattern document (context / problem / solution / trade-offs) plus roadmap issues.

Enforcement rule: any BUILD item at ~60% at week's end is finished within the week or demoted to DOCUMENT. Nothing ships half-built.

## Rationale
1. **Proof beats scope.** The platform's claims (attack success reduction, cycle-time reduction, tamper-evidence) are only credible if measured on working software. Three deep artifacts with committed evidence outweigh twelve shallow ones.
2. **Half-built security features are anti-signals.** In a security platform specifically, a partially implemented control implies a false sense of protection — worse than an honestly documented gap.
3. **Sequencing is an architecture skill.** Deciding what *not* to build, and in what order value is realized, is the core of principal-level judgment. This ADR is the artifact of that judgment.
4. **Patterns are deliverables too.** In consulting contexts, a well-written reusable pattern with explicit trade-offs is a client-facing work product in its own right.

## Consequences
- (+) Every claim in the README is backed by a runnable demo or committed evidence.
- (+) The roadmap section transparently distinguishes built vs designed — no implied completeness.
- (−) Reviewers scanning for feature count may under-rate the project; mitigated by the README's built-vs-designed table and this ADR.
- (−) Some threat-model items carry accepted risks in v1 (see threat model §3); each has a compensating control and a documented production design.
