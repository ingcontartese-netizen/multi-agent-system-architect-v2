# Knowledge, Memory, Retrieval, and Provenance

Load this reference when the system must ingest sources, preserve meaning, maintain memory, retrieve evidence, or prove what informed an output.

## Table of Contents

- Knowledge layers and authority
- Controlled knowledge lifecycle
- Lossless distillation and fusion
- Seven-field provenance
- Memory types and retention
- Retrieval selection and pipeline
- Research protocol
- Context engineering
- Required tests

## Knowledge Layers and Authority

Keep four concerns distinct:

| Layer | Purpose |
|---|---|
| Canonical source | Human-governed authority with version, owner, and change policy. |
| Working bundle | Task-specific selection with explicit source locators. |
| Archive | Superseded history preserved for audit, not silently reactivated. |
| Runtime knowledge | Material actually available to the model or retrieval system. |

An attached, well-structured knowledge pack may outperform a retrieval stack for a bounded task. Add indexing only when scale, freshness, access control, or repeated lookup justifies it.

Application guides cite canonical values by locator and version; they do not reprint pinned values that can drift independently.

## Controlled Knowledge Lifecycle

Use explicit states:

```text
raw -> candidate -> reviewed -> canonical -> deprecated
```

Never promote automatically because the model used a source successfully once. Record owner, source, timestamp, version or hash, tenant, confidence, expiry, and supersession link. Deprecation removes active authority but preserves history.

## Lossless Distillation and Fusion

Do not equate concatenation with preservation. A governed fusion needs:

1. immutable snapshots and a per-file manifest;
2. authority order and scope boundaries;
3. section/block inventory before rewriting;
4. destination map with one semantic home per mechanism;
5. conflict table distinguishing duplicate, complement, and contradiction;
6. content-retention matrix with explicit archive decisions;
7. alternating source-to-output and output-to-source passes;
8. independent readback and marker checks.

Preserve structured payload semantics. A YAML or JSON fence that parses but loses fields, order-dependent meaning, or nested content is a failed transformation.

## Seven-Field Provenance: the Cuneo Contract

For each substantial decision or artifact, record:

1. files or sources actually read;
2. version, hash, or access date;
3. sections consulted;
4. received material not used;
5. facts extracted;
6. synthesis or inference added by the model;
7. conflicts, gaps, and limits.

This record proves inputs and transformations without storing private chain-of-thought. A claim may not exceed its evidence level.

## Memory Types and Retention

Separate:

| Type | Content | Persistence rule |
|---|---|---|
| Working state | Typed data for the current run | Durable for the run; authoritative for transitions. |
| Conversation history | Messages needed for dialogue | Compact and expire by policy. |
| Episodic memory | Prior decisions and outcomes | Store only verified summaries with lineage. |
| Semantic memory | Facts and indexed knowledge | Source, version, timestamp, tenant, ACL, freshness, correction, and delete required. |
| Procedural memory | Skills, policies, and playbooks | Versioned and governed like code. |

Do not save every message permanently. Support correction, deletion, expiry, tenant isolation, and rebuild. Verify deletion from source, index, cache, and assembled context.

## Retrieval Selection and Pipeline

Choose the lightest strategy that passes retrieval evals:

| Need | Strategy |
|---|---|
| Small bounded source | Direct load or structured lookup. |
| Exact terms, IDs, or code | Lexical or structured search. |
| Paraphrase and conceptual similarity | Semantic retrieval. |
| High recall plus precision | Hybrid retrieval and reranking. |
| Ambiguous multi-hop investigation | Bounded agentic retrieval with coverage log. |

Governed pipeline:

```text
source governance
-> parse and semantic segmentation
-> metadata, tenant, ACL, version, hash, expiry
-> strategy and query transformation
-> retrieve and optional rerank
-> context assembly with source locators
-> generation
-> retrieval, faithfulness, citation, latency, and cost eval
-> correction/delete/rebuild feedback
```

Metadata and lineage must survive chunking and indexing. Apply ACL pre-filtering before retrieval. Test stale sources, poisoning, malicious instructions, missing metadata, over-retrieval, and ungrounded synthesis.

## Research Protocol

A serious research workflow must:

1. decompose the question into answerable sub-questions;
2. prefer primary sources for technical claims;
3. deduplicate and assess freshness and reliability;
4. capture evidence with stable locators or snapshots;
5. seek counter-evidence;
6. separate facts, inferences, and uncertainty;
7. produce verifiable citations and a coverage log;
8. let the human change scope or reject source classes.

Browser or search output follows the untrusted-input controls in [reference 05](05_runtime_state_bridge_data_security_and_reliability.md). Prefer APIs, deterministic DOM tools, and snapshots over visual automation when possible.

## Context Engineering

- Follow the direct router in `SKILL.md` and the packaging boundary in reference 09; load detailed resources only when needed.
- Pass artifact IDs and source locators instead of complete transcripts.
- Compact after milestones while preserving decisions, constraints, open work, and test results.
- Keep secrets outside prompts and memory; use capability handles.
- Make the assembled context reproducible for eval and incident review.

## Memory and Knowledge Governance Contracts

Treat memory as a set of governed planes, never as one undifferentiated blob. Before enabling durable memory, compiled knowledge, or retrieval, declare a `MEMORY_POLICY` with owner, purpose, scope, tenant, ACL, admitted memory kinds, write authority, promotion rule, retention, expiry, correction, deletion, rebuild, supersession, checkpoint, and escalation.

Use this six-kind design crosswalk:

| Kind | What it holds | Typical home | Governance |
|---|---|---|---|
| Instruction | Active constraints, policies, and task rules | Versioned skill or policy bundle | Human-governed release and rollback. |
| Working | The minimum state needed for the next safe transition | Context window or typed run state | Run-scoped, compacted at checkpoints. |
| Episodic | Verified decisions and outcomes from prior runs | Append-only journal or governed store | Lineage, expiry, correction, and tenant isolation. |
| Semantic | Curated facts and relationships | Knowledge bundle, wiki, or retrieval store | Source, version, freshness, ACL, and delete propagation. |
| Procedural | Reusable methods and playbooks | Versioned files or executable contracts | Reviewed and tested like code. |
| Evidentiary | Manifests, receipts, proofs, and verifier results | Immutable artifacts | Retained for audit; never treated as a cognitive fact merely because it exists. |

This grid is not declared equivalent to cognitive taxonomies that distinguish sensory, working, episodic, semantic, and procedural memory. Sensory input is transient intake; instruction and evidentiary memory are governance extensions. Publish a many-to-many crosswalk whenever another taxonomy is used, and preserve disagreements instead of forcing a one-to-one mapping.

Apply the allocation rule:

```text
context = needed for the next safe step
memory  = must survive the task
artifact = must be independently inspected or verified
```

Select the lightest knowledge mechanism that passes its eval:

| Situation | Preferred mechanism |
|---|---|
| Small, bounded, stable source set | Direct load or curated knowledge bundle. |
| Stable corpus reused frequently with important relationships | Compiled, interlinked Markdown knowledge. |
| Human-readable local memory with moderate scale | File-first store plus lexical or hybrid local search. |
| Large, volatile, access-controlled, or long-tail corpus | Governed retrieval with an external index. |
| Mixed stable core and volatile tail | Always-loaded curated core plus retrieval on demand. |

Run `KNOWLEDGE_PACK_VS_RAG` before adding an index. Record corpus scale, freshness, ACL, repeated-use rate, relationship density, curation cost, deletion/rebuild needs, multi-user needs, and operational burden. A local SQLite, lexical, or vector index is still lightweight infrastructure; it is not “zero infrastructure.” Search first, then inject only the bounded evidence needed by the task.

Diagnose “RAG where a wiki was needed” when the same stable facts are retrieved repeatedly, relationships are destroyed by chunking, knowledge is fragmented into silos, the index creates avoidable lock-in, or humans cannot curate the effective view. Preserve raw sources as immutable evidence, compile only reviewed material, maintain interlinks and naming conventions, and keep lineage from every compiled page to its sources.

Use these lifecycle contracts:

- `KNOWLEDGE_PROMOTION_CARD`: source/version/locator, facts, synthesis, conflicts, limits, owner, approver, current state, and supersession. Runtime authority excludes `raw`, `candidate`, and `deprecated`.
- `DISTILLATION_ACCEPTANCE_PACK`: source-to-output and output-to-source maps, explicit denominators, semantic retention checks, independent verifier, and separate findings for formatting loss versus meaning loss.
- `KNOWLEDGE_RELEASE_MANIFEST`: complete active set, addendum chain, `supersedes`, effective-view proof, recorded time, effective time, and consumer compatibility.
- `MEMORY_WRITE_GATE`: purpose, class, legal or policy basis, minimization, namespace, authority, payload hash, expiry, conflict rule, delete path, readback evidence, and correction link.
- `RETRIEVAL_PROMOTION_CONTRACT`: versioned dataset, baseline, positive and negative denominators, ACL/freshness prefilter, threshold, latency, cost, non-claims, and the decision `promote | revise | reject`.
- `DELETION_PROPAGATION_RECEIPT`: object, source base, scope, targets, result, timestamp, exceptions, expiry, and verifier; rebuild must prove that deleted or superseded material cannot resurrect.

A content-curation score may auto-approve only low-risk material after a non-compensable hard gate defined by [reference 04](04_governance_autonomy_risk_approval_and_rollback.md). Missing provenance, policy conflict, disallowed source class, uncertain rights, failed ACL, or high-impact claims route to human review regardless of aggregate score.

## Optional Knowledge Well and Continuity Profile

The knowledge-well continuity pattern is optional for long-running work that benefits from a human-readable knowledge well and explicit continuity. Activate it only after necessity triage and name a knowledge custodian.

The profile has four logical contracts, which may be grouped into three or more physical files:

1. a versioned knowledge well with canonical, candidate, and superseded layers plus a consultation map at the entry point;
2. a source map that indexes received material, locators, hashes, reading status, admitted claims, exclusions, and conflicts;
3. an append-only activity journal with decisions, outcomes, open unknowns, and evidence locators;
4. a continuity handoff with the last verified checkpoint, effective-view hash, approval/effect state, next safe transition, risks, and correction or deletion links.

The handoff carries typed artifacts and locators, not a full transcript. A resumed session first verifies bundle version and hash, reconstructs the effective view, reads the last checkpoint, and demonstrates continuity before it can write. Knowledge-side continuity ends at those proofs; runtime lease, effect reconciliation, session renewal, and `STATE_UNCERTAIN` remain owned by [reference 05](05_runtime_state_bridge_data_security_and_reliability.md).

The profile preserves the distinctions between instruction, working, episodic, semantic, procedural, and evidentiary memory. It never treats the journal as canonical knowledge, the source map as approval, or a successful retrieval as promotion.

Public behavior:

- `POS`: all required fields and bindings are valid, the effective view is reproducible, and no unapproved effect occurs.
- `NEG`: the profile declines activation or fails closed with a structured reason.
- `MALFORMED`: missing or contradictory authority, version, locator, checkpoint, or effect fields are enumerated and produce no effect.
- `RECOVERY`: the prior attempt is preserved, readback and reconciliation occur before retry, and duplicate effects are prohibited.

## Provenance Manifest and Claim Ledger

Every governed knowledge release carries a `PROVENANCE_MANIFEST`. It binds artifact, run, version, owner, tenant, and output locators to:

- every source actually read, with stable locator, hash or version, access date, and consulted sections;
- received material not used, together with the exclusion reason;
- claim IDs and the facts extracted for each claim;
- synthesis, inference, or recommendation added by the system;
- the exact output section influenced by each source and claim;
- source class, evidence level, freshness, expiry, conflicts, gaps, limits, and supersession.

The manifest is bidirectional: every substantial output claim resolves to admitted evidence, and every admitted source resolves to the claims or sections it influenced. A source candidate log, release manifest, or list of links is not a substitute for this mapping.

If official sources disagree, the claim ledger retains both records with version, date, role, scope, and effective interval. The output remains `VERIFY` or unknown until the declared authority resolves it; no merge may erase the disagreement. Every live claim names an owner, next review, expiry, and review trigger.

## Research Authority and Dynamic Claim Gates

Measure before classifying. `SOURCE_MEASURE_FIRST` records bytes, tokens where available, file count, duplicates, parseability, language, and whether each source was read as text, inspected visually, or only enumerated. User estimates and line counts are planning hints, not evidence of workload.

Use a `SOURCE_CANDIDATE_LOG` with source class, authority, version or access date, freshness, supported claims, prohibited uses, unresolved questions, and promotion state:

```text
inspiration_only
-> secondary_unverified
-> primary_verified
-> project_evidence
-> human_baptized
```

The sequence is not automatic. A secondary source may nominate a claim, but promotion requires the evidence class appropriate to the claim. Human baptism records authority and scope; it does not make a false or stale factual claim true.

For catalogs and market maps, declare the universe, categories, inclusion and exclusion criteria, verification date, primary sources, retired or absorbed entries, unresolved entries, and refresh policy. State “complete relative to the declared universe,” never “complete in absolute terms.”

Every dynamic claim uses a claim ledger with:

- `claim_id`, exact claim text, claim type, product or subject scope, and output locator;
- source role, URL or stable locator, version, observed date, effective date, and access method;
- `product_claim_status`: `official-current | official-preview | third-party | unverified | rejected`;
- liveness, freshness, and local-proof results as three separate gates;
- maturity for the exact child surface, never inherited from a parent brand or adjacent feature;
- clock, owner, `next_review`, expiry, and review trigger;
- contestation risk, confidence, conflicts, non-claims, and cutoff status.

Link QA verifies scheme, allowed domain, redirects, final destination, final 2xx status where HTTP applies, language variants, and access date. A reachable page proves liveness only. It does not prove that ownership, acquisition, rename, availability, lifecycle, maturity, or end-of-life content is current.

High-impact ownership and lifecycle claims require an independent or regulatory source in addition to the vendor page. If official sources conflict, preserve each record with date, version, role, region, account scope, and effective interval; mark the claim `VERIFY`, reduce its evidence level, or leave it unknown. Never resolve an official-source conflict silently.

Use proof granularity: a source supports only the exact claim and scope it actually establishes. Separate facts, inference, recommendation, availability, quality, maturity, and finality. “Current” does not mean final, immutable, generally available, or high quality.

`RESEARCH_COVERAGE` reports sources received, measured, read, admitted, rejected, or unresolved; total claims, verified claims, rejected claims, gaps, refresh dates, and the declared universe. Research remains a candidate-generation lane until its claims pass these gates.

## Optional Network Investigation Program

For a high-value or contested question, the owner may activate a bounded network-investigation program. It declares sub-questions, admitted source classes, freshness window, counter-evidence search, time and cost budget, coverage target, stopping rule, and verifier. The output is an evidence pack and claim ledger, not automatic canonical memory.

This optional program may support later evaluation and authoring, but it does not import runtime recovery, supervisor behavior, or host failover into this reference. Those mechanisms remain in their dedicated runtime and evaluation homes.

## Required Tests

- source-to-output and output-to-source retention;
- malformed but parseable structured payloads;
- conflict and supersession handling;
- ACL and tenant isolation;
- correction, deletion, cache purge, and index rebuild;
- stale source and freshness behavior;
- prompt injection and data poisoning;
- citation and claim support;
- direct-load baseline versus retrieval complexity.
