# System Planes and Stack Selection

Load this reference when mapping required system capabilities, comparing stacks, or deciding which layers are internal, external, optional, or unnecessary.

## Table of Contents

- Plane map
- Plane classification
- Surface versus durable state
- Selection sequence
- Organizational readiness and operational ceiling
- Candidate evidence model
- Scoring and sensitivity
- Shortlist contract
- Anti-lock-in and exit
- Freshness rules

## Plane Map

Classify each plane as `required`, `optional`, `external`, or `not_needed`:

| Plane | Responsibility |
|---|---|
| 1. Surface | CLI, IDE, chat, web UI, or operational control plane. |
| 2. Skill/procedure | Portable instructions and progressively loaded resources. |
| 3. Harness/SDK | Model loop, tools, context, permissions, session, and subagents. |
| 4. Orchestrator/durable runtime | State, transitions, retries, timers, checkpoint, and resume. |
| 5. Trigger | Cron, webhook, queue, event bus, file watcher, or channel gateway. |
| 6. Memory/knowledge | Working, conversation, episodic, semantic, and procedural memory. |
| 7. Execution | Host, worktree, container, microVM, browser, desktop, or managed sandbox. |
| 8. Trust | Identity, capabilities, secret broker, policy, budget, approval, egress, and kill switch. |
| 9. Observability/eval | Trace, metrics, replay, eval, audit, and incident response. |
| 10. Interoperability | Agent Skills, MCP, A2A, ACP, and host adapters. |

Do not install a plane because a diagram includes it. State why it is required and who operates it.

Use the seven object categories defined in [reference 01](01_doctrine_scope_and_necessity_triage.md) before comparing candidates. Same-level components are not automatically aggregators; apply the explicit aggregation role and merge controls in reference 03.

## Plane Classification

For every plane record:

```yaml
status: required | optional | external | not_needed
owner:
capabilities:
data_and_state:
trust_boundary:
interfaces:
failure_mode:
evidence:
exit_strategy:
```

An external plane still needs a contract and failure policy. A not-needed plane needs a reason so future scope changes can reopen it deliberately.

For each required or external plane also record proved capabilities, evidence
locators, unresolved gaps, organizational owner, and the resulting operational
ceiling. A diagram or vendor claim is not readiness evidence.

## Surface Versus Durable State

The surface may create, inspect, pause, or approve a run. It must not be the only custodian of critical state for a long-running product workflow. Durable state must survive IDE, CLI, browser, network, and model-session loss. Runtime state rules live in reference 05; the builder-relay exception lives in reference 10.

## Selection Sequence

1. Complete scope, Mode/AU/R, and plane map.
2. Inventory and reuse verified existing foundations before proposing another shell or platform.
3. Define required contracts before products.
4. Build a dated candidate catalog from primary sources and installed probes.
5. Compare objects within the same category or account for missing layers.
6. Produce at least three viable options when the decision is material.
7. Run sensitivity on important weights and assumptions.
8. Record decision, consequences, migration, and exit strategy in an ADR.
9. Verify capability on the pinned version before scaffold or deployment.

For report-producing systems, classify generation and governance separately even when one product implements both. Content synthesis, semantic validation, publication authority, rendering, and retention are different capabilities.

## Organizational Readiness and Operational Ceiling

Use this optional profile when the request includes organizational adoption,
migration, pilot, or release readiness. Do not activate it for a narrow technical
design that does not need organizational change.

Keep maturity domains separate:

- adoption and work redesign;
- architecture and contract completeness;
- supervision and human control;
- evaluation, operations, and release.

For each domain record `proved_capabilities`, evidence locators, gaps, owner,
authorized scope, prohibited scope, review date, expiry, and operational ceiling.
The weakest applicable hard gate bounds the envelope; an average maturity score
does not raise it. Readiness to build or pilot never implies production authority.
Default `production_authorized: false` until the separate release gate binds the
exact evidence and decision.

The readiness decision records the evidence package, hard gates, dissent,
conditions, human signers, expiry, authorized and prohibited scope, review date,
and the next release authority. Unresolved dissent remains visible; a signature
does not erase a failed hard gate.

For staged migration, freeze a representative real-task gold set before changing
the architecture. Progress only through evidence-backed levels such as:

- L0: governed context, ownership, baseline, and rollback;
- L1: governed quality, evaluation, and supervised pilot;
- L2: bounded operations with proven recovery and release controls.

Each level has entry evidence, exit criteria, rollback, and a step-back signal.
Do not begin with an autonomous reviewer before contracts, use transcripts as
memory, add parallelism without merge policy, let specialists own shared state, or
migrate without the frozen gold set. Calendar horizons such as 30/90/180 days may
be planning examples, never universal doctrine or evidence of completion.

## Candidate Evidence Model

The dated catalog records:

```yaml
id:
object_categories: []
layers: []
languages: []
capabilities: {}
durability:
hitl:
sandbox:
protocols: []
deployment:
license:
maturity:
official_sources: []
verified_at:
confidence:
contract_and_policy:
  credential_and_access_mode:
  DPA:
  processing_regions_and_data_residency:
  provider_log_retention:
  training_use:
  subscription_or_API_terms:
  permitted_harness_pairing:
  alternative_access_path:
```

Do not store editorial rankings, stars, model prices, or marketing claims as durable doctrine. `unknown` is a valid value.

## Scoring and Sensitivity

Weight only criteria tied to requirements. Candidate dimensions may include:

- explicit control and state;
- durability and recovery;
- HITL and risk fit;
- security, sandbox, identity, and tenancy;
- language and existing-stack fit;
- knowledge and retrieval fit;
- interoperability and portability;
- observability and eval;
- deployment and operations burden;
- developer experience and lock-in.

Show raw evidence, weights, score, uncertainty, and disqualifiers. Double or halve important weights to see whether the ranking changes. A sensitive result is a decision risk, not a reason to hide alternatives.

## Shortlist Contract

Return:

```yaml
requirements_snapshot:
plane_map:
options:
  - id:
    category:
    verified_capabilities: []
    gaps: []
    tradeoffs: []
    operational_cost:
    risks: []
    exit_strategy:
sensitivity: []
organizational_readiness:
authorized_scope:
prohibited_scope:
production_authorized: false
decision_expiry:
review_date:
decision:
why:
conditions_that_change_the_decision: []
verification_needed: []
```

Do not output an automatic winner when required evidence is missing.

## Anti-Lock-In and Exit

- keep procedure in Agent Skills and product policy outside provider prompts;
- access tools and data through typed interfaces or MCP where justified;
- use A2A only for real remote agent boundaries;
- keep state and artifacts in controlled storage;
- map model profiles instead of scattering model IDs;
- export traces and run artifacts in portable formats;
- version schemas and adapters;
- include workflow, skill, memory, integration, control-surface, identity, data,
  and observability dependencies in the lock-in analysis, not only the model;
- verify DPA, processing region and residency, provider retention, training-use,
  credential mode, subscription-versus-API terms, and the chosen harness pairing;
- reject proxy or credential workarounds that evade a provider contract;
- document how to replace each critical plane.

## Freshness Rules

Every volatile entry has a verifier date, source locator, confidence, and owner. Run Tech Watch quarterly or more often, after a major release, and always before a high-impact or vendor-critical decision. Installed capability beats memory and marketing. If a named product cannot be identified precisely, ask for the locator or mark it unverified.

Recheck contractual terms, credential modes, data handling, price, and capability
immediately before a vendor-critical decision. Keep dated cases and current vendor
facts in the evidence catalog; evergreen doctrine contains only the verification
obligation and stop rule.
