# Runtime, State, Bridges, Data, Security, and Reliability

Load this reference when the design persists runs, invokes tools, crosses process or network boundaries, handles untrusted input, or must survive retry, restart, and partial failure.

## Table of Contents

- State machine before prompts
- Canonical run state
- Runtime context policy and assembly
- Optional controlled session renewal profile
- Durable execution and recovery
- Deterministic triggers, liveness, and checkpoints
- Tool contract
- Agent-computer interface and effect lifecycle
- Bridge and carrier boundary
- Data and local-first operation
- Untrusted input and prompt injection
- Security control plane and capability binding
- Sandbox and execution isolation
- Identity, secrets, egress, and tenancy
- Contract bundle integrity
- Scaling and disaster recovery
- Continuity, release, recovery, and retirement
- Optional external recovery supervisor
- Single-home boundaries and required tests

## State Machine Before Prompts

Define before writing behavior prompts:

- states and terminal outcomes;
- events, transitions, and guards;
- persisted data and artifact references;
- side effects and idempotency keys;
- timers, deadlines, retry, and backoff;
- approvals and resume validation;
- cancellation, compensation, and rollback.

The prompt controls behavior inside a state. It is not the state store.

## Canonical Run State

Persist a typed record such as:

```yaml
run_id:
tenant_id:
request:
risk_class:
plan_version:
current_state:
artifacts: []
approvals: []
budgets:
versions:
audit:
```

Store large artifacts outside the transactional state record and retain IDs, hashes, media types, lineage, and locations. Every write and external side effect carries the run ID and an idempotency key. Approval is an immutable event, not a mutable boolean.

## Runtime Context Policy and Assembly

Treat context capacity as a governed runtime resource. Before a long-running or tool-using run, declare a `CONTEXT_POLICY` with:

- model or capability profile and measured capacity;
- immutable instructions, working state, external memory, and cold-store layers;
- parameterized soft and hard limits, plus output and tool-result reserves;
- maximum slice size, retention rules, and ordered retrieval priority;
- reset, compaction, truncation, and selective-compression policy;
- capacity preflight, overflow behavior, owner, and escalation.

Soft and hard limits are configuration, not universal doctrine. Measure them for the selected host and workload; do not hard-code example ratios. Abort before a model call when instructions, evidence, tool reserve, and output reserve cannot fit without violating the hard limit.

Build each call through a `CONTEXT_ASSEMBLY_CONTRACT` that binds the policy version, immutable snapshot, selected and excluded locators, working-state version, open loops, decisions, reviewer feedback, token estimate, and effective-view hash. Put stable reusable material before variable task material when the host supports caching, but never let cache behavior change authority or freshness.

Prefer the smallest high-signal context that supports the next safe transition. Use manifest-plus-slice for large artifacts and just-in-time retrieval instead of repeated full reloads. Recursive compaction is lossy and requires source locators plus an independent retention check.

A summary is derived navigation. It is never a canonical source, durable checkpoint, proof of completion, or authority to resume. Keep task status and unresolved work in typed state outside the summary, and verify them after every reset or compaction.

Record the choice between reset and compaction, its symptoms and trade-offs, and the model, harness, and policy versions tested. Re-evaluate the choice after a material model or harness change. Context-cost metrics belong to [reference 07](07_observability_evals_opex_and_learning.md); knowledge promotion and retrieval authority belong to [reference 02](02_knowledge_memory_retrieval_and_provenance.md); model mapping belongs to deployment configuration and [reference 11](11_system_planes_and_stack_selection.md).

## Optional Controlled Session Renewal Profile

The controlled session-renewal pattern is optional for a full context window, planned interruption, daily boundary, or restart that must preserve continuity without granting two sessions authority to write.

The `SESSION_RENEWAL_CONTRACT` declares:

```yaml
run_id:
predecessor_session:
successor_session:
reason:
owner:
continuity_bundle_version:
continuity_bundle_hash:
effective_view_hash:
checkpoint_id:
approval_state:
effect_state:
predecessor_lease:
successor_lease:
unknowns: []
next_safe_transition:
readback_evidence: []
```

Use the governed continuity bundle from [reference 02](02_knowledge_memory_retrieval_and_provenance.md). Park, expire, or revoke the predecessor writer before granting the successor lease. Prove one active lease and zero dual writes.

The successor first validates bundle version and hash, reconstructs the effective view, reads the checkpoint, reconciles approvals and possible effects, and demonstrates that no interval was silently lost. Missing, stale, incompatible, or contradictory authority, checkpoint, lease, or effect fields fail closed.

Treat observed slow sessions or manual renewals only as scoped evidence in [reference 08](08_case_patterns_and_antipatterns.md). They do not establish a universal renewal threshold or a performance claim.

## Durable Execution and Recovery

Distinguish:

| Failure | Response |
|---|---|
| Technical retry | Network, provider limit, timeout; retry with bounded backoff and jitter. |
| Semantic retry | Output fails schema or validation; request a constrained correction. |
| Agentic repair | Strategy is wrong; allow at most the declared repair budget. |
| Human escalation | Policy, confidence, authority, or budget cannot resolve safely. |

Persist before and after side effects. Use queue backpressure, per-tenant concurrency, lease/heartbeat, cancellation, dead-letter or compensation, step/workflow timeout, and circuit breakers. A process kept alive in memory is not durable execution.

Event and schedule triggers create deduplicated run IDs. Missed schedules use an explicit `skip`, `catch_up`, or `coalesce` policy. A read-only file watcher or channel gateway is a trigger plane; it is not the production state store.

## Deterministic Triggers, Liveness, and Checkpoints

Assign waiting, scheduling, leases, resume, and terminal-state ownership to deterministic software. An LLM may interpret a proved event in a bounded run; it must not be the durable watcher, clock, lease owner, or source of runtime truth. A persistent process is not persistent state.

Declare a `TRIGGER_DELIVERY_CONTRACT` with source, event or normalized due time, timezone, deduplication identity, missed-fire policy, maximum catch-up, dead-man check, evidence locator, and terminal delivery state. Verify the first scheduled execution against the intended local and UTC times. Select local or managed execution through data-residency, uptime, connector, and file-access requirements rather than convenience alone.

Declare a `RUN_OWNERSHIP_LIVENESS_CONTRACT` with owner, lease expiry, renewal rule, heartbeat age, progress locator, stale thresholds, recovery authority, and split-brain guard. A heartbeat proves liveness only; it does not prove progress, correctness, or authority.

Every durable workflow declares a `CHECKPOINT_FAMILY_DECLARATION`:

```yaml
family:
source_of_truth:
write_boundary:
monotonic_identity:
replay_rule:
compaction:
corruption_handling:
migration:
restore_test:
```

For a fresh-context or outer loop, keep the task ledger and checkpoint outside the model context, execute one bounded unit per iteration, validate it, then persist before the next iteration. Require both a verifiable goal and a ceiling on attempts, elapsed time, and budget. Selection of this topology remains in [reference 03](03_operating_modes_hats_and_orchestration.md).

For append-only carriers, use an atomic append primitive or a unique end-of-file anchor. Read back ID uniqueness, physical tail position, `MAX = LAST`, and recent-window monotonicity. A correct next number alone does not prove a correct append.

On resume, read from the durable checkpoint, identify any missed interval, consume multiple events in order, then rearm against the new physical tail. A tail, uniqueness, or monotonicity mismatch fails closed and must be repaired before reporting success.

Test the ambiguous crash point where an effect occurs before its checkpoint. Bind one intent to one effect with an idempotency key and request fingerprint, reopen the authoritative store, read external state, and reconcile before retry.

Use an `UNATTENDED_SAFETY_ENVELOPE` with maximum steps and attempts, deadline, spend and concurrency ceilings, kill switch, cooperative cancellation, poison path, terminal-state denominators, and recovery owner. Treat `stop`, `park`, `export`, and `resume_pending` as explicit, verifiable outcomes.

The generic trigger, append, checkpoint, and liveness substrate is single-homed here. The optional shared relay ledger and read-only watcher patterns remain single-homed in [reference 10](10_verifier_playbook.md); do not recreate their relay, acknowledgement, or verifier protocol in this reference.

## Tool Contract

Each tool declares:

```yaml
purpose:
input_schema:
output_schema:
bounded_result:
read_or_write:
risk_class:
allowed_targets: []
idempotency:
timeout_and_cancellation:
dry_run:
errors: []
retry_policy:
approval_policy:
provenance_and_audit_id:
```

Use one precise purpose per tool. Separate `draft_*` from `commit_*`. Prefer a narrow API tool over generic shell or network access. A registry must return typed errors instead of crashing the orchestration loop.

## Agent-Computer Interface and Effect Lifecycle

Design the agent-computer interface for stable choice and bounded observation, not maximum power. For each tool, state what it does, parameter enums and constraints, what it returns, when to use it, when not to use it, and at least one negative example. Normalize safe input variants inside the handler instead of making the model guess syntax.

Shape every result into action or command, exit or status code, principal error, affected artifacts, structured data, and a locator for the complete log. Truncate only after preserving the authoritative result and its hash. Validate preconditions before execution and postconditions through independent readback.

Classify each action as `read`, `draft`, `write_reversible`, `write_irreversible`, or `privileged`; minimize its blast radius and declare rollback or compensation behavior.

Keep five distinct gates and their evidence:

```text
discovered
-> callable
-> authorized for this action and target
-> executed
-> independently read back
```

No earlier gate implies a later one. A reachable tool may remain blocked. Bind `risk_per_action`, `authorized_rmax`, `reachable_but_blocked`, inherited risk, disqualifiers, and approval owner to the tool call without redefining the R scale or approval authority in [reference 04](04_governance_autonomy_risk_approval_and_rollback.md).

For high-impact tools, use `DRAFT_ONLY_HIGH_IMPACT`: produce a preview and diff, bind budget and target, obtain approval for the exact digest, perform an explicit commit, then return a commit receipt and readback. Decompose universal write tools into narrow read, draft, approval-request, commit, and verify operations.

Use an `EFFECT_AWARE_RETRY_CONTRACT` with operation semantics, effect boundary, idempotency-key scope and retention, request fingerprint, retryable failures, shared retry budget, readback query, uncertain state, and reconciliation owner. Never retry merely because a response was missing; first determine whether the effect may already exist.

`TOOL_EVAL_MINIMUM` declares tasks, expected outcomes, allowed valid paths, tool-use assertions, and token or cost fields. Evaluation corpus, scoring, and independent verdicts remain in [reference 07](07_observability_evals_opex_and_learning.md) and [reference 10](10_verifier_playbook.md).

## Bridge and Carrier Boundary

Keep one semantic core and thin carrier shims. The bridge owns identity, request/response schema, timeouts, capability negotiation, and error normalization. It does not own agent doctrine.

Verify:

- transport and server identity are pinned;
- carrier-specific output is normalized at every read boundary;
- HTTP/CLI/MCP adapters produce parity for the same contract;
- `executed` is not accepted without independent state or artifact readback;
- partial failure and reconnect do not duplicate side effects;
- doctor checks exercise the real route, not only process liveness.

Missing carrier, locale, parser, or capability mappings fail explicitly with an actionable error. Do not hide drift behind a silent fallback.

This reference owns carrier-neutral runtime semantics, identity, effects, and recovery. Host packaging, adapter metadata, protocol parity, installation, and migration remain in [reference 09](09_interoperability_and_host_portability.md); dated capability selection remains in [reference 11](11_system_planes_and_stack_selection.md).

## Data and Local-First Operation

For portable local-first systems:

- use one authoritative writable data root;
- enable transactional journaling appropriate to the database;
- keep single-writer semantics unless multi-writer behavior is proven;
- back up through database-aware APIs, not blind copies of live files;
- test restore, lock handling, stale sidecars, and abrupt termination;
- detect duplicate instances with an explicit fingerprint or lease;
- separate configuration, state, cache, artifacts, and canonical sources.

Inventory and reuse verified foundations before building another control shell, bridge, or storage layer.

Cloud-sync folders are replication surfaces, not concurrency control. Validate sync conflict, file lock, restore, and path portability on the actual environment.

## Untrusted Input and Prompt Injection

Treat web pages, email, tickets, documents, repository content, tool output, and inter-agent messages as untrusted data.

Classify the authorized workflow, not the hostile action contained in untrusted data. As defined canonically in [reference 01](01_doctrine_scope_and_necessity_triage.md), one fixed public read-only fetch plus schema extraction remains a deterministic AU1/R0 workflow; delimit and deny injected instructions separately. Escalate only when the authorized workflow itself requires a judgment loop, write, sensitive target, broader privilege, or higher blast radius.

- delimit data from instructions;
- never propagate retrieved text into the system prompt automatically;
- allowlist tools, operations, paths, and destinations;
- scan imported skills, plugins, MCP servers, and archives;
- require approval for side effects derived from external content;
- log the chain `source -> decision -> action`;
- test poisoning, hidden instructions, partial data, and oversized payloads.

## Security Control Plane and Capability Binding

Separate the instruction layer from the control plane. A prompt, message, tool description, signature, matching hash, or authenticated carrier may prove content or origin; none grants authority by itself.

Threat-model authorization failure, confused deputy, prompt injection, tool poisoning, supply-chain compromise, and data exfiltration. Map untrusted sources to reachable sinks and assume a filter may be bypassed. Treat approval interfaces and reviewer attention as attack surfaces that require exact target, preview, and consequence binding.

Represent executable authority with a `CAPABILITY_ENVELOPE`:

```yaml
binding_id:
issuer:
holder:
principal:
workload:
tenant:
session:
audience:
action:
target:
constraints:
expires_at:
revocation:
evidence_route:
```

Record a `DELEGATION_CHAIN` from principal through delegator and workload to tenant, session, audience, action, and target. Delegation may narrow authority but cannot amplify privilege. Reject mismatched audience, tenant, scope, target, expiry, policy version, or derivation.

Evaluate every tool call through a deterministic policy broker against its capability envelope and current state. Default network services to no listener or loopback; a public bind is an explicit governed capability.

Use a broker for secrets and emit a `SECRET_BROKER_RECEIPT` that binds lifetime, audience, sender, target, action, and revocation. Give the model a temporary capability handle, never plaintext secret material.

Define an `EGRESS_POLICY` with canonical destinations, DNS and IP resolution, redirect rules, denied address ranges, allowed methods, data classes, rate and size budgets, and a time-of-use recheck. Re-resolve and revalidate the final destination immediately before the request and read back the destination and result.

Bind execution to an `APPROVAL_BINDING` containing the preview digest, choices, target, constraints, expiry, invalidation reasons, and commit receipt. This is runtime enforcement only; risk classification, consent, denial, and approval authority remain single-homed in [reference 04](04_governance_autonomy_risk_approval_and_rollback.md).

Maintain a `TOOL_REGISTRY_MANIFEST` with provenance, version pin, schema fingerprint, permissions, permission diff, trust level, lifecycle, disable or revocation path, and checkpoint-compatibility gate. Review third-party code and requested permissions, quarantine it in an isolated project before broader use, and never treat popularity or a vendor label as security evidence.

For channel gateways, use a dedicated workload identity, hold the bot token as a secret, allowlist authorized senders, treat every message as untrusted input, and default to one active gateway writer per channel and profile. Multiple writers require a proven coordination contract.

Treat every write-capable MCP server, plugin, skill, or carrier according to its actions, targets, data, and effects. Keep protocol packaging and vendor-specific adoption guidance in [reference 09](09_interoperability_and_host_portability.md), and keep volatile catalog facts in reference 11.

## Sandbox and Execution Isolation

| Level | Use |
|---|---|
| S0 | No sandbox; only trusted, read-only work with user-level privileges. |
| S1 | Rootless standard container with dropped capabilities and bounded resources. |
| S2 | Hardened container or isolated runtime for untrusted code and stronger tenant boundaries. |
| S3 | Ephemeral microVM for high-risk code, network, or brokered secret access. |
| S4 | Managed sandbox after verifying region, retention, egress, image provenance, and SLA. |

Minimum hardening: non-root identity, read-only root, minimal workspace mount, CPU/RAM/PID/disk/time limits, no container socket, denied network by default, controlled DNS, signed image and SBOM, cleanup after crash, path-traversal and archive-bomb defense, and command/file/network audit.

Sandbox strength and action authority are orthogonal. A strong sandbox does not authorize an effect, and approval does not make an unsafe runtime safe. Bind a `SANDBOX_PROFILE` to the action and test negative paths for privilege escalation, metadata endpoints, localhost services, mounts, egress, persistence, and tenant crossover.

## Identity, Secrets, Egress, and Tenancy

The model should receive a temporary capability, not the secret itself. Prefer workload identity, short-lived audience-bound tokens, policy-gated secret broker, scoped credentials, rotation, redaction, revocation, and kill switch. Never place secrets in skill files, prompts, memory, logs, or artifacts.

Classify egress as public read, authorized internal SaaS, external write, or unknown. Unknown is denied. Route network access through specific tools or an allowlisted proxy with metadata logging and rate/size limits.

Enforce tenant isolation in keys, credentials, workflow namespaces, rows or indexes, artifact prefixes, sandboxes, caches, traces, and budgets. A prompt instruction is not a tenant boundary.

## Contract Bundle Integrity

Treat task and responsibility contracts as machine-checkable logical views composed from the existing requirements, hat, run, risk, tool, acceptance, and provenance artifacts. Do not create a second standalone contract family merely to repeat those fields.

The task view freezes identity, owner, goal, constraints, non-goals, format, authoritative inputs, Definition of Done, budget, stops, typed errors, and required evidence. The responsibility view binds each object to producer, verifier, approver, operator, authority, separation rule, escalation, expiry, and succession.

Resolve all contract IDs and versions as one graph before execution or resume. Fail on missing references, illegal cycles, or inconsistent authority, effects, risk, states, budgets, errors, Definition of Done, receiver, and next authority. Individually valid files do not prove a coherent bundle.

Keep five completion proofs distinct:

1. the task criteria are satisfied;
2. the output is structurally and semantically valid;
3. the artifact is packaged and ready for its declared receiver;
4. the run reached a valid terminal state;
5. the real-world outcome is independently verified where applicable.

Never collapse these levels into a single `done`.

A typed error occurrence records code, phase, observable cause, retryability, whether an effect may already exist, safe state, owner, next action, and evidence locator. Keep it consistent with the tool result, run transition, retry or compensation decision, and incident trace.

Every receiver declares acceptance and rejection criteria, inherited risk, next authority, acknowledgement state, and evidence of rejection. Delivery does not transfer authority or erase risk.

Extend checkpoint records with a compatibility matrix, migration proof, invalidation reason, authorizer, original-record link, and no-duplicate fault test. An intact but incompatible checkpoint must not be resumed by inventing a transition.

## Scaling and Disaster Recovery

Scale model calls, external tools, and sandboxes independently. Use queue depth and latency, not CPU alone. Add bulkheads, provider limits, cancellation, and runaway budgets.

Recovery requires point-in-time state backup, versioned artifact storage, replayable events or queue strategy, rebuildable indexes, run manifests, tested restore, and an explicit policy for in-flight runs. Test restart during approval, tool call, artifact write, and commit; prove that no side effect is duplicated.

## Continuity, Release, Recovery, and Retirement

Build a `CONTINUITY_DOSSIER` from business-impact analysis through tested restore. Include dependencies, fallback paths, RTO, RPO, in-flight policy, backup scope and independent failure domains, restore evidence, degraded mode, owner, exercise cadence, and changes that invalidate the proof. Set cadence from impact and change rate; do not promote a source-specific example cadence into a universal rule.

Keep credentials and recovery authority outside the failed system. Maintain a plain-language restart path and prove rebuild-from-clean, credential rotation, state restore, artifact restore, and queue or event reconciliation.

Use an `INCIDENT_AUTHORITY_MATRIX` and `INCIDENT_COMMUNICATION_PLAN` to bind severity to stop and resume powers, delegates, evidence custody, legal or privacy routing, recipient class, verified facts, deadline, approval, and delivery readback. Reference 04 remains authoritative for who may approve, deny, compensate, or resume.

Separate three recovery lanes:

| Lane | Purpose | Required proof |
|---|---|---|
| Technical rollback | Restore code, configuration, schema, or state. | Exact version and readback. |
| Effect compensation | Reconcile, reverse, notify, or otherwise address an external effect. | Effect evidence and authorized outcome. |
| Autonomy or organizational step-down | Reduce tools, privilege, automation, or operating mode. | New authority envelope and safe terminal state. |

Do not promise reversibility when an effect requires reconciliation, third-party action, or notification.

A release and operations contract declares denominators, owner, environment, effect mode, `risk_designed`, `risk_exercised`, live lanes, in-flight policy, and proof level. Require separate design, controlled pilot, and operational-admission gates; aggregate scores cannot bypass a hard gate.

A runtime canary contract binds frozen thresholds, abort behavior, in-flight policy, degraded mode, and `INDETERMINATE`. Emit the signals needed to distinguish local regression, external dependency failure, and provider degradation. Metric definitions, SLI/SLO evaluation, cost analysis, and canary verdicts remain in [reference 07](07_observability_evals_opex_and_learning.md).

Use provider-side hard caps where available and a deterministic detector for repeated or degenerate output outside the model. Emit verified-value, authority-conformance, unknown-outcome, and cost-per-outcome fields for evaluation in reference 07.

Monitor the monitors through a deterministic heartbeat, expected-report window, missed-report alarm, and injected fire drill. A monitor cannot attest to its own health merely by remaining alive. Keep incident and case evidence in [reference 08](08_case_patterns_and_antipatterns.md).

Inventory orphan files, services, schedules, monitors, checkpoints, and credentials during continuity exercises, and retire them through the governed retirement path instead of accumulating runtime cruft.

At a material model or harness upgrade, inventory each component and the assumption it encodes, test removal or simplification in a controlled environment, and remove unnecessary complexity. Selection and volatile model claims remain in reference 11; evaluation evidence remains in reference 07.

Retire a runtime through freeze, drain, credential and capability revocation, removal, tombstone, and readback of every known resurrection path. Prove that schedules, queues, caches, checkpoints, adapters, and installers cannot silently reactivate the retired version.

## Optional External Recovery Supervisor

The external recovery-supervisor pattern is optional for chat, session, carrier, provider, or external-service failure that leaves progress or effect state uncertain. It supplements deterministic recovery; it is not an autonomous retry loop.

The `EXTERNAL_RECOVERY_SUPERVISOR_CONTRACT` declares:

```yaml
incident_id:
run_id:
session_id:
trigger:
owner:
checkpoint_id:
effective_view_hash:
operation:
request_fingerprint:
idempotency_key:
lease_state:
effect_state:
external_state_evidence: []
unknowns: []
recovery_choice:
required_approval:
successor_lease:
terminal_state:
```

First block new writes, preserve the interrupted attempt, read checkpoint, lease, request, and effect evidence, then inspect the actual external state through approved read-only probes. Do not infer failure from a missing response and do not infer success from process liveness.

Choose only among evidence-bound resume, bounded retry, authorized failover, park, or human escalation. Never blind-retry or fail over automatically when an effect may exist. Grant a successor lease only after reconciling the prior writer and proving one active lease.

Research on external feasibility and alternatives remains in reference 02; evaluation and provider-health verdicts remain in reference 07. Observed chat errors, congestion, or manual recovery events remain scoped evidence in reference 08 and do not become universal performance claims.

## Single-Home Boundaries and Required Tests

Keep these ownership boundaries explicit:

| Concern | This reference owns | Canonical neighbor |
|---|---|---|
| Context and session | Runtime capacity, assembly, checkpoint, renewal, and effect continuity. | Knowledge authority and continuity bundle: reference 02; cost metrics: reference 07. |
| Loops and delegation | Trigger, lease, checkpoint, cancellation, and effect semantics. | Topology and role selection: reference 03. |
| Risk and approval | Machine enforcement, capability, preview digest, and receipt. | Classification, consent, denial, and authority: reference 04. |
| Carriers and hosts | Carrier-neutral identity, errors, runtime security, and recovery. | Adapter packaging, host parity, installation, and migration: reference 09. |
| Relay and sentinel | Generic append, checkpoint, heartbeat, and liveness substrate. | Optional modules C02/C04 and verifier protocol: reference 10. |
| Evidence and operations | Runtime events, receipts, and evidence locators. | Reports: reference 06; metrics and eval: reference 07; cases: reference 08. |
| Stack and model facts | Version references used by a run. | Dated catalog, selection, and provider mapping: reference 11. |

Apply the scope and AU/R decision from [reference 01](01_doctrine_scope_and_necessity_triage.md); this reference does not reclassify the authorized workflow.

Required fixture bindings:

- `CL-01`: `F2-CL-01-POS`, `F2-CL-01-NEG`;
- `CL-03`: `F2-CL-03-POS`, `F2-CL-03-NEG`, `F2-CL-03-MALFORMED`, `F2-CL-03-RECOVERY`;
- `CL-09`: `F2-CL-09-POS`, `F2-CL-09-NEG`, `F2-CL-09-MALFORMED`, `F2-CL-09-RECOVERY`;
- `CL-10`: `F2-CL-10-POS`, `F2-CL-10-NEG`, `F2-CL-10-MALFORMED`, `F2-CL-10-RECOVERY`;
- `CL-12`: `F2-CL-12-POS`, `F2-CL-12-NEG`, `F2-CL-12-MALFORMED`, `F2-CL-12-RECOVERY`;
- `CL-19`: `F2-CL-19-POS`, `F2-CL-19-NEG`, `F2-CL-19-MALFORMED`, `F2-CL-19-RECOVERY`;
- Controlled session renewal and external recovery supervision: bind each profile to E1, E2, E3, and E4.

Test context overflow and summary-as-checkpoint rejection; renewal with one active lease; missing and contradictory capability fields; tenant, audience, target, expiry, SSRF, redirect, and approval-TOCTOU failures; missed triggers and split brain; append tail mismatch; effect-before-checkpoint; stale or incompatible checkpoints; contract graph gaps and cycles; effect-aware retry; restore, degraded mode, retirement, and recovery-supervisor paths.

Positive fixtures require all authority, state, evidence, owner, and terminal fields. Negative and malformed fixtures fail closed with zero effect. Recovery fixtures preserve the prior attempt, read back real state, expose unknowns, and prohibit duplicate effects.
