# Operating Modes, Hats, and Orchestration

Load this reference after necessity triage when assigning cognitive roles, process boundaries, planning levels, coordination, and artifact handoffs.

## Table of Contents

- Hats before processes
- Hat contract
- When to separate a process
- Portable roles
- Planning levels
- Coordination patterns
- Hybrid lifecycle
- Artifact handoff
- Aggregation discipline
- Concurrency and loop limits
- Model profiles

## Hats Before Processes

A hat is a bounded cognitive contract applied to one task. One capable model may wear several hats sequentially. A separate agent is justified only when isolation adds a measurable benefit or required boundary.

Do not turn every discipline into a long-lived process. Start with one worker and explicit rubrics; split only after the necessity gate proves distinct tools, permissions, context, models, success criteria, ownership, trust, or useful parallelism.

## Hat Contract

Each hat declares:

```yaml
hat_id:
purpose:
inputs:
knowledge_scope:
allowed_tools: []
forbidden_actions: []
output_schema:
success_checks: []
risk_class:
budget:
stop_conditions: []
escalation:
```

The orchestrator passes the minimum context and receives a typed artifact, not an unrestricted transcript.

## When to Separate a Process

Apply the six canonical separation criteria in [reference 01](01_doctrine_scope_and_necessity_triage.md). This reference maps an already justified separation to roles and coordination; it does not introduce a second criteria list. If separation fails that gate, collapse the roles into hats.

## Portable Roles

The default role library is:

| Role | Owns | Must not silently own |
|---|---|---|
| Spec-writer | Requirements, scope, executable done criteria | Implementation approval. |
| Planner | Milestones, dependencies, risks, and evidence plan | Production side effects. |
| Implementer | Scoped changes and local tests | Final verification of own work. |
| Verifier | Independent checks and defect report | Rewriting acceptance criteria after seeing output. |
| Reviewer | Cross-cutting quality, safety, and maintainability | Hidden product decisions. |
| Release-ops | Packaging, rollout, readback, and rollback | Canonical policy changes. |

These are contracts first. Map them to host subagents only when separation is justified.

## Planning Levels

| Level | Horizon | Persistence |
|---|---|---|
| Micro-plan | Next one to three tool calls | Usually ephemeral. |
| Task plan | Milestones, artifacts, risks, tests, and stop criteria | Human-reviewable. |
| Execution graph | Typed states, transitions, timers, and recovery | Durable. |

Re-plan only after new evidence, failure, or scope change. A long narrative list is not an execution graph.

Build order follows the dependency graph and verified interfaces, not the visual organigram. Persist consultation choices and routing constraints as state when later transitions depend on them.

For persistent or high-impact work, define states and transitions through [reference 05](05_runtime_state_bridge_data_security_and_reliability.md) before writing behavior prompts.

## Coordination Patterns

| Pattern | Use when | Primary risk |
|---|---|---|
| Router | Independent request classes map to specialists | Misclassification. |
| Manager | One owner must synthesize delegated work | Manager bottleneck or context overload. |
| Agents-as-tools | Specialists can be called with strict contracts | Hidden recursion. |
| Handoff | Control legitimately transfers between domains | Context and responsibility loss. |
| Swarm or peer | Work is genuinely decentralized | Loops, ambiguous owner, and cost explosion. |

Swarm is never the default. Name the final owner, loop detector, cancellation, budget, and merge rule.

## Hybrid Lifecycle

A common robust sequence is:

```text
deterministic intake and validation
-> bounded agentic planning with structured output
-> deterministic policy gate
-> isolated execution
-> independent verification
-> human approval when risk requires it
-> deterministic commit or side effect
-> audit and evaluation
```

The workflow controls lifecycle and risk. The model chooses within bounded nodes.

## Artifact Handoff

Each delegation returns a typed artifact with producer, run ID, version, summary, evidence, decisions, risks, open questions, and verification state. Pass references to large artifacts. Do not use prose acknowledgement as proof of execution.

The receiver validates schema, provenance, authority, and completeness before using the artifact. Inter-agent messages are untrusted input.

## Aggregation Discipline

An aggregator is an explicit role, never inferred merely because nodes share a level or parent. Derive topology from serialized edges and contracts, not visual indentation. Its contract declares merge schema, precedence, source addresses, final owner, and checks. Track local risk separately from inherited risk for every contribution; propagated risk carries severity, owner, and an addressable source artifact or node. Re-run safety and acceptance checks after merge because safe parts do not guarantee a safe composition. Prove composition early with representative artifacts, and label every unimplemented branch or stub honestly. Apply the same typed verification protocol to every contributing agent so results can be compared and reused.

## Concurrency and Loop Limits

Within an explicitly selected Mode C, use these default limits:

```text
fan_out: 3
delegation_depth: 1
repair_cycles: 2
```

Parallelize independent reads and isolated work. Serialize shared writes unless the merge strategy is proven. Every task needs timeout, cancellation, budget, owner, and terminal state.

Every override to fan-out, depth, or repair limits must be motivated, budgeted, recorded in the run contract, and independently verified against the simpler baseline.

## Coordination Control and Deterministic Fan-In

Before parallel work, run `DEPENDENCY_COMMUNICATION_SPLIT`. Record task dependencies, whether workers truly need messages, file or artifact ownership, merge class, token and tool budget, trust boundaries, and the smallest useful team. Parallelism is rejected when work shares mutable state or its merge cannot be proved.

Use a six-stage fan-out/fan-in protocol:

1. freeze the input artifact and `state_version_at_dispatch`;
2. issue a unique `dispatch_id`, `branch_id`, immutable snapshot, bounded contract, budget, deadline, and idempotency key;
3. let branches write only their owned artifacts, never global state;
4. collect at a barrier that records results, failures, cancellations, missing branches, and late arrivals;
5. apply the declared per-key merge policy with a read-only reviewer;
6. re-run policy, safety, and acceptance gates before a single owner commits.

A shared blackboard, when necessary, declares field owner, version, provenance, immutable origin, conflict policy, lock or lease, expiry, and reconciliation evidence. A field without one current owner is not writable.

Classify merges:

| Class | Allowed strategy |
|---|---|
| Reducible | `set_union` or a deterministic reducer with identity and ordering. |
| Ordered additive | `append_then_sort` with a stable key and duplicate rule. |
| Selective | `single_winner` chosen against frozen criteria by a reviewer. |
| Conflicting or policy-bearing | `no_auto_merge`, followed by reviewer arbitration or a human gate. |

Merge is a control step, not fresh authorship. If synthesis changes the deliverable’s meaning, claim set, risk, or policy, it is a new candidate requiring provenance and verification.

Reject stale branches whose base version no longer matches unless the contract defines a deterministic rebase and repeats affected tests. Quarantine late results after cancellation. External side effects are forbidden before merge; any later retry uses the same idempotency key and follows the effect controls in [reference 05](05_runtime_state_bridge_data_security_and_reliability.md).

`COORDINATION_BUDGET_CONTRACT` declares the shared ceiling, child quotas, protected verification reserve, fan-out, depth, handoff, and repair limits. Duplicate dispatch identity reuses a completed contribution instead of paying and merging twice.

`MERGE_REVIEW_CONTRACT` binds immutable contribution hashes, stable ordering, required evidence, missing-result behavior, conflict handling, pre/post hashes, final owner, and a reviewer with no write capability over the candidate. Missing, malformed, or contradictory contracts fail closed.

## Optional Councils and Consensus

A model panel, council, debate, or N-sample consensus is an optional profile for decisions whose value justifies multiplied cost and whose uncertainty cannot be resolved by deterministic tests or one strong worker with several hats.

The contract declares the question, participant independence, context policy, first-pass isolation, model or prompt diversity, quorum, anonymization, comparison rubric, synthesis owner, tie-breaker, dissent retention, evidence requirements, budget, and stopping rule. Cross-ranking must not reveal identity or prior votes before each independent assessment is frozen.

Consensus is a signal, not truth. Majority, convergence, or repeated wording cannot override policy, source authority, a deterministic failure, an independent verifier, or required human approval. Preserve minority reports and outliers with provenance; divergence may expose ambiguity or missing evidence rather than error.

Prefer, in order: deterministic verification; one worker with a rubric; independent reviewer; same-model panel; multi-model council. Record the cheaper baseline and the measured benefit before retaining the expensive profile.

## Delegation, Messaging, and Cancellation Contracts

Every delegated unit uses a `SUBAGENT_CONTRACT` with parent and task identity, harness, minimal context policy, inherited and removed capabilities, input and output schemas, ownership, success checks, stopping conditions, nesting depth, result route, cancellation, and resume semantics.

Reject unqualified “swarm.” Choose one explicit topology:

- active-owner peers with one named final owner; or
- queue/fan-out/fan-in with dispatch, barrier, merge, and terminal contracts.

Choose the communication primitive by schema, ownership, trust, delivery semantics, state effect, cancellation, acknowledgement, and deployment boundary. A mailbox, shared file, queue, event, or tool result is a carrier; none grants authority by itself.

`AGENT_MESSAGE_ENVELOPE` separates authenticity, integrity, provenance, authority, and delivery state. A valid signature or matching hash proves bytes and origin, not permission to act. Inter-agent messages remain untrusted data until schema, source, authority, freshness, and scope are checked.

Before scaffold or dispatch, freeze an `ORCHESTRATION_CONTROL_FRAME` with objective, topology, owners, artifacts, tool and capability map, risk, approvals, state transitions, budgets, merge rule, verification lane, cancellation, recovery, and terminal states. The verifier reviews the frame independently.

`DELEGATION_ENVELOPE` includes parent/task ID, objective, minimal context slice, provenance, authority subset, inputs, expected output, message trust class, and output hash. Delegation can narrow authority but cannot enlarge it.

`CANCELLATION_PROPAGATION_CONTRACT` records the parent/child graph, deadline, acknowledgement, effect state, late-result policy, and proof of quiescence. Cancellation does not prove that an external effect stopped; reconcile it through reference 05 before retry.

`MULTI_AGENT_TRACE_CONTRACT` records trace, parent, task, actor, capability and version, input/output hashes, route reason, cost, stop/review outcome, and inherited risk. Risk is monotone across delegation and merge unless an authorized gate explicitly changes it; no child or aggregator may silently lower it.

## Governed Peer Collaboration Profile

This is an optional human-governed peer-work profile. It is not the default; activate it only after [reference 01](01_doctrine_scope_and_necessity_triage.md) justifies distinct builder and verifier boundaries and the host capability probe confirms they are real.

The profile requires four logical contracts, which may be grouped into three or more physical files:

1. goal and authority: exact objective, scope, non-goals, human sovereign or delegate, risk, approvals, budget, and frozen done criteria;
2. builder delivery: candidate version/hash, source locators, self-checks, decisions, unknowns, effects, and rollback;
3. verifier response: independent reproduction, finding or pass, evidence locators, preserved dissent, and explicit verdict;
4. transition and closure: current state, checkpoint, open work, next safe actor, terminal evidence, and closure authority.

The human sovereign starts or delegates the goal and retains authority over scope, risk, exceptions, and the exact version admitted. Approval does not transfer automatically to later bytes or broader actions; detailed authority and denial rules remain in [reference 04](04_governance_autonomy_risk_approval_and_rollback.md).

The builder owns the candidate and self-evidence but cannot issue the independent verdict. The verifier reproduces the claim against frozen criteria and cannot silently rewrite the candidate, acceptance criteria, or answer key.

Dissent is falsifiable:

- the dissenter states the exact disputed claim, evidence, reproduction, and what result would change the position;
- the other party either answers with evidence or records the unresolved delta;
- a party that changes position states which evidence or test caused the change;
- unresolved material disagreement routes to the human authority rather than being averaged away.

The lifecycle is:

```text
learn and inventory
-> plan together
-> builder candidate
-> independent reproduction
-> pass or evidence-bound finding
-> bounded repair
-> final joint signature
```

Allow at most two semantic cycles unless the human authority approves a new bounded exception. Runtime retry classification, idempotency, restart, and recovery budgets remain owned by reference 05. A retry cannot change candidate meaning or extend the semantic loop; any content change is a semantic cycle.

Builder and verifier exchange typed artifact identifiers, version/hash, evidence locators, risks, unknowns, verification state, and checkpoint. The detailed relay, acknowledgement, sentinel, and verifier mechanics stay single-homed in [reference 10](10_verifier_playbook.md); this profile defines roles and transitions only.

Public behavior:

- `POS`: authority, candidate, evidence, independent verdict, and terminal state are complete and no unapproved effect occurs.
- `NEG`: necessity fails or either peer rejects with evidence, so the profile does not activate or does not close.
- `MALFORMED`: missing authority, candidate hash, criteria, evidence, state, or closure fields are enumerated and no effect occurs.
- `RECOVERY`: the new session proves continuity from checkpoint and hashes before writing; interrupted attempts and uncertain effects are preserved and reconciled.

## Scoped Historical Observation

Historical peer-work records exist, but their duration, outputs, and performance claims remain single-homed in the case and evaluation package. This reference retains only the boundary: the profile makes no superiority, universal productivity, losslessness, or cross-domain fitness claim.

The evidence record belongs to [reference 08](08_case_patterns_and_antipatterns.md); evaluation design and longitudinal claims remain in [reference 07](07_observability_evals_opex_and_learning.md), while report and document evidence remain in [reference 06](06_reports_artifacts_and_visual_qa.md).

## Model Profiles

Use capability profiles rather than hard-coded model IDs:

- `router-fast` for classification and extraction;
- `planner-strong` for ambiguity and architecture;
- `executor-code` for implementation inside a sandbox;
- `researcher` for sourced evidence;
- `verifier` for independent review;
- `summarizer` for stable compaction and reporting.

Provider and model mapping belongs to deployment configuration and the run manifest.
