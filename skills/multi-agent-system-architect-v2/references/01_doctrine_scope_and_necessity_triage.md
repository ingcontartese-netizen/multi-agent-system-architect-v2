# Doctrine, Scope, and Necessity Triage

Load this reference when deciding how much system the request warrants. Complete this decision before choosing frameworks, agents, protocols, or databases.

## Table of Contents

- Authority and outcome
- Compare like with like
- Requirements interview
- Problem dossier and completeness gate
- Three-axis classification
- Operational decision profile
- Sequential necessity gate
- Multi-agent justification
- Promotion, boundary, and collapse proof
- Design and build lanes
- System passport, acceptance, and exit
- Scope decision artifact

## Authority and Outcome

Identify the human sovereign and the authority order for requirements, policy, data, and final approval. Convert the request into:

- objective and measurable benefit;
- users, tenants, and affected parties;
- non-objectives and forbidden outcomes;
- inputs, outputs, side effects, and retained data;
- latency, duration, scale, budget, and operating environment;
- acceptance evidence, rollback, and stop conditions.

The architectural objective is not maximum autonomy or agent count. It is the smallest governed solution that can meet the acceptance evidence.

## Compare Like with Like

Classify each candidate before comparing it:

| Category | Primary responsibility |
|---|---|
| Surface | Human interaction through CLI, IDE, chat, dashboard, or control plane. |
| Agent framework | Model loop, tools, structured output, delegation, and agent primitives. |
| Workflow runtime | State, transitions, retries, pause, checkpoint, and resume. |
| Harness or SDK | Operational shell around the model: tools, context, permissions, sessions, and subagents. |
| Managed platform | Hosting, identity, policy, registry, observability, tenancy, and deployment. |
| Personal runtime | Always-on user gateway across channels and personal automations. |
| Protocol | Interoperability between capabilities; it does not provide the whole runtime. |

Do not compare objects from different categories as substitutes without naming the missing layers.

Keep four namespaces separate:

- `architecture_form`: direct capability, deterministic workflow, one agent, hats, or multiple agents;
- `object_category`: the seven categories above;
- `system_plane`: the responsibility map in [reference 11](11_system_planes_and_stack_selection.md);
- `coverage_status`: `required`, `optional`, `external`, or `not_needed`.

Topology, actor count, communication channel, and process or identity boundary are
additional axes. Do not infer one from another or reuse the same short label for
different objects. Compare candidates only inside one object category, unless the
comparison explicitly accounts for every missing plane. Evaluate an additive,
unchanged, and subtractive variant against the same quality floor; a new capability
may justify removing components rather than adding them.

## Requirements Interview

Gather or conservatively infer:

```yaml
goal_and_owner:
users_and_tenants:
inputs_and_outputs:
side_effects:
data_sensitivity_and_retention:
latency_and_duration:
volume_and_concurrency:
human_approval:
existing_stack:
self_host_or_cloud_constraints:
budget:
machine_checkable_success:
non_agentic_baseline:
initial_state_and_population:
final_state_and_real_outcome:
error_profile_and_disqualifiers:
decision_owners:
prototype_exit_strategy:
```

Mark every inferred value as an assumption. If missing facts affect authority, sensitive data, side effects, reversibility, risk, or acceptance, stop at design/proposal and request the missing decision. Otherwise use a reversible, low-autonomy assumption explicitly.

## Problem Dossier and Completeness Gate

Before classification or product selection, assemble a problem dossier as a
validated view over the purpose, requirements, risk, and acceptance artifacts. It
does not require a new standalone file. It must connect:

- the real problem, affected population, initial state, and desired final state;
- observable outcome units and denominators, not only model-quality proxies;
- error classes such as omission, false positive, false negative, duplication,
  delay, incorrect data, and unauthorized effect;
- impact, detectability, recoverability, safe failure, escalation owner, and
  non-compensable disqualifiers;
- authority, boundaries, constraints, assumptions, and evidence locators;
- the simplest credible baseline and the conditions for stopping or reopening.

Unknown values remain explicitly `open`; invented values fail the gate. Do not
classify Mode/AU/R, score a stack, or start a build while a decisive field is
missing. A weighted score can rank only candidates that have already passed every
mandatory gate.

## Three-Axis Classification

Classify independently:

### Architecture Mode

| Mode | Decision |
|---|---|
| A | No agentic system. Use a direct model or another capability and hand off. |
| B | Governed workflow, one bounded agent, or one model wearing explicit hats. |
| C | Multiple independent agents or distributed agent services are justified. |

### Autonomy Level

Autonomy is a property of the whole system across its planes. A framework plus a prompt is not, by itself, an autonomous agent.

| Level | Operational meaning |
|---|---|
| AU0 | Response without tools. |
| AU1 | One bounded tool call. |
| AU2 | Supervised multi-step loop. |
| AU3 | Delimited task completion inside policy and sandbox. |
| AU4 | Long-running or event-driven execution with durable state. |
| AU5 | Open-ended, self-goal-generating, or sovereign autonomy. It is outside the supported production envelope and must be reduced or refused. |

Federation is a trust and interoperability topology, not an autonomy level. A federated system may still be AU2-AU4. Choose the lowest supported autonomy that meets the objective.

### Risk Class

Assign R0-R5 from the action, target, data, privilege, reversibility, and blast radius. Risk controls belong to reference 04; architecture mode and autonomy never authorize higher risk by themselves.

## Operational Decision Profile

Mode, AU, and R are independent summaries, not a complete operating envelope.
Duration and durable state do not prove path discretion: a deterministic process
may run for months, while a short single-agent run may replan materially.

For a medium- or high-impact decision, record a companion profile:

```yaml
architecture_form:
path_discretion:
action_authority:
time_horizon_and_durability:
distance_from_human_review:
environment_openness:
actor_instances:
identity_or_process_boundaries:
context_and_state_isolation:
model_tool_and_permission_differences:
topology_and_channels:
final_human_owner:
```

Feed this profile into the risk envelope, approval design, and evaluations. Do not
infer autonomy, maturity, isolation, or accountability from the number of agents.
Classify each material action when a product contains paths with different owners
or envelopes.

## Sequential Necessity Gate

Apply in order:

1. Can a direct capability or ordinary function deliver the result without continuity or side effects? Choose Mode A or the function.
2. Are steps, branches, inputs, outputs, and recovery known? Choose a deterministic workflow.
3. Is semantic judgment local? Use a bounded AI island with an input contract, allowed context, output schema, validators, effect owner, and deterministic fallback.
4. Is uncertainty broader but still owned by one bounded loop? Put one agent inside the governed workflow.
5. Can one model apply several cognitive rubrics without process or trust isolation? Use hats, not more processes.
6. Does a distinct permission, tool, context, success criterion, trust boundary, or useful parallel path require separation? Consider Mode C.
7. Does Mode C beat the frozen simpler baseline on real outcome, verified success, latency, cost, human effort, risk, or governance? If not, remove or collapse it.

Classify the authorized operation, not the hostile action requested by untrusted input. A fixed read-only fetch and schema extraction from one untrusted page remains a deterministic AU1/R0 workflow when no judgment loop or write is required. Delimit the page as data, deny its injected instructions separately, and add an agent or higher risk only when the authorized workflow itself needs those powers.

Choose routing by evidence:

- stable known classes use deterministic dispatch;
- specialization discovered during work may use a bounded handoff with an owner,
  hop limit, route dataset, and anti-bounce rule;
- unknown or sensitive routing returns to a human decision.

When Directive-Orchestration-Execution is proposed, first return `NOT_WARRANTED`
for a simple task. When warranted, the directive states why, what, and constraints;
orchestration emits a schema-bound payload; deterministic execution validates
schema, authority, review state, and artifact hash and fails closed. Free-form
prose is not an execution contract.

## Multi-Agent Justification

Add a separate agent only when at least one condition is material:

- different tools or permissions;
- different model or context requirements;
- independent success criterion or verifier role;
- useful parallelism;
- team, tenant, trust, or remote-service boundary;
- significant context reduction for the final owner.

Record the final owner, artifact contract, cancellation, and budget. Apply the canonical concurrency, depth, repair, and override rules in [reference 03](03_operating_modes_hats_and_orchestration.md).

## Promotion, Boundary, and Collapse Proof

Treat promotion to Mode C and every new process, trust, state, or service boundary
as a falsifiable hypothesis. Reuse existing requirements and acceptance artifacts
to produce these composed views:

- **Baseline race:** same task population, initial state, sources, authority,
  graders, budgets, thresholds, and disqualifiers for the simpler baseline and
  candidate.
- **Boundary invoice:** expected benefit plus schema and context loss, concurrent
  state, retry and idempotency, latency, identity, observability, deployment,
  recovery, change, ownership, and exit cost.
- **Ablation:** remove or collapse each proposed actor or boundary so the measured
  benefit can be attributed rather than confused with a stronger model or larger
  budget.
- **Live-value gate:** distinguish deterministic harness proof from a repeated,
  blind live comparison. Record `NOT_RUN`, `PASS`, `FAIL`, or `INCONCLUSIVE`;
  never promote a harness PASS into a live-value claim.
- **Step-back rule:** predeclare the signal that collapses the extra agent,
  boundary, or plane when value, reliability, cost, or risk fails its threshold.

Mutation evidence must name the mutation, invoked surface, observation, and kill
reason; a check that is green by construction is not evidence.

## Design and Build Lanes

The design lane is mandatory for Modes B and C. Define purpose, responsibilities, planes, state, tools, knowledge, memory, trust, approval, observability, verification, and exit strategy.

The build lane is optional. Enter it only when implementation is requested, the design and risk gates are approved, an isolated workspace exists, rollback is credible, and acceptance checks are executable. Mode A leaves this skill after a reasoned handoff.

## System Passport, Acceptance, and Exit

Before build or material stack selection, assemble a system passport as a composed
view over the existing artifacts:

- purpose, non-goals, Mode, AU, R, authority, and action-level owners;
- boundaries, contracts, state and knowledge, tools, planes, evaluation,
  operations, economics, and exit;
- completeness status and evidence locator for every required plane;
- real-world outcome, units, population, initial state, expected final state,
  thresholds, denominators, grader, uncertainty, and safe-failure conditions.

A missing mandatory plane or disqualifier fails closed. An acceptance metric about
the model cannot substitute for the real outcome.

Record exit status as `planned`, `tested`, or `unknown`. Use `tested` only after a
dry run or observed replacement. A prototype also declares limits, portability and
export, rewrite triggers, and kill criteria; initial success does not prove fitness
for production traffic, data, or risk.

## Scope Decision Artifact

Return:

```yaml
status:
authority:
architecture_mode: A | B | C
autonomy_level: AU0 | AU1 | AU2 | AU3 | AU4 | AU5
risk_class: R0 | R1 | R2 | R3 | R4 | R5
assumptions: []
alternatives: []
decision:
why_not_simpler:
why_not_more_complex:
sensitivity: []
acceptance_evidence: []
operational_profile: {}
problem_dossier_status:
baseline_race:
boundary_invoice:
ablation_and_collapse:
system_passport_status:
real_outcome_contract:
exit_strategy:
exit_status: planned | tested | unknown
prototype_exit_strategy:
next_gate:
```
