# Governance, Autonomy, Risk, Approval, and Rollback

Load this reference when a design grants initiative, reads protected data, writes shared state, performs side effects, or requires human consent and recovery.

## Table of Contents

- Human sovereignty
- Decision ownership and meaningful oversight
- Autonomy is a system property
- AU control envelope
- Effect-aware resilience and escalation
- Risk and approval matrix
- Approval request contract
- HITL without fatigue
- Aggregated and inherited risk
- Policy hierarchy, exceptions, and applicability
- Policy decision
- Organizational governance and affected parties
- Change and rollback governance
- Hard stops

## Human Sovereignty

The model may explain, propose, draft, and verify. Policy authorizes. The human sovereign decides product intent, canonical changes, exceptional risk, and final baptism.

For governed changes use:

```text
notify -> explain -> show target and diff -> obtain scoped consent -> execute -> read back -> report
```

Absence of a reply is not consent. Approval is an auditable event with actor, scope, artifact hash, timestamp, expiry, and decision.

Permanent constraints belong in policy, contracts, and tests, not in an expiring task list that can be checked off and forgotten.

## Decision Ownership and Meaningful Oversight

Every material path identifies who owns the decision, effect, failure, escalation,
and stop. For a production system, resolve at least:

- process or product owner;
- technical or runtime owner;
- data owner;
- risk, security, or compliance owner;
- competent human reviewer or approver.

One person may fill several roles in a small system, but each responsibility must
be named. For each material decision identify exactly one human `Accountable`, at
least one `Responsible`, and only the `Consulted` and `Informed` roles that are
useful. A model may propose, execute, or provide evidence; it is never the
Accountable authority. Delegation records scope, basis, expiry, conflict rule, and
escalation.

Oversight is meaningful only when the human has sufficient information,
competence, response time, executable approve/edit/reject/stop powers, a usable
interface, readback, appeal or recourse, manageable workload, and a delegate.
Measure the decision population and timeout rate. A nominal approval button
without these conditions is not a control.

Each non-trivial run also has a bounded task contract: objective and finish line,
context and environment, constraints, deliverable schema, risk, acceptance
evidence, owner, failure path, stop, and rollback.

## Autonomy Is a System Property

Do not call a framework-plus-prompt autonomous. Operational autonomy emerges from trigger, state, memory, tools, identity, policy, environment, budgets, recovery, observability, and stop control.

An unattended single agent can be AU4. A supervised multi-agent workflow can remain AU2. Agent count does not measure autonomy, and autonomy does not authorize risk.

## AU Control Envelope

| Level | Minimum controls |
|---|---|
| AU0 | Output schema and content policy. |
| AU1 | Tool input/output validation, timeout, and bounded result. |
| AU2 | Step budget, write approval, checkpoints, and visible plan. |
| AU3 | Scope, sandbox, verifier, egress policy, cancellation, and escalation. |
| AU4 | Durable state, idempotent triggers, deduplication, retry, alert, budget, and kill switch. |
| AU5 | Open-ended or sovereign autonomy has no approved operational envelope; reduce scope or refuse. |

For AU3-AU4 also define heartbeat/lease, approval deadlines, dead-letter or compensation, disaster recovery, and maximum unattended duration.

## Effect-Aware Resilience and Escalation

Retries are allowed only when effect state is known. A pre-effect failure may use a
bounded retry with deterministic backoff. If an effect may have occurred, first
use idempotency, status readback, or reconciliation; never retry blindly.

Use an explicit escalation ladder:

1. bounded technical retry for a classified pre-effect failure;
2. review or repair loop against fresh evidence;
3. circuit-break the failing capability and preserve checkpoint state;
4. use a pre-authorized fallback only inside the same policy, data, and risk
   envelope;
5. return to the human gate or safe stop.

Use deterministic rails for known invariants: select the relevant tests from the
changed surface, run schema and policy checks, and apply an automatic repair only
for a predeclared safe pattern with readback. Prompted review complements these
rails for semantic or previously unknown failures; it does not replace them.
Bound both repair paths and return unresolved work to the human owner.

Classify provider or model failures before choosing a response:

| Failure class | Governed response |
|---|---|
| authentication or credential | stop and quarantine; rotate or change access only under explicit credential authority |
| rate limit | bounded backoff and retry only inside time and cost budgets |
| context overflow | deterministic compaction or partition with provenance, then retry only if effect-free |
| model or service error | use an approved model profile or provider fallback only inside the same capability, policy, data, and risk envelope |
| timeout or unknown effect | abort, read back or reconcile effect state, then retry only when non-effect is proven |

Attempt limits are configuration or policy, not model-selected values. Exhaustion,
ambiguous effect state, duplicate effect, or a fallback that changes provider,
credential, data location, cost, or authority requires a new decision. Runtime
error mechanics live in [reference 05](05_runtime_state_bridge_data_security_and_reliability.md); this reference owns whether escalation or fallback is authorized.

## Risk and Approval Matrix

| Class | Typical action | Default decision |
|---|---|---|
| R0 | Public read-only source | Allow within logged scope. |
| R1 | Internal read under RBAC | Allow only for authorized tenant and purpose. |
| R2 | Reversible local or draft write | Allow with checkpoint and final review. |
| R3 | Shared staging, PR, ticket, or collaborative write | Require plan or tool-call approval. |
| R4 | External communication, finance, production deploy, irreversible business action | Explicit authenticated approval; draft and commit separated. |
| R5 | Root, IAM, secrets, open network, destructive security action | Deny by default; use a separate privileged procedure with temporary credentials. |

Raise the class for sensitive data, unknown targets, broad scope, poor reversibility, or large blast radius. Architecture mode never lowers the risk class.

Hard gates are non-compensatory. Human judgment may assess residual risk or request
new evidence, but it cannot convert a failed sovereignty, security, authority,
reversibility, residency, budget, or recovery gate into PASS by adding score
elsewhere.

## Approval Request Contract

Show the approver:

- exact action and target;
- current state and proposed diff;
- reason and source evidence;
- impact, blast radius, and reversibility;
- credential or role to be used;
- preview or dry-run result;
- budget and expiry;
- options `approve`, `edit`, `reject`, and `defer`.

Persist state before waiting. On resume, revalidate target, artifact hash, policy, credential, and expiry before commit.

For `defer`, also record wait reason, reopening trigger, expiry, owner, and minimum
dossier. Treat denial as a structured result, but a denial closes the current
intent. The system may explain, propose a materially different safe alternative,
or request new consent; it must not continue the denied action under a renamed
plan.

## HITL Without Fatigue

Use human attention at meaningful boundaries:

- approval before irreversible action;
- plan review and editing;
- tool-parameter editing before execution;
- durable checkpoint;
- steering during a long run;
- escalation on low confidence, policy failure, or budget breach;
- sampled quality review;
- post-review with rollback.

Allow scoped approval for a bounded action class and session, never an indefinite global `approve all`. Measure edit, reject, defer, timeout, and escalation rates to improve policy.

Map machine and human outcomes without compensatory scoring:

| Evidence state | Human options |
|---|---|
| `PASS` | approve, request evidence, or reject on a separately stated policy ground |
| `FAIL` | revise or reject |
| `INDETERMINATE` | request evidence, defer, reduce scope, or reject |
| `HARD_FAIL` | reject and enter the declared recovery path |

## Aggregated and Inherited Risk

An aggregator owns both its local transformation risk and every inherited risk carried by its inputs. Each propagated risk includes source address, owner, severity, status, and required control. Merge policy cannot lower a child risk silently. Re-evaluate safety, authority, and approval after composition, and expose inherited risks in the report envelope rather than collapsing them into one unlabeled severity.

## Policy Hierarchy, Exceptions, and Applicability

Declare precedence among applicable law or binding instrument, contract, approved
organizational policy, system policy, and runtime rule. A lower layer cannot
silently weaken a higher one.

Every exception records:

```yaml
scope:
authority:
reason:
effective_at:
expires_at:
compensating_controls: []
evidence:
renewal_authority:
debt_state:
```

Invisible, expired, or unowned exceptions fail closed. A source being official
does not prove it is binding or applicable. For regulatory or contractual claims,
record instrument type, authority, jurisdiction, binding status, adopted,
published and effective dates when relevant, pending step, applicability test,
claim locator, access date, freshness trigger, and required qualified review.
Keep current facts in a dated evidence ledger, not in evergreen doctrine.

## Policy Decision

Use a deterministic policy engine outside the model. Conceptually:

```python
def decide(action, context):
    if action.risk >= R5:
        return DENY
    if not context.identity.can(action.scope):
        return DENY
    if action.target not in context.allowed_targets:
        return DENY
    if action.risk <= R1 and action.read_only:
        return ALLOW
    if action.risk == R2 and action.reversible and context.within_budget:
        return ALLOW_WITH_CHECKPOINT
    if action.risk in {R3, R4}:
        return REQUIRE_APPROVAL
    return DENY
```

The model may classify and explain; it cannot grant itself authority.

## Organizational Governance and Affected Parties

When a system changes work, the governance package also covers task delta, human
capacity and competence, workload, fallback, appeal, communication, feedback, and
labor, privacy, or sector review where applicable. Identify affected parties and
the owner of each mitigation.

Cross-check the human-readable charter against machine-readable contracts. Reject
promised controls with no field, unresolved owners, non-instructional dates, or
signatures without artifact readback. Readiness to build or pilot is a separate
decision from production release.

## Change and Rollback Governance

Before an impactful change, record alternative, evidence, migration, rollback, owner, and acceptance threshold. The release mechanics, shadow/canary rules, and predeclared thresholds have their single home in [reference 07](07_observability_evals_opex_and_learning.md).

Canonical knowledge, policy, prompts, tool schemas, and host adapters change through proposal and independent verification. Preserve superseded versions and prove the active version after the change.

The final authority event binds the exact artifact and evidence. Record the
independent gate, active hash, rollback anchor, and human baptism separately; a
technical PASS is not a product decision.

## Hard Stops

Stop or escalate when:

- owner, target, or authority is ambiguous;
- approval does not bind the exact artifact or action;
- a material decision lacks a human Accountable or an effect, failure, escalation, or stop owner;
- the human lacks information, competence, time, powers, readback, appeal, or a workable load;
- rollback or compensation is undefined for an impactful write;
- a secret would enter model context or logs;
- sandbox, egress, identity, or tenant boundary is missing;
- budget, retry, delegation, or duration is unbounded;
- a retry is attempted with uncertain effect state, or a fallback changes the authorized envelope silently;
- a denial is reinterpreted as permission to continue the current intent;
- a hard fail is overridden by score or informal approval;
- a policy exception is invisible, expired, unowned, or conflicts with a higher authority;
- a regulatory or contractual claim lacks applicability and freshness evidence;
- the system is asked to generate or expand its own goals without a bounded human mandate;
- verifier evidence is absent or produced by the same unchecked actor;
- the kill switch cannot halt trigger, workflow, tool, or credential.
