# Observability, Evaluations, OpEx, and Governed Learning

Load this reference when defining evidence, traces, tests, cost controls, release gates, incidents, or how lessons become future changes.

Evidence is scoped, not contagious: every claim binds its target, version, dataset or population, environment, time, verifier, and known limits. A stronger label outside that scope is invalid.

## Table of Contents

- Run manifest and trace
- Metrics that matter
- Evidence claims and eval datasets
- Test and eval layers
- Eval case contract
- Agentic test matrix and outcome states
- External verification and LLM judges
- Verifier calibration and adversarial review
- Budgets, capacity, and backpressure
- Cost and operational economics
- Accepted-outcome economics and routing
- Release, canary, and rollback
- Release truthfulness across surfaces
- Incident response
- Governed learning and Tech Watch
- Governed evolution contract
- Evolution safety and de-engineering

Route each claim to the narrowest section and smallest independently checkable proof unit; aggregate only after every constituent denominator and verdict is explicit.

## Run Manifest and Trace

Version together:

- skill and procedure bundle;
- workflow graph and prompt bundle;
- tool schemas and policy;
- model profile and provider mapping;
- sandbox image and dependency lock;
- eval dataset and configuration;
- budget and human interventions;
- input and output artifact hashes.

Trace spans should cover intake, routing, model call, retrieval, tool call, policy decision, approval wait, sandbox execution, verification, artifact write, and final response. Attach run ID, tenant, versions, risk, tool, tokens, cost, latency, retries, approval outcome, and artifact IDs.

## Metrics That Matter

Track:

- end-to-end and verified success;
- first-pass success;
- human intervention, edit, reject, and defer rates;
- tool errors, timeout, retry, and repair counts;
- p50/p95/p99 latency and queue wait;
- token, money, and time per successful task;
- rollback, incident, and stale-run rates;
- blocked injection, secret, and policy violations;
- quality delta versus the simplest baseline.

Cost per call is not the objective. Optimize verified benefit per successful task.

## Evidence Claims and Eval Datasets

Freeze each falsifiable claim before opening results:

```yaml
claim_card:
  claim_id:
  population:
  candidate_version:
  baseline_version:
  primary_measure:
  guardrails: []
  threshold:
  threshold_rationale:
  non_claims: []
  evidence_scope:
    level: DESIGN | OFFLINE_FIXTURE | SANDBOX | PILOT | PRODUCTION
    target:
    host_or_carrier:
    versions: {}
    dataset_or_distribution:
    volume:
    environment:
    verified_at:
    verifier:
    known_limits: []
    invalidating_changes: []
  decision_owner:
```

Evidence is scoped, not contagious. A sandbox result does not prove live equivalence; a human approval cannot turn a failed technical check into a PASS; a higher evidence label is invalid unless its target, versions, dataset, volume, environment, time, verifier, and limits are bound. Use the single evidence ladder in [reference 10](10_verifier_playbook.md) and declare `NOT_RUN` for every unexercised lane.

An eval dataset manifest records population, provenance, privacy class, case family, grouping key, development/test/challenge/holdout split, visibility, freeze event, near-duplicate audit, contamination event, and replenishment evidence. Freeze splits by group before candidate generation. Keep candidate input, oracle, and system-under-test runtime separate; the candidate must not import, retrieve, or infer expected values. Deliberately wrong-oracle probes should fail safely and expose leakage.

For datasets and generated tables, bind the eval to a data contract: fields, types, units, date/currency formats, keys, missing-value semantics, deduplication, source, timestamp, and validity checks. A parsed file without a declared denominator or contract is not a qualified fixture.

## Test and Eval Layers

| Layer | Purpose |
|---|---|
| Unit | Tool, parser, schema, policy, routing, and reducer without a real model. |
| Scenario | Workflow state transitions with stubs or controlled models. |
| End-to-end | Real model, tools, sandbox, carrier, and artifact on representative tasks. |
| Online | Shadow, canary, sampled dual-run, and production monitoring. |

Exercise resume, timeout, approval, idempotency, cancellation, malformed output, provider failure, and adversarial input. Most checks should be deterministic.

## Eval Case Contract

Each case declares:

```yaml
id:
input:
initial_state:
allowed_tools: []
forbidden_actions: []
expected_artifacts: []
checks: []
risk_class:
budget:
rubric:
```

Use atomic checks and frozen fixtures. Include cases for no-system decisions, AU4 recovery, R4 draft/commit, malicious retrieval, memory deletion, simple versus complex RAG, stale catalog, crash during approval, cross-host parity, and multi-agent versus single-agent baseline.

Use synthetic credentials and recognizable fake secret patterns. Never place a real secret in an eval corpus, trace fixture, or golden artifact.

## Agentic Test Matrix and Outcome States

Use the cheapest independent layer that can falsify the claim:

| Layer | Typical cadence | What it proves |
|---|---|---|
| Deterministic unit | every change | tools, schemas, reducers, policy, parsers, and graders without an LLM |
| Mocked reasoning/scenario | every change | state and decision behavior with controlled tool responses |
| Frozen behavioral eval | pre-release and material prompt/model changes | model behavior against atomic rubrics and thresholds |
| End-to-end or online | scheduled, pre-release, pilot, or canary | the real carrier, environment, effects, artifacts, and operational path |

An agentic eval treats `task`, `trial`, `grader`, `assertion`, `environment`, and `terminal state` as first-class. For each relevant run, artifact, review, trace, policy, and budget object, map the applicable happy, rework, fallback, human, parallel, and retry paths to explicit assertions and publish the full denominator. A runner that discovers or processes zero expected tests returns `INDETERMINATE`, never a green `0/0`.

Every check returns exactly:

- `PASS` — the declared assertion ran and its evidence satisfies the frozen criterion;
- `FAIL` — the assertion ran and contradicted the criterion;
- `INDETERMINATE` — the runner, evidence, denominator, dependency, or state cannot support either verdict.

Include a reason code, missing evidence, owner, and recovery action. Crash, malformed structured output, stale evidence, or a missing result is not automatically candidate failure; validate and recover the measuring instrument before modifying the candidate.

Repeated trials declare trials per case, fixed and varying factors, pairing key, success numerator, full denominator, interval method, confidence level, seed semantics, and inconclusive rule. Distinguish probability of at least one success (`pass@k`) from probability that every required trial succeeds (`pass^k`). A seed alone does not promise reproducibility across changing models, tools, providers, concurrency, or data.

For delayed ground truth, create a pending outcome with callback or scheduled readback, due date, immutable trial identity, expiry behavior, and promotion block. A provisional proxy must not masquerade as final truth. Each loop declares its oracle type, feedback latency, maximum attempts, stop, escalation, and the autonomy permitted by that verifiability.

## External Verification and LLM Judges

Prefer test, lint, schema, reconciliation query, browser assertion, citation checker, policy engine, and artifact readback. Use a model judge only where deterministic checks cannot decide.

Mitigate judge bias with atomic rubrics, structured output, blind candidate identity, multiple judges or human calibration, frozen datasets, leakage checks, and disagreement review. Judge confidence never replaces missing evidence.

## Verifier Calibration and Adversarial Review

Negotiate the definition of done, rubric, denominators, hard gates, interaction method, and evidence level before construction. The verifier remains separate from the builder and receives artifacts through a typed handoff; active coordination may clarify evidence location but must not reveal expected verdicts or hidden oracle content.

Calibrate each verifier with positive, negative, ambiguous, and hard-failure fixtures; a reference solution; self-exclusions; mutation probes; and sampled readback. Record expected and discovered denominators. Meta-evaluate whether the grader distinguishes `FAIL` from `INDETERMINATE`, detects missing tests, and rejects an artifact that merely asserts its own success.

Treat a candidate output as untrusted data. A model judge gets explicit delimiters, blind identity, an atomic rubric, no tools or effects unless the eval contract independently authorizes them, an evidence-citation requirement, an unknown path, order-swap checks, a calibration set, and a disagreement queue. Never allow instructions embedded in the candidate to alter the judge contract.

For subjective quality, weight a frozen rubric toward known failure modes and interact with the live output when the claim concerns interaction; screenshots alone are insufficient. Use independent adversarial review, external evidence, no more than the predeclared repair cycles, and a human decision where required.

Authorized red-team work declares target ownership, written authority, synthetic data, budget, exercised threat families, logging, kill switch, stop criteria, and zero-effect proof. Negative controls must include missing provenance, builder-equals-verifier, absent owner, forbidden authority, and risk actions without required human control.

Real work, including a guide or report produced during development, may become an eval only when its task, frozen inputs, checks, failure replay, and evidence are captured. Retrospective confidence is not a test.

## Budgets, Capacity, and Backpressure

Maintain separate budgets for rate, concurrency, tokens/context, money, tool or model steps, retries, and qualified human review. Each has owner, reservation, spend, release, attribution, soft warning, hard stop, and escalation authority. A global ledger and local worker quotas are both required when fan-out can cause starvation.

Define priority classes and fairness before load; interactive or safety-critical work may outrank batch work, but no actor receives an implicit unlimited share. On pressure, choose explicitly among queue, throttle, retry-after, degrade, shed, defer, or stop. Do not silently shift work to an unverified model, carrier, or approval path.

Treat human review as a finite queue. Declare intake quota, maximum artifact or diff size, required summary and test log, risk tag, reviewer skills, service objective, stale-work disposition, and fatigue threshold. Overproduction is a failure mode: unreviewable drafts, reports, or changes are inventory, not accepted value.

## Cost and Operational Economics

- use economical profiles for routing, extraction, and stable validation;
- reserve strong profiles for planning, synthesis, and difficult repair;
- parallelize only independent work;
- cache safe read-only retrieval and bounded tool results;
- cap model calls, tool calls, wall time, money, artifacts, and delegation;
- terminate when acceptance passes, not when the model asks for another refinement;
- estimate cost before an expensive or paid lane and obtain approval when required.

Maintain run and cost ledgers with real provider counts when available and explicit estimates otherwise. Separate subscription/flat channels from metered API channels without pretending either is free.

## Accepted-Outcome Economics and Routing

Define the accepted outcome before comparing systems. Measure:

```text
total candidate cost =
  model input (cached and uncached)
  + model output
  + tool, compute, storage, and carrier cost
  + evaluation cost
  + qualified human review time
  + retry and rework cost
  + declared residual-risk allowance

cost per accepted outcome = total candidate cost / accepted outcomes
```

Report first-pass acceptance, rejection, rework, qualified human minutes, and latency percentiles beside the ratio. Keep estimated prices labeled and revalidate authoritative pricing before go-live or a paid commitment. Do not game the metric by lowering quality, hiding eval cost, batching incomparable outcomes, or counting produced-but-unaccepted work.

Route by frozen task class, complexity, risk, latency objective, and evidence from paired trials. Assign the least costly profile and reasoning effort that satisfies the claim; promote or degrade only under declared criteria and budget. Do not encode a universal vendor mix or percentage. Compare candidate and simplest baseline on the same case IDs, fixtures, criteria, and comparable budgets, then use one-component ablations to decide keep, simplify, or remove.

## Release, Canary, and Rollback

Significant changes use versioned artifacts, offline eval, shadow or dual-run, canary, and predeclared rollback thresholds. Compare by skill, workflow, prompt, model profile, tool schema, and policy version. Widen rollout only after evidence and approval.

Do not move thresholds after seeing the result. Record regression, option sensitivity, migration, and exit strategy.

## Release Truthfulness Across Surfaces

Capability labels and product copy are acceptance contracts. When implementation state changes, update every UI, locale, adapter, guide, test, and generated artifact, then sweep the source for stale labels. A feature may be honestly de-scoped, but failure, fallback, or missing capability must remain visible rather than silently translated or suppressed.

## Incident Response

1. Stop the workflow or tool and activate the kill switch.
2. Revoke capabilities and isolate affected tenants.
3. Preserve trace, artifacts, policy decisions, and sandbox evidence.
4. Identify exact skill, prompt, tool, model, workflow, and policy versions.
5. Assess side effects and affected users.
6. Roll back or compensate.
7. Add a regression eval.
8. Complete postmortem and governed policy or design proposal.

## Governed Learning and Tech Watch

Every useful run may produce an immediate artifact and a candidate lesson. Candidate lessons enter an evolution bucket with signal, evidence, recurrence, impact, risk, owner, and destination. They do not mutate canonical skill or policy automatically.

Promote only after threshold, independent verification, human consent when required, migration, and release gate. Keep volatile framework capabilities in a dated catalog. Use the pinned Tech Watch cadence and freshness rules in [reference 11](11_system_planes_and_stack_selection.md).

## Governed Evolution Contract

Evolution is proposal production, not self-authorized mutation. Classify the proposed change before any write:

1. output refinement inside a run;
2. bounded in-run adaptation;
3. candidate memory update;
4. prompt, policy, tool, or workflow patch;
5. versioned release;
6. self-code or infrastructure change.

Higher levels inherit all lower-level controls and require the authority appropriate to their effects. Memory, instructions, skills, prompts, policies, and code never promote themselves.

Use this append-only pipeline:

```text
learning_event
-> issue cluster
-> threshold opens a candidate
-> minimal patch proposal
-> frozen development/regression/blind evaluation
-> independent promotion decision
-> staging
-> canary
-> versioned release or rollback
```

Each `learning_event` records run and source locators, concise signal, evidence, failure family, affected population, impact, risk, privacy class, and owner; never persist private chain-of-thought. A cluster threshold opens only a proposal. A single high-impact incident may justify immediate review, but it does not bypass evaluation or approval.

A patch proposal records cluster and source events, target component, minimal diff, expected effect, primary measure, guardrails, development/regression/blind dataset hashes, leakage audit, must-pass gates, migration, rollout, rollback, expiry, proposer, independent verifier, and required approvals. Freeze candidate input and all eval splits before generation; keep the blind set inaccessible to the proposer. Record fingerprints before and after candidate creation and again before and after promotion.

Tools that optimize prompts, generate skills, or harvest successful workflows are candidate proposers only. Package reusable know-how only when recurrence and measured benefit justify it; review its instructions and scripts, version it, run regression sentinels, and require human promotion before stable reuse.

Treat a nontrivial prompt as a versioned program output rather than an opaque string. A prompt builder should compose only required sections, keep authority and critical constraints salient, express desired behavior positively, reserve prohibitions for absolute boundaries, delimit untrusted material, require retrieval or tool readback before claims that need it, and place current runtime inputs where the target model can reliably use them. Any placement, persona, repetition, or reasoning-format heuristic remains a dated hypothesis to test against the frozen behavioral corpus; it is never promoted from citation or intuition alone.

## Evolution Safety and De-engineering

Evaluate every proposal across knowledge quality, architecture, tools, speed or latency, and leanness. Name one primary measure and guardrails for cost, latency, risk, and complexity; improvement on one dimension must not silently degrade another.

For each additive candidate, compare a subtractive alternative that removes or consolidates components while preserving the acceptance floor. Declare component count, dependency and porting cost, operational burden, rollback complexity, and exit path. A model or host upgrade is a reason to retest necessity, not to retain architecture by inertia.

Threat-model the evolution path itself: poisoned learning events, reward or threshold gaming, fragile or captured graders, blind-set leakage, approval manipulation, candidate-namespace escape, memory promotion, and rollback loss. Candidate work occurs in an isolated namespace with read-only access to canonical inputs; observation and proposal leave canonical bytes unchanged. Only a decision-bound, versioned promotion may change them.

Production outcome signals may inform a new learning event when their population, attribution, delay, quality, and scoring weights are dated and recorded. Scheduled experiments require a frozen hypothesis, budget, time window, keep/discard rule, kill switch, and rollback; they cannot silently rewrite the scoring function or production system.
