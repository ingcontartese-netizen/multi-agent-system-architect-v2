# Verifier Playbook

Load this reference when reviewing a plan, implementation, migration, release, or collaborator handoff. The verifier is independent from the builder and reports evidence, not reassurance.

Keep stable evidence separate from run telemetry. Stable evidence binds a claim to its check, denominator, artifact hashes, and decision; telemetry records run-specific facts such as run ID, host, duration, and retention. A verifier may link the two, but must not make the frozen evidence envelope depend on volatile telemetry.

## Table of Contents

- Independence and authority
- Evidence ladder
- Gate design
- Mechanism-grain adjudication and probe contradictions
- Deterministic checks before model judgment
- Qualification and reproducibility pack
- Readback and denominators
- Fix verification and invariance
- Baseline migration and closure chain
- Bounded builder-verifier loop
- Fused-plan verification
- Cross-surface and file-hot discipline
- Asynchronous relay sentinel
- Shared Relay Ledger optional profile
- Optional read-only watcher profile
- Blind forward testing
- False-PASS defenses
- Verifier report

Treat every public command sequence named by this playbook as a documented path: replay it in the published order from a clean environment and recheck protected state after each step, including optional commands.

## Independence and Authority

Separate builder and verifier whenever the change affects shared behavior, governance, safety, data, adapters, or release state. The verifier receives the specification, raw artifacts, and acceptance criteria, but does not inherit the builder's confidence or hidden intended answer.

The verifier may reject, request a concrete repair, or escalate an unresolved requirement. It may not silently redefine product intent or approve on behalf of the human sovereign.

## Evidence Ladder

Use the highest level actually reached:

```text
observed
-> source_verified
-> tool_verified
-> live_verified
-> human_baptized
```

Examples:

- a log says a command ran: observed;
- a primary specification supports a claim: source_verified;
- an isolated command and readback reproduce it: tool_verified;
- the real target host or carrier passes: live_verified;
- the final decision owner accepts it: human_baptized.

Never upgrade a claim because the narrative is detailed.

## Gate Design

Define before inspection:

- scope and authoritative sources;
- required and forbidden artifacts;
- machine-checkable done criteria;
- risk and side-effect boundary;
- exact test environment;
- acceptable assumptions and unresolved questions;
- rollback and stop condition.

Verify the smallest package that can close a point. Large undifferentiated reviews hide defects and create endless loops.

## Mechanism-Grain Adjudication and Probe Contradictions

Map sources and outputs at the actionable mechanism grain, not by similar wording, footer markers, or approximate section names. A source ID is retained only when its behavior, contract, or explicit archive decision exists in the destination.

For graphs and organizational views, verify relationships from serialized edges and contracts rather than visual proximity or indentation. Normalize model output at each read boundary and require every semantic state to execute its named check.

Before declaring a bug, probe the relevant rings independently: source/file, parser, runtime/server, carrier/API, client/UI, cache/index, and real external state. Contradictory probes localize the defect; they are evidence to investigate, not noise to smooth over.

Validate the validator. Exercise its positive and negative fixtures, explicit root, encoding, denominator, self-exclusions, and failure exit. Apply the same readback rule to verifier scripts, manifests, and report formats that the verifier applies to the product.

## Deterministic Checks Before Model Judgment

Prefer:

- parser, schema, lint, typecheck, and unit tests;
- exact file, hash, byte, count, and encoding checks;
- database or API reconciliation queries;
- browser assertions and screenshot/pixel inspection;
- citation and source-locator checks;
- policy-engine decisions;
- artifact and target-state readback;
- expected output comparison with atomic rubrics.

Use reflection or an LLM judge only for residual semantic questions. The judge-mitigation contract has its single home in [reference 07](07_observability_evals_opex_and_learning.md); this playbook requires deterministic evidence first.

## Qualification and Reproducibility Pack

Use this pack when a qualification crosses a host, process, language lane, renderer, toolchain, bridge, or published run path. It is the single normative home for `CL-20`. Do not require every field for a direct file-only check; declare non-applicable fields and the reason.

The pack contains:

- `DEPLOYMENT_ADDRESS_CARD`: concrete source and target addresses for every bridge, plus schema, identity, timeout, error surface, owner, and effect boundary;
- `PLACEMENT_ACCEPTANCE_PACK`: selected continuity and placement checks, terminal state, duplicate-effect count, recovery time, and artifact proof;
- `RUNTIME_DEPENDENCY_PREFLIGHT`: interpreter and runtime version, invocation mode, dependencies required and present, working directory, environment assumptions, encoding at every text boundary, capability probes, and `content_fail | environment_fail` classification;
- `LAB_READINESS_CONTRACT`: contract, execution, and evidence planes; non-agentic baseline; positive and negative fixtures; oracle class; manifests; secret boundary; denominators; readback; one authorized next variable; and `production_authorized: false` unless separately approved;
- `LANGUAGE_LANE_PARITY_CONTRACT`: lane owner, runtime, source root, test command, shared contracts, forbidden cross-calls, fixture set, artifact schema, parity property, evidence, and exit path;
- `TOOLCHAIN_VERSION_EVIDENCE`: supported minimum, locked resolution, tested snapshot, latest observed version, primary support source, compatibility result, verification date, invalidating change, and owner;
- `PARITY_PROPERTY_CONTRACT`: semantic invariants, structural schema, whether byte identity is required and why, normalization policy, tolerated variance, comparator, negative fixtures, and failure action;
- `REPOSITORY_STATE_CLASSIFICATION`: path class, canonicality, versioning, generator, recreation command, retention, secret eligibility, cleanup guard, manifest inclusion, and readback;
- `STABLE_EVIDENCE_ENVELOPE`: claim, check, denominator, hashes, and decision, with volatile telemetry carried separately;
- `LIVE_LANE_STATUS`: `NOT_CONFIGURED | NOT_RUN | PASS | FAIL | INCONCLUSIVE`, target, model or version, credential class, budget, timestamp, evidence, and promotion rule;
- `ANCHORED_EXPERIMENT_OVERLAY`: base release, anchor set, authorized delta, invariants, new variable, comparison oracle, collapse-to-baseline rule, and freeze chain;
- `OUTPUT_CLASSIFICATION`: `delivered | manifested | temporary | regenerable`, with retention, owner, hash policy, cleanup proof, and a prohibition on unknown outputs; and
- `TEXT_SOURCE_PLUS_VISUAL_SOURCE`: separate hashes and provenance for extracted text and visual material, including cover or layout notes; never claim PDF text was inspected when only images were read.

The documented public entrypoint is part of the product contract. Execute it from a clean directory without a hidden import path or prepared environment. Run the published commands in order, including optional report commands, and repeat protected-tree readback after every command rather than only at the end. For Python entrypoints that must not create bytecode, the documented invocation uses `-B`; a guard inside an imported module is only defense in depth. Inspect the entire protected companion tree because caches and unclassified outputs can appear along the import chain even when excluded from a source manifest.

`SK2-GUIDE-197` and `R-019` are one norm, not two features: interpreter, invocation mode, file decoding, source literals, stdout, and redirection encoding are part of the verification harness. On a textual mismatch, falsify harness, environment, current directory, and version defects before changing protected content. A corrected harness must rerun the same check and prove the content tree remained invariant.

Qualification gates include four cases:

- `POS`: the clean documented path passes with explicit denominators, classified outputs, stable evidence, and target readback;
- `NEG`: a hidden dependency, cross-lane call, unclassified output, cache mutation, unsupported version, or false live claim fails closed;
- `MALFORMED`: a parseable pack missing owners, denominators, parity property, encoding, manifest scope, or failure action is invalid; and
- `RECOVERY`: after an environment or harness failure, correct only the harness, rerun the original reproducer, reconcile side effects, and prove the protected baseline is unchanged.

## Readback and Denominators

Every PASS statement includes what was checked and the denominator:

```text
files checked: 23/23
required IDs assigned: 138/138
tests passed: 89/89
adapters matching canonical hash: 3/3
```

Read the destination, not only the command output. Verify absence claims with a scoped search. Verify deletions across file, metadata, cache, index, and UI. Verify that tests use isolated copies and cannot mutate installed artifacts.

## Fix Verification and Invariance

After a fix, prove the target defect is gone and the protected behavior is invariant. Re-run the narrow reproducer, relevant regression suite, neighboring contracts, negative cases, and source-to-output retention. Adapt an old test in spirit when architecture changes; do not delete its intent merely to make the suite green.

## Baseline Migration and Closure Chain

This is the single normative home for `CL-22`. A frozen baseline may change only through a machine-readable `BASELINE_MIGRATION_RECORD` containing authority, reason, source baseline hash, allowed paths or locators, exact before and expected after hashes, invariant set, historical-artifact policy, current-view rebuilds, verifier, effective gate, rollback, and supersession chain. Historical validators may accept only a signed, hash-bound, path-specific record; a generic `ignore drift`, rewritten historical baseline, or disabled gate is invalid.

No hash, append, or closure statement becomes evidence because it looks plausible or appears in a message. Generate it with a reproducible command, read back the physical target, and verify the relevant denominator. For append-only artifacts, also prove `MAX == LAST`, unique IDs, strict physical order, complete blocks, and the required final newline before advancing a checkpoint.

A closure anchor declares scope, hash algorithm, path ordering, path normalization, record and newline policy, excluded surfaces, and every derived surface such as manifests, companions, archives, or rendered artifacts. After human baptism, any authorized delta requires a bounded diff, forward and inverse coverage, a passing gate, a new anchor, and a recorded cascade across affected derivatives. Unchanged historical evidence remains immutable and points through the supersession chain.

The gate rejects an unsigned migration, a hash without target readback, an ambiguous ordering recipe, a partial derivative cascade, or a closure claim whose physical append order is inconsistent. Recovery resumes from the last valid anchor, replays only the authorized migration, rebuilds declared current views, and independently proves both the new closure and rollback to the source baseline.

## Bounded Builder-Verifier Loop

For each package:

1. builder declares scope, artifacts, hashes, checks, risks, and requested gate;
2. verifier independently reproduces high-risk claims and reports PASS or numbered findings;
3. builder applies only founded findings and records the readback;
4. close after at most two message rounds unless a real unresolved defect remains.

Do not exchange ceremonial acknowledgements that obscure ownership. A verifier finding names file, line or contract, severity, evidence, and a bounded correction.

## Fused-Plan Verification

For a fused plan, preserve independent drafts long enough to compare them. Create an improvement matrix, adjudicate differences at mechanism grain, mark every accepted delta, verify conflicts and omissions, and require builder/verifier signatures. Re-open only named deltas; do not silently replace the agreed authority with a later narrative summary.

## Cross-Surface and File-Hot Discipline

- Use orthogonal fresh readers for source fidelity, semantics, and operational behavior; remembered paths and familiar names are not provenance.
- Verify imports through independent source, destination, and final human-acceptance proof chains.
- Apply the same reusable verification contract to every agent or hat contribution, including safety behavior in an isolated runtime rather than by reading builder-authored tests alone.
- Treat an unhandled HTTP 500, swallowed stderr, or silent fallback as a defect, not harmless flakiness.
- Inspect visual work as a first reader on the rendered surface, not only through source code or extracted text.
- When a capability or label changes, sweep every UI, locale, adapter, guide, test, and source occurrence; recheck the missed surface plus a full source search.
- Treat product copy as an acceptance contract. Honest de-scope must remain visible, and cold-start or fallback failure must not be silenced.
- Verify that permanent constraints remain in policy, contracts, and regression tests after task completion.
- Before writing an append-only or shared file, reread the tail and MAX ID. If another writer changed the hot file, stop, reread, recompute the append, and verify physical order afterward.
- After a collision or restart, resume through a lightweight hook that reads the canonical state and proves its attachment before work continues.
- Do not install a candidate merely because carryover tests pass; installation has its own target readback, smoke, and rollback gate.
- Distinguish deterministic safety behavior from repetitive tone introduced by prompt-author anxiety; test both policy enforcement and product character.
- Never place real secrets in verifier fixtures or eval corpora; use recognizable fake patterns and prove scanner self-exclusions.

## Asynchronous Relay Sentinel

When collaboration uses an append-only message file, treat it as an event source:

```text
read physical MAX message ID
-> arm read-only sentinel from MAX
-> wait for a higher collaborator message
-> return ID, author, title, requests, and cited artifacts
-> consume the handoff
-> re-read physical MAX
-> rearm from the consumed ID
```

Requirements:

- the shared log is the source of truth;
- own outgoing messages advance the observed ID but do not complete the sentinel;
- timeout means no event, not PASS or failure by the collaborator;
- connection or watcher failure must terminate with an explicit error, never remain inertly `running`;
- watcher health is proven by comparison with the physical MAX, not process status alone;
- recovery rereads all missed blocks in order;
- the sentinel never writes to the shared log;
- a relay writer remains outside runtime unless independent use cases justify it.

The builder's Handoff, Agenda, and message log preserve cantiere continuity. They do not replace product runtime state.

## Shared Relay Ledger Optional Profile

The shared relay ledger is an optional append-only coordination pattern for a builder and an independent verifier. Activate it only when asynchronous handoff, restart recovery, or auditable physical ordering is necessary and a direct handoff cannot meet the acceptance requirement. Role ownership remains in [reference 03](03_operating_modes_hats_and_orchestration.md); durable product state and carrier recovery remain in [reference 05](05_runtime_state_bridge_data_security_and_reliability.md). This ledger is evidence transport, not application memory or authority.

Its contract declares ledger identity and path, canonical UTF-8/LF serialization, block schema, author identity, strictly increasing physical ID, optional block hash, writer ownership, checkpoint format, `MAX/LAST/EOF` checks, collision behavior, retention, recovery command, stop authority, and rollback. Before every append, the writer rereads the physical tail and maximum ID. If another writer changed the file, the pending append is discarded, recomputed against the new maximum, written once, and read back. A duplicate, skipped, truncated, reordered, or ambiguous block fails closed.

Required module cases:

- **E1 - effectiveness:** builder delivery and verifier response traverse the ledger in two complete, uniquely numbered blocks; both parties reproduce hashes, denominators, and the final physical order;
- **E2 - necessity:** repeat the handoff without the ledger using the simplest direct mechanism; keep this profile only when the accepted continuity or audit property is measurably lost;
- **E3 - failure injection:** inject a concurrent append, duplicate ID, out-of-order block, truncation, and missing final newline; the writer must stop without overwriting or silently renumbering another author's block; and
- **E4 - recovery:** after interruption, reread every block after the last consumed checkpoint in physical order, reconcile `MAX/LAST/EOF` and uniqueness, consume each complete handoff once, then bind and read back the new checkpoint.

## Optional Read-Only Watcher Profile

The read-only watcher is an optional pattern for an append-only coordination source. Activate it only when waiting latency or restart catch-up has an accepted requirement; otherwise use deterministic bounded polling or direct coordination. It never writes to the ledger, never grants authority, and never treats its own process state as proof of observation.

The profile binds the source identity, last consumed physical ID and optional hash, polling or event mechanism, backoff, timeout semantics, writer prohibition, catch-up range, rearm rule, error states, stop authority, and retained status evidence. An event is only a hint; the physical maximum is the truth. Health requires a successful source read plus comparison of checkpoint, `MAX`, `LAST`, uniqueness, order, complete EOF, and every higher block. Timeout means no new event. Connection loss, rate limiting, orphaned process, restart, ambiguous state, or unreadable source enters an explicit failed state and preserves the last valid checkpoint.

Required module cases:

- **E1 - effectiveness:** arm from the physical maximum, append one higher collaborator block, wake, return its ID, author, title, requests, and cited artifacts, consume it, and rearm from the read-back checkpoint;
- **E2 - necessity:** remove the watcher and run bounded polling against the same latency and continuity requirement; disable this profile when the simpler mechanism remains sufficient;
- **E3 - failure injection:** inject a stale event hint, missed higher ID, connection loss, rate limit, process restart, malformed block, and concurrent append; the watcher must not report healthy, PASS, or advance the checkpoint without physical catch-up; and
- **E4 - recovery:** restart from the last valid consumed ID, reread all higher blocks in order, prove attachment by matching the physical maximum, surface any gap once, and rearm only after the new checkpoint is read back.

## Blind Forward Testing

Use fresh workers or threads with the candidate skill and a realistic user task. Provide raw artifacts and minimum task-local context. Do not leak the expected architecture, suspected defect, or answer key.

Include:

- trigger and no-trigger tasks;
- three unrelated domains;
- deterministic workflow versus agent choice;
- AU4 recovery and R4 approval;
- malformed structured payload;
- malicious retrieved content;
- cross-host parity;
- simplest-baseline comparison.

Freeze fixtures and candidate versions. For a formal benchmark, use enough representative tasks to expose variance, repeat runs, and penalize unverified outcomes and unintended side effects.

## False-PASS Defenses

- A command exit code without target readback is insufficient.
- A test suite with unknown discovery count is insufficient.
- Parsed JSON with empty semantic payload is insufficient.
- A visually plausible PDF without render inspection is insufficient.
- A `running` watcher that missed a higher physical ID is failed.
- A model self-reporting tool use is insufficient.
- A second model seeing the expected answer is not independent.
- A successful happy path without retry, resume, denial, or rollback is incomplete.
- A claim based on stale vendor documentation remains pending.

## Verifier Report

Return:

```yaml
status: PASS | FAIL | BLOCKED
scope:
authorities_read: []
artifacts_checked: []
checks_run: []
denominators: {}
findings: []
reproduced_claims: []
unverified_claims: []
side_effects_observed: []
rollback_evidence:
next_gate:
```
