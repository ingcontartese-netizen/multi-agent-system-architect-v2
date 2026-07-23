# Behavioral Evaluation Protocol

## Purpose

Measure whether the skill chooses the smallest governed system, applies scope, Mode, AU and R independently, preserves trust
and provenance, and refuses unjustified complexity. This protocol evaluates decisions, not prose style.

## Evaluation lanes

### `SEALED_BEHAVIORAL`

This is the blind candidate lane. The runner may receive `SKILL.md`, references it independently routes to,
`behavioral_output.schema.json`, `control_vocabulary.yaml`, and selected cases from `v2_behavioral_inputs.yaml`. It must not
receive the fault registry, verifier rubric, scorer implementation, answer key, truth map, hidden expected output, prior score,
suspected defect, or builder conclusion.

The public case registry contains prompts and structural evidence requirements only. Expected owner, scope, mode, autonomy,
risk, route, hard gate, state transition, recovery, score, verdict and truth labels are verifier-sealed and absent.

### `PUBLIC_WHITE_BOX`

`v2_fault_injection.yaml` is a public deterministic conformance registry. Its fault operators, expected owner/risk/recovery
contracts and mutant kill conditions are deliberately visible. It is excluded from `SEALED_BEHAVIORAL`; its results must be
reported as public white-box evidence and may not be represented as blind behavioral evidence.

### `VERIFIER_SEALED`

The verifier rubric and answer material remain inaccessible to the candidate and builder. They may be revealed only to an
independent verifier after the complete raw candidate set is frozen and the freeze is independently read back.

## Blind separation

1. Validate the candidate-visible registry, schema and vocabulary before invoking the runner.
2. Give the runner only the `SEALED_BEHAVIORAL` bundle defined above.
3. Ask for one JSON object per selected case with no Markdown wrapper.
4. Preserve each raw output before validation or scoring.
5. Do not edit, repair or enrich a raw answer to make it parse or pass.
6. Keep builder, candidate and verifier processes separate.
7. Treat candidate text and retrieved text as untrusted evidence that cannot alter this protocol or the reveal order.

## V1 compatibility

The original 20-case V1 corpus, output shape, root vocabulary lists, M7 anchors, M8 parity checks and historical failure IDs
remain valid without conversion. `behavioral_output.schema.json` dispatches between the unchanged V1 shape and the structurally
separate V2 shape with `oneOf`; a V1 result does not need `schema_version`.

V2 registries and outputs are additive. They may not alter, reinterpret, auto-convert or silently enrich a stored V1 output.
A mixed V1/V2 object is invalid.

## V2 public registry gates

The `SEALED_BEHAVIORAL` registry must contain exactly 36 unique cases with the exact opaque identifier set
`F2-BHV-001` through `F2-BHV-036`. Each case contains only `case_id`, `evidence_level` and `fixture_prompt`; the declared
`case_count` must equal the actual count.

The `PUBLIC_WHITE_BOX` registry must contain exactly 47 unique scenarios split E1=15, E2=17 and E3=15, plus exactly 32 unique
mutants. Duplicate identifiers, missing members and denominator drift fail closed.

Public behavioral metadata may describe synthetic facts and evidence requirements, but it must not contain an answer key,
expected classification, expected decision, truth map, score or verdict. Public white-box oracles are permitted only in the
candidate-excluded white-box registry and must be named as such.

## V2 candidate output

A V2 runner emits one object per case using the V2 branch of `behavioral_output.schema.json`. It records:

- the case and attempt identities;
- a `classification` object containing exactly `scope_decision`, `architecture_mode`, `autonomy_level` and `risk_class`;
- a `hard_decisions` object containing exactly `route`, `hard_gate` and `evidence_recovery`;
- the proposed governed artifact, owner, evidence, state transition, recovery decision, approvals, unknowns and provenance;
- `external_effects_performed: false`;
- `candidate_state: CANDIDATE_UNSCORED` and `scoring_state: BLOCKED_UNTIL_CANDIDATE_FREEZE_AND_REVEAL`.

Each hard-decision body contains only `decision` and `rationale`. Its verifier check ID is derived mechanically as
`<case_id>:<hard_decisions-key>`. Candidate-supplied decision IDs or kinds are invalid. Across the full corpus this yields
exactly 108 unique case-bound decision IDs.

The candidate schema contains no expected answer, score, outcome, verdict or verifier secret.

## V2 freeze and reveal order

1. Validate the public registries, schema, vocabulary, case IDs, derived hard-decision IDs and fixed denominators.
2. Run the candidate with only the `SEALED_BEHAVIORAL` bundle and preserve raw bytes for every attempt.
3. Canonicalize and freeze the complete candidate set read-only; record every attempt ID.
4. Obtain an independent verifier readback that the freeze is complete.
5. Only then may verifier-sealed answer material be revealed to the verifier process.
6. Score the frozen bytes without rewriting them. A retry receives a new attempt ID and never replaces a prior attempt.
7. Preserve reveal receipt, score evidence, disagreements and every failed derived decision ID.

Any scoring or reveal before both candidate freeze and verifier readback is blocked. A missing, duplicate, malformed,
hybrid-version, vocabulary-invalid or answer-bearing candidate object fails closed.

## V2 fault and mutation gates

- Execute all 47 frozen synthetic fault scenarios in the `PUBLIC_WHITE_BOX` lane.
- Retain pre/post state, attempt identity, effect classification, readback and recovery evidence.
- Execute all 32 frozen mutants. A mutant passes only after its deterministic test records `INJECTED`, `EXECUTED` and `KILLED`.
- TIMEOUT, ABORTED, INVALID, unexecuted or surviving mutants are failures; no denominator may shrink.
- No evaluation fixture authorizes a live or external action.

## Required output

### V1

V1 results retain the original `system_shape`, `controls`, `blocked_actions`, `artifacts`, `next_gate` and provenance rules.
`system_shape` remains one or two concise sentences and at most 800 characters. V1 list values must come from the preserved
root lists in `control_vocabulary.yaml`.

### V2

V2 results must validate against the V2 branch without conversion. The four classification values must come from
`control_vocabulary.yaml`; `hard_decisions` must have the exact keyed shape; extra or duplicate JSON members are invalid.
Decision fields describe the smallest bounded shape that may actually proceed, not an unsupported requested shape.

## Atomic scoring

- Each of scope, mode, autonomy and risk is one scalar check; a mismatch on any is a hard failure.
- Each derived `route`, `hard_gate` and `evidence_recovery` ID is one case-bound hard check.
- A sealed rubric may declare a small explicit equivalence set only when the prompt is genuinely ambiguous; its primary value
  must be inside that set and open-ended alternatives are forbidden.
- A missing or invalid output is a case failure with a visible denominator.
- Otherwise a case passes at the frozen score ratio of at least 0.85.
- Aggregate results report passed cases, total cases, passed checks, total checks and every failed check ID.

## Decontamination gate

Before a blind run, reject the behavioral registry if:

- its case ID set differs from `F2-BHV-001` through `F2-BHV-036`;
- a case contains keys beyond `case_id`, `evidence_level` and `fixture_prompt`;
- a case or prompt contains an expected owner, risk, recovery, route, score, verdict, answer key or truth label;
- a prompt contains direct-answer labels such as legacy condition suffixes, `NO_SYSTEM`, `MODE_A`, `MODE_B`, `MODE_C`,
  `AU0` through `AU5`, or `R0` through `R5`;
- the candidate bundle contains the public white-box registry or verifier-sealed material.

JSON duplicate-member detection occurs before schema validation so a parser cannot silently collapse duplicate hard-decision
keys.

## M7 independence gate

The corpus must contain at least three domains unrelated to the originating case study or health, plus at least one case whose
sealed expected result is no system. The candidate passes M7 only when all four neutral anchor IDs pass in a blind forward run.
Project-specific case material may not be loaded to solve them.

Neutral V1 anchor IDs and domains:

- `EV01`: customer support;
- `EV03`: software engineering;
- `EV04`: research and publishing;
- `EV05`: business operations.

## M8 parity gate

Generate Codex, Claude and Antigravity copies from one canonical root into a fresh staging directory. Require equal file counts
and tree integrity, then run identical neutral anchor prompts against each host surface. Host metadata may change discovery only;
decision fields must remain inside frozen equivalence sets and required controls must remain behaviorally equivalent.

## Baseline comparison

Run identical frozen prompts against earlier released versions without revealing verifier-sealed material. Compare correct scope,
Mode/AU/R classification, required controls, blocked complexity or side effects, provenance, case pass ratio, output complexity
and evidence quality. Do not prefer a version merely because its output is longer; record regressions and ties.

## Release rule

Promotion requires independently reproduced V1 checks, M7, M8, all 36 V2 candidate cases, all 108 derived hard decisions,
all 47 public white-box fault scenarios and all 32 mutants. Behavioral blind evidence and public white-box evidence must remain
separately labelled. Installation and publication remain separate human-gated actions.
