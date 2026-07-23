# Interoperability and Host Portability

Load this reference when selecting protocols, packaging the skill, generating host adapters, or installing the same canonical behavior across Codex, Claude Code/Cowork, and Google Antigravity.

## Table of Contents

- Layer boundaries
- Portability object and protocol boundary
- Agent Skill contract
- Instruction carriers and operational runbooks
- Canonical core and thin adapters
- Canonical contract, adapter, and carrier mapping
- Host targets
- Capability detection
- Dated capability and version evidence
- Adapter generation and parity
- Three-level host parity and promotion
- Installation and rollback
- Release engineering and publication gate
- Source freshness

## Layer Boundaries

| Mechanism | Solves | Does not solve |
|---|---|---|
| Agent Skills | Portable procedure and progressively loaded resources | Tool transport, identity, durable state, or orchestration. |
| MCP | Agent-to-tool, data, resource, and service access | Whole-system orchestration or identity governance. |
| A2A | Task and artifact exchange between independently deployed remote agents or services | Local subtask delegation that a host already supports. |
| ACP | Editor-to-agent interaction where supported | General remote service federation. |
| AGENTS.md, CLAUDE.md, host rules | Project and host instructions | Portable domain procedure by themselves. |

Choose protocols after process, trust, and deployment boundaries are known. Do not add A2A to local hats or MCP to a system that only needs a direct library call.

## Portability Object and Protocol Boundary

Classify each object by the responsibility it actually owns. A product may expose several objects; its marketing label is not a type.

| Object type | Owns | Boundary |
|---|---|---|
| Surface | Human interaction and presentation | Does not prove execution, state, or governance semantics. |
| Harness | Model, context, tools, and task conduction | Does not become the application runtime merely because it invokes tools. |
| Runtime | Execution lifecycle, state, effects, and recovery | Does not own portable doctrine or host discovery. |
| SDK | Construction primitives and client libraries | Does not supply an operating model by itself. |
| Framework | Programming model and composition conventions | Does not prove production readiness or host support. |
| Skill | Portable, progressively loaded procedure and resources | Does not transport tools or federate remote peers. |
| Instruction file | Host or project guidance loaded by a carrier | Does not become a protocol or a second canonical skill. |
| Tool protocol | Agent-to-tool, resource, or service transport | Does not transfer whole-task ownership between peers. |
| Agent protocol | Task and artifact exchange across an independent peer boundary | Does not justify multi-agent architecture by itself. |

Before selecting direct or native calls, MCP, A2A, or another carrier, complete a protocol-boundary decision card with:

- the task owner and the simplest direct or native baseline;
- whether the peer is independently deployed, opaque, or governed by another authority;
- lifecycle, identity, authorization, state, durability, streaming, error, and retry ownership;
- request, response, and artifact schemas, including compatibility and cancellation;
- evidence required for promotion and the exit path if the protocol adds no measured value.

Prefer direct or host-native invocation inside one trust and lifecycle boundary. Use a tool protocol for governed tool or resource access and an agent protocol only when an independently governed peer must own a task or artifact exchange.

Apply a homonym guard to overloaded terms. Record namespace, exact definition, authority source, version, and intended object type. A carrier field named `AgentSkill`, for example, must not be treated as the same object as an Agent Skills package without an explicit mapping.

Single-home rule:

| Concern | Normative home |
|---|---|
| Portability taxonomy, host discovery, carrier mapping, adapter parity, and release packaging | This reference. |
| Runtime effects, sessions, auth, secrets, retry, and recovery | [Reference 05](05_runtime_state_bridge_data_security_and_reliability.md). |
| Team topology, delegation, and coordination | [Reference 03](03_operating_modes_hats_and_orchestration.md). |
| Permission delegation, human approval, and sovereignty | [Reference 04](04_governance_autonomy_risk_approval_and_rollback.md). |
| Reports and evaluation operations | [References 06](06_reports_artifacts_and_visual_qa.md) and [07](07_observability_evals_opex_and_learning.md). |
| Independent verification and blind replay | [Reference 10](10_verifier_playbook.md). |
| Dated framework, product, model, and vendor inventory | [Reference 11](11_system_planes_and_stack_selection.md). |

Cross-links never create a second implementation.

## Agent Skill Contract

For the current portable package:

- directory name and frontmatter `name` match;
- name uses lowercase letters, digits, and single hyphens and stays within 64 characters;
- description states capability, positive triggers, and exclusions and stays within 1024 characters;
- optional top-level `compatibility` stays within 500 characters;
- optional `metadata` carries release version without owning doctrine;
- `SKILL.md` remains below 500 lines and targets less than about 5000 tokens;
- detailed resources are directly routed from `SKILL.md`, one level deep;
- text files are UTF-8 without BOM;
- no README, changelog, build history, or vendor ranking enters the installable runtime merely for convenience.

Use the current primary specification when a bundled validator disagrees. Record the divergence and test the real host rather than silently weakening the canonical core.

## Instruction Carriers and Operational Runbooks

Keep three layers separate:

| Layer | Content | Change rule |
|---|---|---|
| Canonical skill | Portable procedure, router, hard stops, and resources | Change once in the canonical package. |
| Host instruction file | Thin project or host guidance, import, pointer, or invocation mapping | Derive from current host capability; do not fork doctrine. |
| Operational runbook | Procedure, decision tree, edge cases, fallback, escalation, observability, definition of done, and verified lessons for one operating context | Compose from governed contracts; do not copy the skill. |

An instruction file such as `AGENTS.md`, `CLAUDE.md`, or another host guide is an instruction carrier, not a tool or agent protocol. Prefer one governed source with thin imports or generated host mappings where the live host supports them. Import syntax, precedence, nesting depth, path behavior, symlink support, and size limits are dated capability data and must be detected before use.

A runbook is an optional operational profile, not an automatically required new artifact. When justified, compose it from the existing agent-hat, run-manifest, autonomy/risk, and acceptance contracts. It must declare owner, scope, prerequisites, steps, decision points, fallback, escalation target and timing, minimum observability, completion evidence, rollback, and a governed lessons record. If those fields already live in referenced canonical artifacts, link them rather than duplicating them.

Unknown host support enters:

```yaml
status: PENDING_CAPABILITY_DISCOVERY
capability:
evidence_request:
owner:
deadline:
affected_decision:
fallback_allowed: false
```

Do not copy to a likely path, invent an import, or weaken the canonical contract while this state is pending.

## Canonical Core and Thin Adapters

Use:

```text
canonical skill directory
-> capability detection
-> generated Codex adapter metadata
-> generated Claude adapter metadata or hooks when justified
-> generated Antigravity adapter metadata when documented
-> byte and behavior parity checks
```

Adapters may map discovery paths, metadata, permission declarations, hooks, or invocation syntax. They may not fork triage, governance, risk, output, or provenance semantics.

## Canonical Contract, Adapter, and Carrier Mapping

Changes follow one direction:

```text
modify and verify canonical contract
-> regenerate adapters
-> install into an isolated target
-> read back payload and discovery
-> verify carrier and behavioral parity
```

Stop if an adapter contains a normative rule absent from the canonical core or if a host-only edit would become the source of portable behavior.

Keep canonical contract identity separate from its transported name:

```yaml
canonical_contract_id:
resolved_version:
canonical_schema_fingerprint:
carrier:
wire_name:
wire_schema_fingerprint:
normalizer:
compatibility_rule:
collision_check:
owner:
evidence_locator:
```

For model or provider adapters, additionally declare provider, wire version, endpoint allowlist, auth carrier, model resolved at runtime, continuation contract, stop and error mapping, retry owner, and secret-redaction evidence. This reference owns the portability mapping; reference 05 owns the runtime, secret, retry, and effect semantics.

A carrier-parity contract declares the canonical schema, normalizer, allowed envelope and lifecycle differences, semantic hash, security invariants, and positive and negative cases. API, MCP, A2A, or another carrier may format the exchange differently, but normalization must recover the same governed meaning. A matching wire name or parseable envelope is not parity.

## Host Targets

Facts verified for this release are recorded in the outer `P2_HOST_TARGETS.yaml`. Current targets include:

| Host | Global target | Project target | Evidence state |
|---|---|---|---|
| Codex | `$HOME/.agents/skills/multi-agent-system-architect-v2` | `$REPO_ROOT/.agents/skills/multi-agent-system-architect-v2` | Targets verified against the current Codex manual; V2 uses a separate target so the installed V1 remains intact. |
| Claude Code/Cowork | `~/.claude/skills/multi-agent-system-architect-v2` | `<repo>/.claude/skills/multi-agent-system-architect-v2` | V2 uses separate global and project targets; verify discovery before release. |
| Google Antigravity | `~/.gemini/config/skills/multi-agent-system-architect-v2` | `<workspace>/.agents/skills/multi-agent-system-architect-v2` | V2 uses separate targets; reverify current host support before release. |

Paths are capability data, not eternal doctrine. Re-read before installation and test discovery on the installed version.

## Capability Detection

Before generating or installing an adapter, detect:

- host and version;
- supported skill directory and precedence;
- accepted frontmatter and metadata;
- project versus global discovery;
- available shell, filesystem, web, subagent, MCP, and document capabilities;
- permission and approval model;
- hooks, agents, and UI metadata support;
- path, encoding, symlink, and network restrictions.

Run a `RUNTIME_SEMANTICS_CHECK` before claiming portability across function tools, hosted tools, MCP tools, handoffs, approvals, guardrails, and sessions. Record which controls apply to which carrier, where they run, interaction limits, and every unsupported combination. Reference 05 remains the normative home for their runtime and effect semantics.

Unknown means pending, not assumed. Degrade by omitting host-only metadata or by handing off the unavailable lane; do not change the canonical behavior contract.

## Dated Capability and Version Evidence

Classify every portability claim before using it:

| Claim class | Allowed use |
|---|---|
| `EVERGREEN_NORMATIVE` | Stable boundary, invariant, or decision rule supported strongly enough for this reference. |
| `DATED_CAPABILITY` | Product, host, feature, path, version, maturity, limit, or support claim with source and review clock. |
| `OPTIONAL_OPERATIONAL_PROFILE` | Runbook, carrier, packaging, or deployment pattern activated only when its trigger and tests pass. |
| `PROJECT_EVIDENCE` | Scoped observation that may motivate a rule but never becomes a universal guarantee. |
| `CROSS_REFERENCE_ONLY` | Evidence or mechanics whose normative home is another reference. |

Maintain capability identity independently from display names and catalog rows:

```yaml
claim_id:
claim_class: DATED_CAPABILITY
canonical_entity_id:
surface_id:
alias_of:
object_type:
capability_or_feature:
scope_or_region:
spec_version:
package_release:
wire_version:
site_label:
maturity:
authority:
source_locator:
observed_at:
expires_or_reverify_at:
drift_status:
```

`stable`, `GA`, `RC`, `preview`, `beta`, `EOL`, `absorbed`, and `renamed` are distinct, dated states. A stable runtime does not imply that every feature is stable. Repository release, package release, document version, wire version, site banner, and capability version are separate fields and must not be substituted for one another.

A framework capability card records access date, version, host and language scope, supported capabilities, strengths, cautions, maturity, evidence, unknowns, adoption fit, credential handling, and network exposure. Compare capabilities and constraints, not popularity or a compensatory ranking. A prototype tier, personal host surface, or parent runtime never inherits production governance or feature maturity automatically.

For host team capabilities, also record topology, task ownership and dependencies, peer messaging, claim or file locking, plan approval, hook gate behavior, permission authority, delegation limits, and experimental status. Reference 03 owns the coordination pattern and reference 04 owns approval authority; the capability card only reports what the dated host supports.

When official sources disagree, preserve a normative-source drift record containing each locator, authority, observed field and value, maturity, observation date, conflict class, decision, and freshness deadline. Do not silently choose the convenient source or claim equivalence between distinct taxonomies; publish an explicit many-to-many crosswalk when mapping is necessary.

Specific framework lists, vendor features, adoption counts, current versions, and host maturity belong to the dated catalog in reference 11. This reference owns the evidence contract and freshness gate, not those volatile entries.

## Adapter Generation and Parity

Generate adapters from a typed manifest. Embed canonical skill name, version, and source fingerprint. Recreate rather than hand-edit adapters.

CI or the release verifier executes parity checks on every generated adapter and fails on canonical hash or behavior drift.

Parity checks verify:

- every adapter points to the same canonical version and hash;
- no normative text exists only in a host pack;
- host-specific permissions remain least privilege;
- default prompt and trigger behavior preserve scope and hard stops;
- the same blind tasks produce equivalent Mode/AU/R decisions and artifacts;
- stale or unsupported fields fail with an actionable message.

Carrier-specific formatting may differ; semantics and safety may not.

## Three-Level Host Parity and Promotion

Record three independent evidence levels for every host:

| Level | Required evidence | States |
|---|---|---|
| Payload | Canonical file set, byte counts, hashes, tree fingerprint, and declared exclusions | `PASS`, `FAIL`, `NOT_RUN` |
| Discovery | Installed path, host detection, fresh-session discovery, readback, and invocation | `PASS`, `FAIL`, `NOT_RUN` |
| Behavior | Frozen corpus, equivalent decisions and artifacts, negative cases, and recovery behavior | `PASS`, `FAIL`, `NOT_RUN`, `INCONCLUSIVE` |

Byte-identical directories do not prove discovery, and discovery does not prove behavior. Never inherit a higher-level PASS from a lower level.

Canonical payload manifests and install or parity fingerprints must exclude declared runtime-generated cache directories and transient bytecode such as `__pycache__`, `*.pyc`, and `*.pyo`. The exclusion set is explicit and reported separately. It never authorizes an unknown payload file: every unexpected non-excluded file is drift and fails closed. Verification tools must not contaminate the tree they attest.

An installation sentinel test may add a temporary, unmistakable test rule to an isolated target, open a fresh host session, verify discovery through the expected behavior, remove the sentinel, and read back its removal. Do not leave the sentinel in the canonical package or treat a prose acknowledgement as proof.

Remote interoperability promotion requires:

```yaml
gate: REMOTE_INTEROP_PROMOTION
live_baseline:
parity_scope:
failure_budget:
rollback:
result: NOT_RUN | PASS | FAIL | INCONCLUSIVE
```

A local carrier normalization test cannot replace a live baseline. Reference 10 owns blind comparison and independent adjudication; this reference owns the promotion prerequisite and host evidence boundary.

## Installation and Rollback

Never install from staging. After PM gate:

1. re-detect target path and host capability;
2. fingerprint source and existing target;
3. back up or version the existing target;
4. copy atomically or use a verified symlink where supported;
5. read back every file and fingerprint;
6. run host discovery and a no-side-effect smoke test;
7. record installation evidence;
8. prove rollback to the prior target.

Do not modify installed v0.x baselines during candidate construction.

## Release Engineering and Publication Gate

Version the canonical skill, adapter set, dated catalog, and distributable release separately. Every adapter and release binds the exact canonical version and hash it carries.

For a catalog:

- a breaking change alters schema, identity, or field meaning;
- a minor change adds backward-compatible fields, entities, or capabilities;
- a patch refreshes or corrects evidence without changing schema or meaning.

For adapters and the canonical skill, classify compatibility against their own public contracts rather than copying the catalog version.

A release manifest records:

- canonical version, bytes, hash, and payload tree;
- adapter version and hash for each host;
- catalog version and freshness date;
- compatibility and migration decision;
- validation date and environment;
- license and attribution result;
- secret scan and sanitation result;
- documentation and final-link checks;
- payload, discovery, and behavioral parity evidence;
- evaluation and release-report locators;
- exact rollback target and readback procedure.

Never publish or install directly from staging. Build into an isolated release directory, verify it, and promote atomically. A `current` pointer, symlink, or equivalent is an optional carrier-specific mechanism and is permitted only after capability detection and rollback proof.

Keep changelogs, build history, and release reports outside the installable runtime unless they are required runtime resources. Reference 06 owns report artifacts, reference 07 owns evaluation operations, reference 05 owns secret and runtime controls, reference 10 owns independent release verification, and reference 11 owns the dated catalog.

A publication gate fails closed unless license, secret scan, canonical-to-adapter parity, required documentation, final links, install/discovery smoke tests, behavioral evidence, and rollback all pass or have an explicit human disposition.

## Source Freshness

Use primary sources for technical claims. Record locator and verification date. Reverify protocol versions, host paths, metadata, permissions, security behavior, and deprecations before material choices. Model, price, and vendor-capability inventory has its single home in the dated catalog governed by reference 11.
