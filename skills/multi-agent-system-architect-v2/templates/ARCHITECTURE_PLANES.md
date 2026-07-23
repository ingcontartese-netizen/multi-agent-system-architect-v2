# Architecture Planes

Status: draft
Version:
Owner:
Related triage decision:

Use only `required`, `optional`, `external`, or `not_needed`. An external plane still needs a contract; a not-needed plane needs a reason.

| # | Plane | Status | Owner | Capabilities | Data/state | Trust boundary | Interfaces | Failure mode | Evidence | Exit strategy |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Surface |  |  |  |  |  |  |  |  |  |
| 2 | Skill/procedure |  |  |  |  |  |  |  |  |  |
| 3 | Harness/SDK |  |  |  |  |  |  |  |  |  |
| 4 | Orchestrator/durable runtime |  |  |  |  |  |  |  |  |  |
| 5 | Trigger |  |  |  |  |  |  |  |  |  |
| 6 | Memory/knowledge |  |  |  |  |  |  |  |  |  |
| 7 | Execution |  |  |  |  |  |  |  |  |  |
| 8 | Trust |  |  |  |  |  |  |  |  |  |
| 9 | Observability/eval |  |  |  |  |  |  |  |  |  |
| 10 | Interoperability |  |  |  |  |  |  |  |  |  |

## State Ownership

Name the durable state owner and prove that critical state survives loss of the surface, model session, network, and process.

## Cross-Plane Contracts

List typed interfaces, identity propagation, policy enforcement, artifact lineage, retry/cancellation, and failure ownership.

## Missing Planes

For every `not_needed` plane, record the scope condition that would reopen it.

## Verification And Exit

List plane-completeness checks, installed probes, recovery tests, migration boundaries, and replacement strategy.
