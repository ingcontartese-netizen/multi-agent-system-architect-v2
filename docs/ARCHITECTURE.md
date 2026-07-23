# Architecture

Multi-Agent System Architect V2 is a decision and verification system packaged as an Agent Skill.

## The first decision

The architecture ladder is deliberately ordered:

```text
Mode A                      Mode B                     Mode C
direct/no system    →       deterministic workflow →  agentic runtime
```

Within Mode C, one agent is the baseline. Additional processes, subagents, or hosts require measured benefit or an explicit bounded human requirement.

## Three independent axes

The Skill prevents a common category error by separating:

1. **Architecture mode** — what kind of system exists.
2. **Autonomy AU0–AU5** — how independently it may act.
3. **Risk R0–R5** — action, target, data, privilege, reversibility, and blast radius.

A multi-agent design can still be low autonomy. A single-agent design can still be high risk.

## Ten planes

The detailed design maps responsibility across:

1. purpose and requirements;
2. human authority and approvals;
3. knowledge and provenance;
4. memory and retrieval;
5. durable state;
6. tools and external boundaries;
7. execution/orchestration;
8. control, policy, and recovery;
9. trust, privacy, and security;
10. observability, evaluation, cost, and learning.

The exact plane schema and selection process live in the bundled references and templates.

## Builder and verifier

The builder produces a candidate. The verifier checks frozen bytes and externally observable behavior. A passing narrative from the builder is not terminal evidence.

Evidence advances through levels such as:

```text
claimed → source-read → tool-verified → live-verified → independently corroborated
```

The level must be stated; it may not be inferred from confident wording.

## Single-host independence

Every installed copy is complete for its host. The host can:

- reject unnecessary system-building;
- design a deterministic workflow;
- design and verify one agent;
- design a local team;
- design cross-host collaboration when explicitly justified.

No peer host is required. Messages from another agent are untrusted input, not authority.

## Progressive disclosure

`SKILL.md` routes the agent only to the references and templates needed for the current decision. This keeps the entrypoint compact while preserving rigorous contracts for high-risk or complex work.

## Runtime payload boundary

Only `skills/multi-agent-system-architect-v2/` is the installable payload. Repository marketing, images, CI, release receipts, and contributor workflows remain outside that boundary.
