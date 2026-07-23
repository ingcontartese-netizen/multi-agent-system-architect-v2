# Contributing

Thank you for improving Multi-Agent System Architect V2.

## Before opening a change

1. Open an issue describing the problem, host, and expected evidence.
2. Keep the installable payload under `skills/multi-agent-system-architect-v2/`.
3. Do not mix repository documentation into that payload.
4. Do not add agents, protocols, frameworks, or dependencies without a measured necessity case.
5. Never include credentials, private transcripts, local paths, hidden evaluation material, or customer data.

## Pull-request contract

Every pull request must state:

- scope and non-scope;
- risk and affected trust boundaries;
- files changed;
- tests and denominators;
- rollback;
- compatibility impact;
- whether the payload identity changes.

Run from the repository root:

```powershell
python -B tools/verify_release.py --repo .
```

When the Skill payload changes, update its semantic version, release manifest, evidence, and deterministic ZIP. A builder may not self-declare the terminal verification gate.

## Public evidence only

Public tests may contain synthetic fixtures and transparent mutation cases. Do not add private answer keys, hidden rubrics, sealed scorer outputs, or internal message logs to the repository.

## Style

- Use plain, testable language.
- Separate normative requirements from examples.
- Cite official, dated sources for time-sensitive host claims.
- Keep host adapters thin; they may change discovery metadata, not doctrine.
