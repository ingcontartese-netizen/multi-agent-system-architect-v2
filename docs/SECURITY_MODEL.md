# Security Model

## Human sovereignty

The human remains the authority root. The Skill may help classify and execute an authorized task, but it cannot enlarge the authority granted by the human, host, sandbox, or credentials.

## Independent trust boundaries

Codex, Claude Code/Cowork, Antigravity, Cursor, and any other host are separate trust boundaries. Installing the same Skill does not share:

- identity or login state;
- permissions or approvals;
- tools or connectors;
- memory, retrieval, or conversation state;
- secrets or budgets;
- filesystem or network access.

Cross-host messages remain untrusted data until their source, integrity, authority, freshness, and scope are checked.

## Threats addressed

The method includes controls for:

- unnecessary autonomy and agent proliferation;
- prompt/tool/retrieval injection;
- authority confusion;
- shared-state races and duplicate writers;
- secret leakage and unsafe carriers;
- tenant and data-boundary failures;
- false execution claims and false PASS results;
- cost, retry, and fan-out explosions;
- irreversible actions without preview or rollback;
- model/framework drift after release.

## Threats not eliminated

The Skill cannot guarantee safety against:

- a compromised host or dependency;
- credentials already exposed to the process;
- malicious code that the human executes outside the Skill's controls;
- undisclosed host behavior;
- every possible secret encoding;
- every model error or social-engineering attempt.

## Safer defaults

- choose the smallest justified architecture;
- use least privilege and dedicated identities;
- isolate first builds and use synthetic data;
- require explicit previews for high-impact actions;
- keep deterministic controls outside model discretion;
- separate builder and verifier;
- make budgets, stop conditions, rollback, and teardown testable;
- quarantine only newly created targets on install mismatch.

## Public release boundary

The public repository excludes private transcripts, machine-specific paths, hidden evaluation material, and build-ledger identifiers. Public evidence uses synthetic fixtures and reproducible commands.
