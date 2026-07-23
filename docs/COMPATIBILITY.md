# Compatibility

Compatibility is a claim about a specific carrier, host version, and evidence level—not a promise that every agent behaves identically.

## Release support matrix

| Surface | Carrier | Status | Installation |
|---|---|---|---|
| Codex desktop/CLI | Codex plugin or direct Agent Skill | Carrier and format qualified; 2.1.2 live gate pending | Marketplace or tagged Skill URL |
| Claude Code | Claude plugin or direct Agent Skill | Carrier and format qualified; 2.1.2 live gate pending | Marketplace or copy to `.claude/skills` |
| Claude Chat/Cowork | Account plugin or ZIP Skill | Carrier and format qualified; 2.1.2 live gate pending | GitHub marketplace or release ZIP upload |
| Google Antigravity IDE | Direct Agent Skill or local plugin | Carrier and format qualified; 2.1.2 live gate pending | Copy tagged folder and use a fresh conversation |
| Cursor | Agent Skill / Remote Rule | Format-compatible; 2.1.2 live gate pending | GitHub Remote Rule or tagged folder |
| Other Agent Skills hosts | Direct Agent Skill | Capability-dependent | Follow the host's official path and verify |

Exact host versions and gate annotations live in [Release evidence](RELEASE_EVIDENCE.md).

Live receipts created for the private 2.1.1 payload identify different bytes. They are historical evidence only and are not inherited by 2.1.2.

## Portability invariants

Every carrier must preserve:

- canonical doctrine and decision gates;
- one-host independence;
- optional—not mandatory—collaboration;
- authority, risk, and rollback semantics;
- required references, templates, schemas, scripts, and public evaluations;
- the Skill name and discovery intent.

Adapters may change paths, invocation syntax, namespace, and metadata length. They may not silently grant permissions, merge sandboxes, or fork doctrine.

## What is not portable

The repository does not promise identical:

- host tool names;
- approval UI;
- sandbox boundaries;
- model behavior;
- hot-reload behavior;
- global installation paths;
- plugin marketplace mechanics.

Each host remains responsible for its own permissions and execution controls.

## Version drift

Official host paths and plugin formats are time-sensitive. If current documentation conflicts with this repository:

1. prefer the host's current official documentation for the carrier;
2. preserve the Skill's governance semantics;
3. open a compatibility issue with source URL and access date;
4. do not call the host supported until a fresh identity/discovery/behavior gate passes.
