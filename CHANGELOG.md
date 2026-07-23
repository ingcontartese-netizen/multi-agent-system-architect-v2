# Changelog

All notable public changes are documented here. The project follows semantic versioning for the installable Skill payload.

## [2.1.2] - 2026-07-23

### Added

- Public GitHub distribution for Codex, Claude Code/Cowork, Antigravity, Cursor, and compatible Agent Skills hosts.
- Codex and Claude plugin marketplace manifests.
- Deterministic release tooling, checksums, public evidence, and multi-runtime CI.
- Apache-2.0 license, attribution, security policy, installation guides, and portability notes.

### Changed

- Unified the discovery description to a portable sub-200-character form so the same Skill payload can serve filesystem and Cowork carriers.
- Replaced private project case labels with neutral public case descriptions.
- Removed opaque build-ledger identifiers that had no public resolver.
- Strengthened public hygiene checks so legacy internal markers fail closed.

### Security

- No change to the Skill's permission model: each host remains an independent trust boundary and teams remain optional.

### Evidence boundary

- Public static, behavioral, and security qualification was rerun on the exact 2.1.2 payload.
- Live host gates from the private 2.1.1 delivery do not transfer to 2.1.2. Release-specific live gates remain pending until separately executed and recorded.

## 2.1.1 - 2026-07-22 (private baseline)

- Added the independent-host contract and made single-host operation explicit.
- Completed live gates for a private delivery. Those receipts identify different bytes and are not evidence for the public 2.1.2 release.

[2.1.2]: https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/releases/tag/v2.1.2
