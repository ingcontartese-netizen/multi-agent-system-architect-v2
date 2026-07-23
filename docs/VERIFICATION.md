# Verification

The release process is designed to make false PASS results difficult.

## Evidence layers

1. **Source identity** — deterministic inventory and tree hash.
2. **Static contracts** — schema, links, versions, payload boundaries, and public hygiene.
3. **Behavioral tests** — public cases and structured output checks.
4. **Fault and mutation tests** — injected defects must execute and be killed by the expected control.
5. **Security matrix** — generator, parity, scanner, entropy, and portable-path cases.
6. **Release packaging** — deterministic ZIP, safe paths, no symlinks/caches, checksum readback.
7. **Host gate** — fresh-session discovery, invocation, behavior, and post-test invariance.
8. **Independent readback** — a verifier other than the builder reproduces the result.

## Local verification

From a repository checkout:

```powershell
python -B tools/verify_release.py --repo .
```

The verifier reads `release/PUBLIC_RELEASE_MANIFEST.json`, validates the repository wrapper, and calls the versioned Skill tooling.

To run the Skill checks directly:

```powershell
cd skills/multi-agent-system-architect-v2
python -B scripts/source_manifest.py . --json
python -B scripts/quick_validate.py . --profile public-only --json
python -B scripts/secret_scan.py . --json
python -B scripts/secret_scan.py . --entropy --json
python -B scripts/security_matrix.py . --json
python -B -m pytest -q
```

Use the exact arguments recorded in [Release evidence](RELEASE_EVIDENCE.md) when reproducing a tagged release.

## Deterministic archives

Build release assets only from a clean repository checkout:

```powershell
python -B tools/build_release.py --repo . --out dist
python -B tools/verify_release.py --repo . --dist dist
```

The builder writes stable ZIP timestamps and ordering. The verifier rejects:

- absolute paths and traversal;
- multiple roots;
- duplicate or case-colliding entries;
- symlinks and special files;
- payload count/hash mismatch;
- unexpected repository files inside the Skill.

## Scanner interpretation

The secret scanner is intentionally bounded. Report:

- eligible files and bytes;
- enabled detectors;
- skipped carriers;
- findings;
- limits and policy version.

Do not translate “zero findings” into “proof of zero secrets.” Manual review, repository push protection, and least-privilege installation remain necessary.

## Host result vocabulary

- `PASS` — all required evidence reproduced.
- `FAIL` — a required condition is false.
- `INCONCLUSIVE` — the host did not expose enough evidence; never silently upgrade this to PASS.
- `BLOCKED` — a declared external prerequisite prevents the gate.

Every host receipt must name the host/runtime version, source identity, target, discovery result, behavior result, mutations allowed, and post-test invariance.

## 2.1.2 live-gate status

The exact public 2.1.2 bytes have completed the reproducible package qualification recorded in [Release evidence](RELEASE_EVIDENCE.md). Release-specific live gates for Codex, Claude Code/Cowork, Antigravity, and Cursor remain pending until each is run in a fresh session and recorded against the 2.1.2 identities. Receipts for the private 2.1.1 payload do not transfer across the byte change.
