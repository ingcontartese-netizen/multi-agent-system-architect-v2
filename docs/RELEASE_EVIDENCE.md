# Release Evidence

Release evidence is generated from the frozen payload and bound to `release/PUBLIC_RELEASE_MANIFEST.json`.

## Evidence contract

The public receipt records:

- semantic version and tag;
- installable file count and byte count;
- deterministic source/public/physical identities;
- test and security denominators;
- Python and host runtime versions;
- package/archive checksums;
- fresh-clone and host discovery results;
- limitations and annotations;
- independent verifier disposition.

## Current public release

The exact 2.1.2 payload values are:

| Measure | Exact value |
|---|---|
| Release tag | `v2.1.2` |
| Installable files | 70 |
| Installable bytes | 1139811 (1,139,811) |
| Source tree SHA-256 | `4552AE02D0D4C55B82E3DAC93E7429E0BE40EF954C4278098E90FC71716A3992` |
| Public readback SHA-256 | `AF96D6A9140BFB75F367645B82450FE853446805D513793C1545C5F79C3352A0` |
| Physical tree algorithm | `release-physical-tree-v1` |
| Physical tree SHA-256 | `41D2F3140960C981A7CDD4ED7180B5A9BC256D7173FE13C090B17A5D52D488E8` |
| Deterministic Skill ZIP SHA-256 | `63219FDF183460C224168F0B4639E3A88A1D91E1169B9A263751771921DDA2A7` |
| Cross-runtime archive reproduction | CPython 3.12.13 = CPython 3.14.3 |
| Public pytest | 164/164 PASS |
| Release-tool tests | 47/47 PASS |
| Archive format | `deterministic-zip-stored` |
| Archive root directory | `multi-agent-system-architect-v2` |
| Security matrix | 293/293 PASS |
| Public-only quick validation | 70/70 PASS |
| Secret scan | 0 findings |
| Secret scanner policy | 2.1.0 |
| Independent terminal gate | PASS_WITH_POST_PUBLISH_URL_GATE; no remaining findings |

These values are also bound in the machine-readable manifest. CI rejects disagreement between this document, the manifest, the Skill payload, and release assets.

The independent verifier reproduced the frozen identities, cold-copy suite, clean-venv CI simulation, archive contents, privacy census, and protected-state invariance. Its only deferred condition is the mandatory anonymous replay against the real tag, release URLs, and CI badge after publication.

Run:

```powershell
python -B tools/verify_release.py --repo .
```

## Live host evidence

No live host gate is claimed yet for the exact 2.1.2 bytes. The release-specific gates for Codex, Claude Code, Claude Chat/Cowork, Google Antigravity, and Cursor are `PENDING` until fresh-session discovery, behavior, identity, and post-test invariance are executed and recorded.

The private 2.1.1 delivery had live receipts, but those receipts identify different bytes and do not qualify 2.1.2.

## Claim discipline

Evidence applies only to the named bytes and runtime. It does not certify vendors, future versions, every host, every threat, or every deployment.

- Scanner `PASS` means no configured detector matched eligible carriers.
- Format compatibility is not a live behavior gate.
- A builder's PASS is not independent corroboration.
- `INCONCLUSIVE` remains inconclusive.
- Installed hosts do not share authority, identity, or state.

The tagged GitHub Release includes the full public receipt and checksums produced after terminal verification.
