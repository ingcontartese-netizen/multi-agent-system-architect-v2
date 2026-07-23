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
| Installable bytes | 1139903 (1,139,903) |
| Source tree SHA-256 | `1D04C870FC39842EC8F9AE56D23B580377650F9BC13B1EDA3A776C1A32C5EF55` |
| Public readback SHA-256 | `AA08AC8B4E7E41A3DC844648E4745A32943C72FF6CD1BF3A22FFE6F530D2E20C` |
| Physical tree algorithm | `release-physical-tree-v1` |
| Physical tree SHA-256 | `A613996B740906080D50E80058ED2274EA4D34CC68BE025C222452B63B9DE103` |
| Deterministic Skill ZIP SHA-256 | `50153A5AD02611753B817749271B4DBAED77A078A90476C82708D567C754563B` |
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
