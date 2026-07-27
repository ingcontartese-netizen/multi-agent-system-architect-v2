# Post-Publication Verification

## Disposition

**PASS — the mandatory anonymous replay for public release `v2.1.2` was completed on 2026-07-23, after publication.**

This closes the `POST_PUBLISH_URL_GATE` that was intentionally left pending in the frozen pre-publication evidence. This documentation-only update does not modify the tag or its four release assets; it records the later observation of the live public objects.

## Public objects verified

- Repository: <https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2>
- Release: <https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/releases/tag/v2.1.2>
- Tag: `v2.1.2`
- Peeled commit: `5ae4658b9b5c4fa76cdedf8281d736d603ad0c86`
- Main exact-head CI: <https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/actions/runs/29973721201>
- Tag exact-head CI: <https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/actions/runs/29974261985>

## Independent anonymous replay

The independent verifier reproduced the release without repository credentials or private workspace state:

| Check | Result |
|---|---|
| Fresh anonymous clone and tag resolution | PASS — tag resolves to the declared commit |
| Four public release-asset downloads | PASS — names, sizes, and SHA-256 values match |
| README Bash verification block | PASS |
| README PowerShell verification block | PASS |
| ZIP structure and safe-entry audit | PASS — one root, 70 files |
| Installable source-tree identity | PASS — `1D04C870FC39842EC8F9AE56D23B580377650F9BC13B1EDA3A776C1A32C5EF55` |
| Public badges, hero, release page, and URLs | PASS |
| Main and tag CI matrices | PASS — 7/7 on Ubuntu and Windows across Python 3.10, 3.12, and 3.14 |

The four downloaded assets matched these frozen values:

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `multi-agent-system-architect-v2-2.1.2.zip` | 1,154,005 | `50153A5AD02611753B817749271B4DBAED77A078A90476C82708D567C754563B` |
| `PUBLIC_RELEASE_MANIFEST.json` | 1,993 | `5DF5C4034108986DDC5DD6A3338298A1DDD4CEF9CB4CDEF25262AEDBB3F6311E` |
| `RELEASE_EVIDENCE.md` | 3,149 | `3A9C0A4F713D1D56BBC4048FC734C0EE138303532888EC342F412C7D7A985B6B` |
| `SHA256SUMS.txt` | 289 | `7A489F55B22050DB7B11BEDA74B25F72F118969F6B8E4F828F6E2659BF0B5FB6` |

One repository-root `LICENSE` comparison reflected checkout line-ending normalization only. Normalized content matched, the file is outside the installable Skill payload, and the observation does not affect the release identity.

## Claim boundary

This receipt verifies the public distribution path, published release assets, documentation commands, and CI visibility for the exact `v2.1.2` release. It does **not** convert format compatibility into a release-specific live behavior gate for Codex, Claude Code/Cowork, Google Antigravity, or Cursor. Those host claims remain as stated in [Release evidence](RELEASE_EVIDENCE.md).
