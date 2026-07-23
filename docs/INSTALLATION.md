# Installation

This repository publishes one canonical Agent Skill and several host-specific carriers. **Install only into the host you intend to use.** Another host is never required.

## Before any write

For every host:

1. Select a release tag, record the commit SHA it resolves to, and verify the published checksum. A tag alone is not an integrity proof.
2. Inspect the target and stop if it already exists.
3. Keep a reversible backup when replacing an older version.
4. Copy the Skill; do not create a shared symlink between hosts.
5. Verify the installed tree against the release manifest.
6. Start a fresh session and run the discovery and behavior probes.

Canonical tagged source:

```text
https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/tree/v2.1.2/skills/multi-agent-system-architect-v2
```

Release ZIP:

```text
multi-agent-system-architect-v2-2.1.2.zip
```

The ZIP contains the root folder `multi-agent-system-architect-v2/` and the same payload used by every direct Skill carrier.

Download the named ZIP, `SHA256SUMS.txt`, manifest, and evidence assets from the same GitHub Release. Verify them before extraction.

PowerShell:

```powershell
$asset = '.\multi-agent-system-architect-v2-2.1.2.zip'
$line = Select-String -LiteralPath '.\SHA256SUMS.txt' -Pattern '  multi-agent-system-architect-v2-2\.1\.2\.zip$'
$expected = ($line.Line -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "SHA-256 mismatch: $actual != $expected" }
```

macOS/Linux:

```bash
sha256sum -c SHA256SUMS.txt
```

## Universal agent-guided installation

Paste this into the single host you want to equip:

```text
Install only the Agent Skill `multi-agent-system-architect-v2` from this tagged source:

https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/tree/v2.1.2/skills/multi-agent-system-architect-v2

Install it only for your own host at personal/global scope. Use a real copy, not a shared symlink. Resolve the tag to its commit SHA and verify the release checksum/source-tree identity before copying. Before writing, detect your currently supported Skill location and show target, action, rollback, and verification. Stop if the target already exists; do not overwrite it. Do not install into or contact any other host. After installation, read back the payload and verify discovery in a fresh session.
```

This prompt grants authority only for the named host and target. It does not authorize deletion, overwrite, cross-host installation, or credential creation.

## Codex

### Recommended: plugin marketplace

Codex recommends plugins for reusable distribution. The repository includes a Codex plugin manifest and marketplace catalog.

```powershell
codex plugin marketplace add ingcontartese-netizen/multi-agent-system-architect-v2 --ref v2.1.2
```

Then open the Codex/ChatGPT desktop Plugins directory, choose **Giuseppe Agent Skills**, and install **Multi-Agent System Architect V2**. Start a new task after installation.

### Direct Skill

Codex supports project Skills under `.agents/skills/` and personal Skills under `~/.agents/skills/`. You can also ask the built-in installer:

```text
Use $skill-installer to install:
https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/tree/v2.1.2/skills/multi-agent-system-architect-v2
Do not overwrite an existing target. Verify discovery in a new task.
```

The current `$skill-installer` may place downloaded Skills under `$CODEX_HOME/skills` (normally `~/.codex/skills`). Let the installed version detect its supported target; do not assume that every Codex surface uses the same path.

### Codex discovery probe

In a new task:

```text
List only the name and exact discovery description for multi-agent-system-architect-v2. Do not read the filesystem.
```

Then run the behavior probe at the end of this guide.

## Claude Code

### Recommended: plugin marketplace

Inside Claude Code:

```text
/plugin marketplace add ingcontartese-netizen/multi-agent-system-architect-v2
/plugin install multi-agent-system-architect-v2@giuseppe-agent-skills
/reload-plugins
```

Claude plugin Skills are namespaced. Invoke it explicitly once if needed, then test automatic discovery with a natural-language architecture request.

Explicit namespaced invocation:

```text
/multi-agent-system-architect-v2:multi-agent-system-architect-v2
```

### Direct personal Skill

Copy the tagged folder to:

```text
~/.claude/skills/multi-agent-system-architect-v2/
```

Project scope uses:

```text
.claude/skills/multi-agent-system-architect-v2/
```

If the top-level Skills directory was created after Claude Code started, restart Claude Code or open a new session.

## Claude Chat / Cowork

Claude Chat/Cowork account Skills are separate from Claude Code's local filesystem Skills.

### Marketplace route

1. Open **Customize → Plugins**.
2. Choose **Browse → Personal**.
3. Add a marketplace from GitHub.
4. Paste `https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2`.
5. Install and enable **Multi-Agent System Architect V2**.
6. Open a fresh chat for the discovery probe.

### ZIP Skill route

1. Open the tagged GitHub Release.
2. Download `multi-agent-system-architect-v2-2.1.2.zip`.
3. Open **Customize → Skills → Create skill → Upload a skill**.
4. Select the named release ZIP.
5. Enable the Skill and open a fresh chat.

Do not choose GitHub's automatically generated source archive. It contains repository wrappers, not just the uploadable Skill payload.

## Google Antigravity

### Direct Skill

Global scope:

```text
~/.gemini/config/skills/multi-agent-system-architect-v2/
```

Workspace scope:

```text
.agents/skills/multi-agent-system-architect-v2/
```

Copy the tagged Skill folder to one target and start a new conversation. Antigravity catalogs Skills at conversation startup.

### Plugin-style checkout

The repository root is an Antigravity plugin (`plugin.json` plus `skills/`). A manual plugin install may place a checkout under:

```text
~/.gemini/config/plugins/multi-agent-system-architect-v2/
```

or, for a workspace:

```text
.agents/plugins/multi-agent-system-architect-v2/
```

No native public GitHub marketplace URL is claimed for Antigravity. Use a reviewed clone/download and verify the tagged commit.

## Cursor

### Remote Rule import

1. Open **Customize → Rules**.
2. Choose **Add Rule → Remote Rule (GitHub)**.
3. Enter this repository URL.
4. Select/import the Skill.
5. Start a new session and invoke `/multi-agent-system-architect-v2` if explicit discovery is needed.

### Direct Skill

Personal scope:

```text
~/.cursor/skills/multi-agent-system-architect-v2/
```

Project scope:

```text
.cursor/skills/multi-agent-system-architect-v2/
```

Cursor also recognizes compatible `.agents/skills` locations. This release claims format compatibility, not a live Cursor qualification, unless [Release evidence](RELEASE_EVIDENCE.md) explicitly records one.

## Compatible Agent Skills hosts

For another host that implements the [Agent Skills specification](https://agentskills.io/specification):

1. Confirm its current personal/project Skill paths from official documentation.
2. Copy only `skills/multi-agent-system-architect-v2/`.
3. Preserve `SKILL.md` capitalization and relative directories.
4. Start a fresh session.
5. Record the host/version/path and run the two probes below.

## Community installer

The community-maintained `skills` CLI can discover and copy the Skill:

```powershell
npx --yes skills@1.5.20 add https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/tree/v2.1.2/skills/multi-agent-system-architect-v2 --global --copy --agent codex
```

This is a secondary community route. Select exactly one supported `--agent`, review its detected host and target, and prefer the official host-specific route above. Do not use `--all` merely because several agents are installed on the same machine. The example targets Codex; it does not claim that this CLI installs Antigravity.

## Post-install verification

### 1. Identity

Compare the installed tree with `release/PUBLIC_RELEASE_MANIFEST.json` or run the verifier against a checkout:

```powershell
python -B tools/verify_release.py --repo .
```

### 2. Discovery-only probe

In a fresh session, without filesystem access:

```text
Return only the discovered name and exact description for multi-agent-system-architect-v2. If exact discovery metadata is unavailable, return only INCONCLUSIVE.
```

### 3. Behavior probe

```text
Use multi-agent-system-architect-v2. I want an autonomous research team for a one-off summary. First decide whether I need any system at all. Return status, Mode, autonomy, risk, rationale, and next gate. Do not build anything and do not contact another host.
```

Expected properties:

- no-system/direct handling is considered;
- Mode, autonomy, and risk remain separate;
- teams are optional;
- no external write occurs;
- the answer includes evidence limits and a next gate.

## Rollback

If installation fails:

1. Disable the plugin/Skill in the host UI if available.
2. Quarantine only the newly created target.
3. Restore the prior target from its byte-verified backup, if one existed.
4. Restart/open a fresh session.
5. Prove that discovery returned to the previous state.

Never delete a previous version until the new version has passed identity, discovery, and behavior checks.

## Official documentation

Host behavior changes over time. These links were checked for the public release:

- [OpenAI — Build Skills](https://learn.chatgpt.com/docs/build-skills)
- [OpenAI — Build Plugins](https://learn.chatgpt.com/docs/build-plugins)
- [Anthropic — Claude Code Skills](https://code.claude.com/docs/en/skills)
- [Anthropic — Plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [Anthropic — Use Skills in Claude](https://support.claude.com/en/articles/12512180-use-skills-in-claude)
- [Google — Antigravity Skills](https://antigravity.google/docs/skills?app=antigravity-ide)
- [Google — Antigravity Plugins](https://antigravity.google/docs/plugins)
- [Cursor — Agent Skills](https://cursor.com/docs/skills)
- [Agent Skills specification](https://agentskills.io/specification)
