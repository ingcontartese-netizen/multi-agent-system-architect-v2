# Support

Multi-Agent System Architect V2 is a community-maintained Agent Skill. Support is evidence-first: include enough information for another person to reproduce the behavior without access to your machine, credentials, or private data.

## Choose the right channel

- Use [GitHub Discussions](https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/discussions) for installation questions, architecture guidance, and usage patterns.
- Use [GitHub Issues](https://github.com/ingcontartese-netizen/multi-agent-system-architect-v2/issues) for reproducible defects in the published package, documentation, validators, or host adapters.
- Use GitHub's private **Report a vulnerability** flow for security issues. Follow [SECURITY.md](SECURITY.md); never publish credentials, private data, production endpoints, or a practical exploit in an issue.

## Before requesting help

Please include:

- Skill version, release tag, and installation route;
- host and host version;
- operating system and Python version when a validator is involved;
- exact command or prompt, expected result, and observed result;
- minimal reproduction using synthetic data;
- relevant validator output with secrets and personal paths removed;
- whether the problem changes files, permissions, network access, or external state.

Verify the downloaded ZIP and source identity first. The commands and current hashes are documented in [Verification](docs/VERIFICATION.md) and [Release evidence](docs/RELEASE_EVIDENCE.md).

## Supported versions

Support and security fixes target the latest public release. Older tags and published checksum records remain as historical evidence where retained, but may not receive backports.

Host behavior can change independently of this repository. A format-compatible package is not automatically a live certification for every host version; consult the release evidence for the exact claims that were reproduced.

## Boundaries

This project has no guaranteed response time or service-level agreement. It is not endorsed or certified by OpenAI, Anthropic, Google, Cursor, or any other host vendor. The Skill provides a governed method; it does not grant permissions, operate outside host policy, or make a compromised environment safe.
