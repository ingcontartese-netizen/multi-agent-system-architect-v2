# Security Policy

## Supported release

Security fixes are applied to the latest public release. Older commits, published checksums, and release assets remain the durable evidence; a tag alone can move and is not an integrity proof. Older versions may not receive backports.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, private data, unsafe install behavior, or a practical permission bypass.

Use GitHub's **Report a vulnerability** flow under the repository's Security tab. Include:

- affected version and host;
- exact preconditions;
- minimal reproduction using synthetic data;
- observed versus expected behavior;
- impact and blast radius;
- whether the issue changes files, permissions, network access, or external state.

Do not include real credentials, personal data, production endpoints, or destructive payloads.

## Trust boundary

This repository contains instructions and local validation tools. Installing it does not grant new host permissions. The effective authority is the intersection of:

1. the human's explicit request;
2. host policy and sandbox;
3. available tools and credentials;
4. the Skill's own governance gates.

The Skill cannot make a compromised host safe. Review the tagged source and checksums before installation, especially when using third-party installers.

## Secret scanning limitation

The bundled scanner is a bounded defense-in-depth control. A clean result means no configured detector matched the eligible files examined. It is not a universal proof of secret absence.
