# Threat Model

Status: draft
Version:
Owner:
Related architecture:

## Assets

List canonical knowledge, credentials, profile data, runtime state, artifacts, approvals, audit evidence, and deployment control.

## Actors And Tenants

List users, operators, agents, external services, administrators, attackers, and cross-tenant risks.

## Trust Boundaries

Map surface, model/provider, bridge, tools, browser/retrieval, sandbox, data stores, queues, and external systems.

## Threat Register

| ID | Threat | Entry point | Asset | Preconditions | Impact | Likelihood | Control | Residual risk | Owner | Test |
|---|---|---|---|---|---|---|---|---|---|---|

## Required Controls

Cover identity, least privilege, secret brokerage, tenant isolation, egress, sandbox, prompt injection, tool approval, idempotency, audit, retention, and kill switch.

## Abuse And Failure Cases

Include malicious retrieval, untrusted tool descriptions, confused deputy, stale approval, replay, duplicate side effect, poisoned memory, data exfiltration, denial of service, and unsafe deserialization.

## Verification And Response

Link tests, incident owner, containment, credential revocation, rollback/compensation, evidence preservation, and residual-risk approval.

## Contract Integrity Threats

Test version hybrids, unresolved references, owner or risk drift, typed-error truncation, replayed approvals, and partial migration. Fail closed and retain rollback plus readback evidence.
