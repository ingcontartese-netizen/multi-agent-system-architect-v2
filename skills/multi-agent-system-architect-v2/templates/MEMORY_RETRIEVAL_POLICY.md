# Memory And Retrieval Policy

Status: draft
Version:
Owner:
Tenancy boundary:

## Memory Inventory

| Type | Content | Authority | Store | Retention | ACL | Correction | Delete proof | Rebuild |
|---|---|---|---|---|---|---|---|---|
| Working |  |  |  |  |  |  |  |  |
| Conversation |  |  |  |  |  |  |  |  |
| Episodic |  |  |  |  |  |  |  |  |
| Semantic |  |  |  |  |  |  |  |  |
| Procedural |  |  |  |  |  |  |  |  |

## Source Governance

Define source owner, trust, version/hash/date, parser, tenant, license, sensitivity, correction path, and archive decision.

## Retrieval Selection

State why direct load, structured lookup, lexical, semantic, hybrid, reranking, or bounded agentic retrieval is the lightest strategy that passes the eval.

## Pipeline

Define ingest, normalization, ACL filter, chunking, index version, retrieval, rerank, context assembly, citation, freshness, and no-answer behavior.

## Untrusted Content

Treat retrieved text, browser output, metadata, and tool descriptions as data. Define instruction-stripping, provenance, capability limits, and poisoning tests.

## Correction, Deletion, And Expiry

Require removal from source, index, cache, assembled context, and backups according to policy, followed by readback evidence.

## Evaluation

Define golden queries, negative sources, ACL cases, poisoning cases, recall/precision targets, citation checks, correction/delete, and stale-index tests.

## Contract And Claim Bindings

Bind each material claim to a versioned contract reference, its authority, evidence locator, and invalidation condition. Reject unresolved, cross-tenant, stale, or owner-mismatched bindings.
