# Reports, Artifacts, and Visual QA

Load this reference when producing reports, documents, images, diagrams, screenshots, PDFs, or any artifact whose meaning and layout must survive generation, versioning, and print.

For a public artifact, visible title, subtitle, cover copy, description, and labels are acceptance claims to the reader. Govern and verify them with the same rigor as the body.

## Table of Contents

- Artifact-first contract
- Report envelope
- Optional artifact quality profile
- Evidence level
- Structured payload semantics
- Cross-artifact truth and localization
- Generation versus publication
- Reproducibility and artifact evidence
- Visual asset policy
- Vision verification
- Layout and PDF QA
- Visual meaning and geometry
- Retention, versioning, and deletion

For a serial artifact, freeze this ordered outline as a series invariant with its effective edition, required locators, parity rule, migration rule, and generated check.

## Artifact-First Contract

A report is not a styled chat transcript. It is a typed artifact produced from selected, validated content for a stated audience and use.

Declare:

```yaml
artifact_id:
artifact_type:
version:
producer:
run_id:
audience:
purpose:
source_artifacts: []
content_scope:
claims: []
assumptions: []
risks: []
local_risk:
inherited_risks:
  - source_address:
    owner:
    severity:
aggregation_checks: []
verification: []
supersedes:
next_gate:
```

Keep the conversational source, selected report source, structured semantic model, rendered output, and published version as distinct artifacts.

## Report Envelope

A governed report should include, when relevant:

- title, objective, audience, date, and edition;
- what was understood and what remains assumed;
- concise decision or plan;
- evidence and source lineage;
- tables, timelines, checklists, diagrams, or images that clarify the content;
- risks, red flags, stop conditions, and escalation;
- progress or delta from the prior edition;
- next check and update criteria;
- technical colophon or provenance manifest, optionally separated from the reader-facing pages.

Identity fields must be optional when the user requests an anonymous artifact. Do not invent names, goals, or baselines from unrelated chat turns.

## Optional Artifact Quality Profile

Activate this profile only for a public, serial, multilingual, or visually consequential artifact. Its requirements extend the base report contract; they are not universal defaults. Freeze a profile before generation:

```yaml
artifact_quality_profile:
  artifact_class: print_book | screen_report | web_app | slide_deck | dataset | other
  brief_id:
  audience:
  source_language:
  editions: []
  reader_facing_surfaces: []
  canonical_strings: []
  series_invariants: []
  editorial_authority:
    decision_owner:
    section_states: {} # provisional | mature | verified | baptized
  thresholds:
    - metric:
      value:
      risk_or_acceptance_rationale:
      anti_padding_check:
  not_applicable_checks: []
```

The profile must make the brief, surface, edition, and language explicit. A threshold is admissible only when tied to a named risk or acceptance condition and accompanied by an anti-gaming check; word, page, agent, or tool counts must not reward padding. A short closing artifact may therefore use a different justified range from a long-form chapter. Section maturity is local: a PASS or human baptism for one section never promotes the whole artifact.

For serial artifacts, register each invariant with `effective_from`, selector, canonical locator, parity or hash rule, migration, and generated check. Invariants include naming, taxonomy, promises, recurring cards, and reader-facing terminology. A later artifact may rename or specialize one only through a declared semantic bridge and an approved migration.

## Evidence Level

Use the single evidence ladder defined in [reference 10](10_verifier_playbook.md). An attractive layout cannot raise the level. A generated chart is evidence only when its underlying data and transformation are verified.

## Structured Payload Semantics

Parsing is necessary but insufficient. Audit that each table, list, block, chart, and section retains:

- semantic type and required fields;
- full payload, including nested content;
- ordering when order has meaning;
- source references and unit definitions;
- empty, unknown, and not-applicable states;
- fallback behavior for malformed model output.

Do not silently downgrade a requested table or chart to unstructured prose. Do not print debugging conversation because a source selector chose the wrong response.

A semantic state such as `validated`, `safe`, `approved`, or `published` is valid only when the corresponding check actually executed and its evidence is attached.

## Cross-Artifact Truth and Localization

Treat title, subtitle, names, dates, product copy, edition claims, terminology, tables, diagrams, and localized editions as one governed promise surface.

- Keep evergreen identity separate from edition date, dated state-of-the-art content, and mutable description. Declare where each date lives, its owner, and its refresh rule.
- Before baptizing a public name, check collisions in the declared registries and surfaces. Record the searched universe, date, unresolved collisions, and chosen canonical string; do not promise global uniqueness or search visibility.
- Extract every falsifiable reader-facing promise and test it in the exact edition, language, and surface where it appears. Truth in a sibling edition does not transfer automatically.
- For multilingual output, freeze non-localizable keys, localizable fields, section and row keys, ordering, source language, adaptation policy, and intentional divergences. Compare section, claim, example, diagram, source, and row parity rather than literal translation alone.
- Bind anchor terms and their definitions to a canonical glossary. Check terms, collective nouns, first-use glosses, and collisions against that source; exclude machine tokens only through a recorded rule.
- Separate reader-facing content from provenance. Search the complete reader-facing corpus for internal message IDs, block or sprint codes, checkpoint names, private filenames, and other workshop jargon; translate, justify, or explicitly exclude every match.
- Apply locale-aware language QA to the complete corpus, not a small known-file list: spelling, diacritics, apostrophes, contextual copulas, grammar, and suspicious forms, followed by integral human reading and final-render readback. Known patterns are regression probes, not proof of linguistic correctness.
- Apply a content-quality gate for voice, source coverage, factual checks, repetition, promise consistency, and qualified human curation. Grammar and volume alone do not establish useful quality.

For tabular or catalog artifacts, use a row-level acceptance pack keyed by stable identity. Declare columns, types, units, date and currency formats, keys, missing-value semantics, deduplication, source, timestamp, localizable fields, exceptions, and readback from the final artifact.

## Generation Versus Publication

Use a staged pipeline:

```text
conversation or source set
-> explicit selection
-> semantic report model
-> content validation
-> layout and media composition
-> visual verification
-> publication gate
-> immutable edition and optional PDF
```

The model may propose structure and visual treatments. Deterministic code owns pagination, styles, numbering, links, assets, and export. Publication fails closed when required content, safety fields, or source lineage are missing.

Reuse the host's proven document and PDF capabilities. Do not bundle a new rendering engine unless repeated qualified use cases and tests prove that the host path is insufficient.

When aggregating contributions, preserve source addresses and local/inherited risks, then rerun safety, completeness, and publication checks on the composed artifact.

## Reproducibility and Artifact Evidence

A reproducibility claim requires two isolated or time-separated builds of the same frozen semantic input, toolchain, assets, locale, and environment. Compare final bytes when byte identity is promised; otherwise compare an explicit semantic projection and explain permitted metadata variance. Apparent determinism in code is not evidence.

Stress the real transformation path with inline-code delimiters, asterisks, underscores, brackets, URLs, comparison symbols, long translated strings, narrow tables, lists, vector diagrams, sparse states, and malformed structured input. Record separately:

1. generation completed;
2. semantic content and text are extractable;
3. the final user-facing artifact was visually inspected;
4. every publication gate passed.

An artifact evidence pack should contain environment fingerprint, semantic-input hash, renderer and dependency versions, two-build comparison, requirement-to-page or component mapping, machine-check results, representative screenshots or rendered pages, exceptions, reviewer decision, final hash, and evidence level. A green semantic validator does not substitute for final-render inspection.

## Visual Asset Policy

- Select assets from the domain need, not from model-invented URLs.
- Track source, license, creator, retrieval date, local cache path, and permitted use.
- Prefer primary product/object/state imagery when inspection matters.
- Generate custom visuals only when rights, accuracy, and purpose are clear.
- Never imply a stock or generated image depicts the user's actual state.
- Use diagrams and charts only when they encode verified relationships or data.

## Vision Verification

Use `extract -> check -> report`:

1. extract visible objects, text, dimensions, and layout facts;
2. compare against a checklist represented as data;
3. report pass/fail, confidence, and limits.

Use deterministic image or canvas checks before a vision model when possible. Abstain below confidence thresholds. Do not make absolute counts, measurements, or medical conclusions from ambiguous images.

## Layout and PDF QA

Verify at representative desktop, mobile, print, and page sizes:

- no clipped, overlapping, or orphaned text;
- stable table widths, numbering, headers, and page breaks;
- images render, retain aspect ratio, and remain legible in print;
- charts include labels, units, data source, and accessible fallback;
- each requested section can begin on a new page when modular printing matters;
- navigation controls and debug metadata are excluded from print;
- anonymous mode removes identity consistently;
- long words, translated copy, and sparse/empty states fit.
- searchable/selectable text remains text unless rasterization is an explicit requirement;
- document outline, bookmarks, internal links, and external links survive the final export;
- rasterization, pagination, and page-count changes are compared against the approved source and explained;
- the real printed/exported file is checked, not only an intermediate preview.

Perform two checks for PDF-critical work: render through a controlled converter and inspect the actual user-facing print/export path. Text extraction alone does not prove layout.

## Visual Meaning and Geometry

Select only the QA profile that matches the delivery surface and mark other profiles not applicable with a reason:

| Profile | Required emphasis |
|---|---|
| `print_book` | trim/page size, selectable text, embedded fonts, outline and links, widows/orphans, sparse final pages, tables, captions, and print legibility |
| `screen_report` | target viewport set, responsive overflow, zoom, accessible reading order, and export parity |
| `web_app` | live interaction, DOM/ARIA structure, responsive states, keyboard path, and user-visible fallback |
| `slide_deck` | slide bounds, minimum readable type, contrast, sequence, notes/export parity, and projection legibility |

Visual verification has three independent layers:

1. **pixel and geometry** — clipping, overlap, contrast, font floor, aspect ratio, label/node/connector bounding boxes, and connector crossings;
2. **structure and accessibility** — reading order, headings, table structure, DOM/ARIA or document tags, selectable text, alt text, and navigation;
3. **meaning** — arrows, containment, proximity, color, hierarchy, terminal state, captions, and duplicated claims agree with the semantic source.

Keep semantic claims shared between prose and renderer data or test both representations. A textual update does not prove that a generated figure, callout, or image changed. Require final-page and caption-continuity inspection after reader-facing edits. A nonblank-page check cannot detect a widow, orphan, isolated fragment, or unreadably sparse ending; use brief-specific layout criteria plus sampled human readback rather than a decorative universal character threshold.

## Retention, Versioning, and Deletion

Every edition records its source artifact IDs, transformations, renderer version, assets, and hash. Updating a plan creates a new edition linked to the initial objective and explicit delta; it does not overwrite history silently.

Users must be able to delete created paths, editions, and reports individually according to retention policy. Deletion must cover metadata, files, previews, caches, and indexes and must produce readback evidence.
