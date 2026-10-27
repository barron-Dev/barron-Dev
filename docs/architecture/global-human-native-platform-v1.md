# Cyclothone Global Human-Native Platform Layer v1

**Status:** Required architecture and implementation backlog. This is a normative product-wide requirement, not a claim that every locale, country, currency, residency region, or accessibility feature is already implemented.

## Product-wide invariant: global by default

Every Cyclothone service, product surface, SDK, CLI, API error, pack, receipt, attestation, notification, developer workflow, and customer workflow must consume the same versioned global context registries by default: locale and language, script and text direction, country/jurisdiction, currency and number/date formats, regulator/framework applicability, residency constraints, and accessibility preferences.

Global support is not an English interface with a translated documentation page. A customer or developer should be able to discover, configure, operate, understand results, and troubleshoot in the supported language and regional context. Coverage must be explicit and honest at the surface and locale level. Unsupported or partial localization must be disclosed; do not silently fall back to misleading translations or imply compliance/residency support that has not been verified.

The system remains one platform and one compositional pack architecture. Do not create separate country products or industry forks. Country, locale, geography, regulatory applicability, developer/customer role, and currency are independent dimensions composed through versioned registries.

## 1. Canonical contract and localized display

Machine-readable contracts remain canonical and language-neutral: Result Contract fields, disposition enums, stable error codes, reason codes, evidence types, policy decisions, and receipt schema. For example, `no_match_in_completed_scope` is the canonical disposition; localized display text is a separate presentation field. The display string must never change authorization, policy, evidence, or machine behavior.

Every human-readable string in packs, SDK errors, CLI output, console, notifications, receipts, attestations, and documentation uses ICU MessageFormat or a documented typed equivalent where ICU is not appropriate. No hand-built pluralization or concatenation for user-facing messages. Build gates must validate:
- mandatory `other` branches for plural/select messages;
- plural branches against the locale's CLDR rules;
- locale-aware number, date, time, currency and measurement formatting;
- required variables, argument types, and locale fallbacks;
- source/translation parity for gated language tiers.

Tests must include Arabic's six CLDR plural categories and languages with distinct plural rules, including Polish. Locale-aware formatting examples must be validated with a real ICU/CLDR implementation rather than assumed from a hand-written example.

## 2. RTL is structural

Locale and text direction are independent. Arabic, Hebrew, Persian/Farsi, and Urdu surfaces must use document direction and propagate direction through providers and portals/popovers. Use CSS logical properties rather than hard-coded left/right layout. Keep code, URLs, file paths, IDs, and other technical tokens LTR within RTL content without flipping surrounding layout. Conformance tests cover receipt and attestation rendering, portaled menus, focus order, mixed-direction text, and screen-reader reading order.

Pack compilation checks RTL support when required by the selected locale and product surface. Missing RTL conformance is a blocking gap, not a warning hidden behind translated strings.

## 3. Published language tiers

Expose a versioned language-tier registry through `cyclothone lang status` and the docs site. Report per-locale coverage by product surface, not only by language name.

- **Tier 1 — Full:** docs, SDK errors, CLI, receipts, attestations, tutorials, and reference architectures. Automated parity gate on every release.
- **Tier 2 — Core reference:** API reference prose, receipt display text, error taxonomy explanations. Missing gated source units fail CI.
- **Tier 3 — Navigation:** landing pages, getting-started, navigation, language switcher. Monitor coverage and publish the current status.
- **Tier 4 — Community:** community-contributed translations reviewed by native-language maintainers; contribution trust budget applies.

A developer must be able to see what is and is not localized before onboarding. A Tier 1 pack cannot ship if required strings or its jurisdiction's required locale coverage are missing. Variable names and code identifiers remain stable; explanatory prose and comments may be localized.

## 4. Locale-aware developer and customer surfaces

- **SDKs:** structured canonical error codes plus localized display messages; applications branch on codes, never translated strings.
- **CLI:** detect `LC_ALL` / `LANG`, use a configured fallback, and support explicit `--lang`. Provide `--no-color` and `--plain` for assistive technology and CI.
- **Docs:** persistent language switcher, locale-specific canonical URLs and `hreflang`, source-unit parity, governed terminology, do-not-translate glossary, and per-language style guides.
- **Console and customer UX:** locale, region, currency, time zone, number/date formatting, direction, and accessibility preferences are first-class settings and defaults, with safe user overrides. Never infer a legal jurisdiction solely from UI language.
- **Reference architectures:** localize explanatory prose and comments while preserving identifiers, API names, canonical enums, and executable code semantics.
- **Notifications and evidence:** canonical machine fields remain stable; localized display text includes locale/version metadata and cannot rewrite the underlying evidence or decision.

## 5. Source-writing discipline

Source English must be translation-friendly: short, direct sentences; active voice; present tense; limited noun stacking; no avoidable idioms, phrasal verbs, or subjective modifiers. Add a documentation lint stage that flags sentence length, stacked noun modifiers, subjective wording, and likely idioms. Treat automated lint as a review aid with explicit, testable rules and controlled false positives; do not pretend a heuristic can prove translation quality.

## 6. Global country and regional registry

Country is not locale. The registry models independently and composes:
- ISO country and subdivision identifiers;
- supported locales, scripts, direction, and language tier by surface;
- currency and formatting rules (ISO 4217), time zone defaults, and user overrides;
- jurisdiction and sector applicability triggers;
- regulator/framework versions and semantic diffs;
- permitted residency regions, in-country requirements, and prohibited data flows;
- payment rails only where the product actually supports them;
- export-control/restricted-market eligibility decisions;
- availability of services, data stores, backups, queues, logs, replicas, support access, and notification providers in each region.

The country matrix in the product strategy is a proposed launch/expansion map, not a verified legal opinion or proof of available infrastructure. Keep it in versioned registry data, with provenance, effective dates, applicability conditions, source links, review status, and explicit gaps. Do not hard-code every country into business logic or claim that a nearest region satisfies an in-country residency law. Legal mappings require qualified review and should distinguish statutory requirements, regulator guidance, contractual obligations, and platform-supported controls.

### Residency and infrastructure trust statements

Residency enforcement occurs at the journal/storage write boundary. Validate tenant, pack, jurisdiction, region, and actual destination partition before persisting data. A cross-region write fails closed with a typed reason; the audit record must itself respect residency constraints. Assess replicas, backups, logs, queues, exports, telemetry, support access, and notifications—not just primary database rows. A configuration field does not prove residency.

The trust page must state precisely what is guaranteed: where data is stored and processed, who can access it, which subprocessors and corporate jurisdictions apply, and which legal access risks remain. Do not imply that a local data center removes the legal exposure of the provider's parent jurisdiction. Country/region availability and legal assertions must be supported by current evidence.

## 7. Global compliance registry

Frameworks are scoped by geography, sector, entity type, processing activity, and applicability triggers—not by a flat universal list. Each versioned control registry includes control IDs, legal/regulatory source, effective dates, applicability conditions, evidence classes, freshness requirements, notification clocks, required locales, semantic diffs, reviewer status, and known limitations.

Reports are per tenant, jurisdiction, framework version, and control; signed and offline-verifiable when the supporting signing and verification path is implemented. A multinational organization may receive distinct jurisdiction-specific reports derived from the same authorized journal, without mixing tenant data or claiming controls that have not been evidenced. Legal applicability and mappings must be reviewed and versioned; a framework name in YAML alone is not compliance.

## 8. Accessibility is part of each locale's conformance

Console, docs, receipt viewer, and CLI meet WCAG 2.1 AA as the minimum target, with jurisdiction-specific requirements evaluated separately. Tests include contrast, keyboard operation, focus management, screen-reader semantics, localized ARIA labels, RTL reading order, and mixed-direction content. Receipt and evidence views remain usable at 200% zoom without losing critical disposition or provenance information. Color is never the only signal; `--plain` output is available for CLI and CI.

Publish an accessibility conformance report by product surface and locale. An English audit is not evidence that the Arabic, Japanese, or other localized surface conforms.

## 9. Global jurisdiction clocks

The clock registry is versioned per regulator, jurisdiction, sector, incident type, trigger, and legal basis. It defines the clock start event, deadline computation, pause/stop conditions where legally allowed, notification requirements, and evidence required to prove delivery. A case cannot close while a mandatory applicable clock remains open unless an authorized, signed justification references that specific clock and reason. Clock changes trigger semantic diff and explicit pack recompilation/adoption; they do not silently alter historical attestations.

Any listed deadline is a candidate mapping until validated against current law and regulator guidance. The engine must not hard-code broad generalizations as universal legal rules. It must show source, version, applicability, and uncertainty where deadlines depend on incident facts or regulator interpretation.

## 10. Export control and restricted-jurisdiction gate

Eligibility is enforced by a platform-owned policy at onboarding/pairing and rechecked where required—not by a community pack. The decision is based on authoritative, maintained rules and permitted signals; it fails closed when required checks cannot be completed. Record a typed reason and minimal audit evidence without exposing sensitive screening details or offering a pack to a prohibited destination. Legal and sanctions determinations require maintained authoritative data and review.

## Implementation backlog: Items 33–41

- **Item 33 — ICU compiler gate and canonical/display split.** Enforce ICU/CLDR validation, required `other`, typed arguments, and locale-resolved formatting. Done when invalid Arabic plural branches and missing `other` fail compilation, and receipt display tests pass across at least six CLDR plural-category languages.
- **Item 34 — RTL conformance suite.** Direction propagation, logical CSS, mixed-direction tokens, portal and screen-reader tests. Done when Arabic and Hebrew receipt/attestation views pass rendered-layout and reading-order checks.
- **Item 35 — Language-tier registry and CLI.** Publish per-locale, per-surface tier and parity status through `cyclothone lang status` and docs. Done when Tier 1 gaps fail CI and developers can inspect coverage before onboarding.
- **Item 36 — Country registry and residency enforcement.** Version country → locales, currency, jurisdiction, residency, regulators, and supported payment rails; enforce destination partition validation. Done when a Saudi-region cross-region write is rejected with a typed reason and the registry is published with provenance.
- **Item 37 — Global framework registry.** Model framework, geography, sector, trigger, version, control mappings and semantic diffs. Done when a multi-jurisdiction tenant can produce separate signed/offline-verifiable reports from authorized journal evidence, with gaps explicit.
- **Item 38 — Jurisdiction clock registry.** Versioned legal basis and clock rules, closure blocking, signed justification. Done when a validated applicable open clock blocks closure absent an authorized clock-specific justification.
- **Item 39 — Accessibility conformance per locale.** WCAG 2.1 AA tests across console/docs/receipt/CLI, including RTL and screen-reader interaction; publish per-locale ACR. Done when each claimed locale passes its own documented audit.
- **Item 40 — Source-writing lint.** Translation-friendly source checks in docs CI. Done when a deterministic fixture containing a configured prohibited noun stack fails the lint gate, with reviewable diagnostics.
- **Item 41 — Export-control gate.** Platform-level restricted-jurisdiction decision at pairing/onboarding with typed reason and auditable outcome. Done when restricted/unknown cases fail closed according to reviewed policy and no unauthorized pack is offered.

## Product-wide adoption rule

These are shared platform capabilities, not optional per-service enhancements. Every service inherits the global context and canonical/display contract by default. A service may declare a capability unavailable only through the shared registry and must surface that limitation honestly. New services, SDKs, APIs, packs, and customer/developer surfaces must pass the relevant locale, country, residency, framework, accessibility, and export-control conformance gates before being advertised as supported.

## Execution order

Item 33 is the next implementation item after the compiler foundation, but it must be implemented as a small verifiable block that does not break the current Result Contract or existing canonical enums. In parallel, keep DW source-attempt/evidence integration moving where independent. Do not treat the proposed country matrix, example regulator clocks, regional names, or launch tiers as verified infrastructure/legal coverage until each entry is evidenced. No production change is implied by this document.
