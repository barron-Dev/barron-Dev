# Reference Pack Generator v1

## Architectural contract

An industry reference is a declarative pack, not a repository, branch, fork, or separate product. The pack schema composes platform primitives; it cannot create a primitive or claim that an unimplemented capability exists. Industry, geography, and developer profile are orthogonal dimensions.

## First implementation slice

- Canonical schema: `schemas/reference-pack.schema.json`.
- Safe YAML loading rejects duplicate keys and non-JSON values.
- Validation rejects unknown top-level fields, unsupported schema versions, malformed identifiers, invalid delivery defaults, contradictory allowed/forbidden bindings, and unsafe dual-control declarations.
- `cyclothone pack build <source.yaml> --out <artifact.json>` emits stable JSON and a SHA-256 artifact digest.
- An optional capability registry is JSON with exactly `services` and `delivery_bindings` arrays. Unresolved required services, optional services, or delivery bindings keep the output `preview`.
- Even a fully resolved artifact is only `compiled_unconformed`; conformance and publication are separate, explicit lifecycle gates.

## Trust boundaries

The compiler does not provision services, apply policy, grant permissions, perform residency enforcement, attest compliance, or execute workflows. A field such as `cross_border_forbidden`, `worm`, `observe_only`, or a compliance-pack name is declarative intent until a runtime primitive and conformance test prove enforcement.

The generator must never infer that a service is supported from a pack's own declaration. Only a separately maintained capability registry may resolve a binding. A missing registry is fail-closed to preview status.

## Determinism

The artifact digest is computed from canonical JSON (sorted keys, compact separators, UTF-8) before the digest field is added. The output JSON is sorted and indented for review. Same validated input and same capability registry produce the same digest.

## Exemplar packs included in this slice

- `packs/financial-services/crypto-exchange-eu.yaml`: regulated finance, dual control, EU overlays, wallet observe-only, and regulated notification workflows.
- `packs/healthcare/hospital-us.yaml`: strict PHI handling intent, medical-device observe-only, patient-safety escalation, and the 60-day HIPAA clock field.
- `packs/developer/solo-developer.yaml`: no mandatory policy pack, one-asset free-tier intent, auto-selected profile, and a 300-second TTFVR target.

These are declarative examples, not proof that their controls or legal obligations are enforced. They intentionally compile as preview until their service and delivery bindings resolve against an independently maintained capability registry.

## Next queue items

1. Bind pack references to real platform service, policy, compliance, and delivery registries.
2. Add the six mandatory conformance tests and retain machine-readable pass/fail artifacts.
3. Add compliance control-to-receipt translation and signed offline verification.
4. Add versioned geography overlays, drift tracking, and TTFVR instrumentation.
5. Add trust-budget demotion, marketplace publication, and the community SDK.

No pack is production-ready solely because it compiles. No compliance claim is made by schema validation alone.
