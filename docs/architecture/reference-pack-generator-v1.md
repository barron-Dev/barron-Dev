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

## Next queue items

1. Add three archetype packs (crypto-exchange-eu, hospital-us, solo-developer) and test their expected unresolved bindings.
2. Bind pack references to real platform service, policy, compliance, and delivery registries.
3. Add the six mandatory conformance tests and retain machine-readable pass/fail artifacts.
4. Add compliance control-to-receipt translation and signed offline verification.
5. Add versioned geography overlays, drift tracking, TTFVR instrumentation, trust-budget demotion, marketplace publication, and the community SDK.

No pack is production-ready solely because it compiles. No compliance claim is made by schema validation alone.
