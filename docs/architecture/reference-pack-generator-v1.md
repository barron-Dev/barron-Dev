# Reference Pack Generator v1

Status: first implementation slice; compiler and schema are reviewable, but runtime bindings and conformance are not yet proven.

## Architectural rule

An industry reference is a declarative YAML pack, not a repository, branch, fork, or separate product. Industry, geography, and developer type are independent dimensions composed into one platform configuration. Geography is referenced by ID and must ultimately resolve through a versioned geography-overlay registry.

The generator must be the only supported path for turning an industry pack into a compiled manifest. Adding an industry is authoring and validating data, not branching platform code.

## Build command

After installing the package:

```bash
cyclothone pack build packs/example.yaml --output build/example.pack.json
```

The command validates the YAML and emits deterministic JSON with SHA-256 digests. It rejects duplicate YAML keys, unknown schema fields, duplicate list values, overlapping required/optional services, unsafe delivery defaults, invalid residency/retention values, and single-role dual-control declarations.

## Trust semantics

The compiler emits `compilation_state=compiled_unverified`, `conformance.status=not_run`, and `primitive_bindings[].state=declaration_only`. Those states are deliberate. A syntactically valid pack is not a production configuration, compliance certification, signed receipt, or evidence that a referenced runtime primitive exists.

A pack cannot be listed or used to satisfy a regulated disposition floor until later work resolves contract IDs to actual implementations and passes the mandatory conformance suite. A failed or missing test must not be represented as a pass.

## Dimensions

- **Industry** declares threat model, asset classes, required/optional services, workflows, and failure fixtures.
- **Geography** is a separate overlay reference that governs residency, legal notification clocks, evidence constraints, and regulatory cascades. It must not fork industry logic.
- **Developer type** chooses the surface and target time-to-first-verified-result (TTFVR), without changing receipt semantics.
- **Delivery, retention, and approval** narrow the platform's available options; a pack cannot create a new capability or bypass authorization.

## Stable contract bindings

The manifest records intended contract IDs for asset inventory, service catalog, policy engine, compliance registry, result delivery, residency guard, evidence retention, approval policy, workflow templates, conformance fixtures, and TTFVR measurement. These are binding points, not proof of active integrations. Follow-up work must inventory each referenced implementation and replace declaration-only state only when tests and runtime evidence prove the binding.

## Next gates

1. Wire the compiler into the CI conformance workflow and validate schema/compiler agreement.
2. Add the three exemplar packs: crypto exchange (EU), hospital (US), and solo developer.
3. Resolve each binding against implemented platform primitives and the Result Session contract.
4. Implement the six mandatory pack conformance tests and publish pass/fail artifacts.
5. Add a versioned geography overlay registry, compliance translation, trust budget, marketplace, community SDK, and per-pack TTFVR measurement.
