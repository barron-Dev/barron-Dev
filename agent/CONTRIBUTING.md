# Agent contribution rules

When changing a Rust struct field in the agent:

1. Run `cargo check -p cyclothone-agent --all-targets` locally.
2. Search all struct literals with `grep -rn "StructName {" agent/src/`.
3. Update every literal explicitly unless `Default::default()` is intentionally valid for every field.
4. Keep the CI all-targets check passing before pushing.

The agent CI must compile test targets, not only the library target, so test constructors cannot silently drift from wire-format structs.
