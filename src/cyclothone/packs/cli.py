from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyclothone.global_language_registry import LanguageRegistryError, load_language_registry

from cyclothone.packs.capability_ceiling import CapabilityCeilingError, evaluate_capability_ceiling
from cyclothone.packs.dependency_lock import DependencyLockError, compile_dependency_lock
from cyclothone.packs.compiler import PackCompileError, build_pack_file
from cyclothone.packs.release import PackReleaseError, sign_compiled_pack, verify_signed_pack


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "lang":
        return _language_command(argv[1:])
    if argv and argv[0] == "pack":
        argv = argv[1:]
    parser = argparse.ArgumentParser(prog="cyclothone pack")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="validate and compile a declarative reference pack")
    build.add_argument("source", help="path to a declarative pack YAML file")
    build.add_argument("--out", required=True, help="path for deterministic compiled JSON artifact")
    build.add_argument(
        "--capabilities",
        help="JSON registry with services and delivery_bindings arrays; omitted means preview-only",
    )
    sign = subparsers.add_parser("sign", help="sign a conformant compiled bundle with an Ed25519 key")
    sign.add_argument("--artifact", required=True, help="compiled JSON artifact")
    sign.add_argument("--private-key", required=True, help="PEM Ed25519 private key; keep outside repository")
    sign.add_argument("--key-id", required=True, help="stable key-transparency identifier")
    sign.add_argument("--out", required=True, help="signed pack.bundle JSON envelope")
    lock = subparsers.add_parser("check-lock", help="validate immutable dependency pins and emit canonical lock digest")
    lock.add_argument("--lock", required=True, help="dependency lock JSON")
    lock.add_argument("--out", help="optional canonical lock report path")
    ceiling = subparsers.add_parser("check-ceiling", help="analyze a compiled pack against an explicit capability ceiling")
    ceiling.add_argument("--artifact", required=True, help="compiled artifact JSON")
    ceiling.add_argument("--ceiling", required=True, help="versioned effective ceiling JSON")
    ceiling.add_argument("--out", help="optional JSON analysis report path")
    verify = subparsers.add_parser("verify", help="verify a signed pack.bundle offline")
    verify.add_argument("--bundle", required=True, help="signed pack.bundle JSON envelope")
    verify.add_argument("--public-key", required=True, help="trusted Ed25519 public key PEM")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            artifact = build_pack_file(args.source, args.out, capabilities_file=args.capabilities)
            print(
                f"{artifact['pack_id']}: {artifact['publication_state']} "
                f"sha256={artifact['artifact_sha256']} output={args.out}"
            )
            if artifact["publication_state"] == "preview":
                print("unresolved references remain; this artifact is not conformant or production-ready", file=sys.stderr)
            return 0
        if args.command == "check-lock":
            try:
                lock_input = json.loads(Path(args.lock).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise DependencyLockError(f"lock_input_read_failed:{type(exc).__name__}") from exc
            report = compile_dependency_lock(lock_input)
            rendered = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
            if args.out:
                Path(args.out).write_text(rendered, encoding="utf-8")
            print(rendered, end="")
            return 0 if report["status"] == "pass" else 2
        if args.command == "check-ceiling":
            try:
                artifact = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
                effective_ceiling = json.loads(Path(args.ceiling).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise CapabilityCeilingError(f"ceiling_input_read_failed:{type(exc).__name__}") from exc
            report = evaluate_capability_ceiling(artifact, effective_ceiling)
            rendered = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
            if args.out:
                Path(args.out).write_text(rendered, encoding="utf-8")

            print(rendered, end="")
            return 0 if report["status"] == "pass" else 2
        if args.command == "sign":
            envelope = sign_compiled_pack(args.artifact, args.private_key, args.key_id, args.out)
            print(f"{envelope['manifest']['pack_id']}: signed sha256={envelope['manifest']['artifact_sha256']} output={args.out}")
            return 0
        result = verify_signed_pack(args.bundle, args.public_key)
        print(f"{result['pack_id']}: verified sha256={result['artifact_sha256']} key_id={result['key_id']}")
        return 0
    except (PackCompileError, PackReleaseError, CapabilityCeilingError, DependencyLockError) as exc:
        print(f"pack {args.command} failed: {exc}", file=sys.stderr)
        return 2


def _language_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="cyclothone lang")
    subparsers = parser.add_subparsers(dest="command", required=True)
    status = subparsers.add_parser("status", help="report locale-tier parity from a versioned registry")
    status.add_argument("--registry", required=True, help="path to the language registry JSON")
    status.add_argument("--minimum-tier", type=int, default=1, choices=(1, 2, 3, 4),
                        help="block release when required units are missing at this tier or higher")
    args = parser.parse_args(argv)
    try:
        result = load_language_registry(args.registry, minimum_tier=args.minimum_tier)
    except LanguageRegistryError as exc:
        print(f"lang status failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
