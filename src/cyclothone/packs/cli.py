from __future__ import annotations

import argparse
import sys

from cyclothone.packs.compiler import PackCompileError, build_pack_file
from cyclothone.packs.release import PackReleaseError, sign_compiled_pack, verify_signed_pack


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
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
        if args.command == "sign":
            envelope = sign_compiled_pack(args.artifact, args.private_key, args.key_id, args.out)
            print(f"{envelope['manifest']['pack_id']}: signed sha256={envelope['manifest']['artifact_sha256']} output={args.out}")
            return 0
        result = verify_signed_pack(args.bundle, args.public_key)
        print(f"{result['pack_id']}: verified sha256={result['artifact_sha256']} key_id={result['key_id']}")
        return 0
    except (PackCompileError, PackReleaseError) as exc:
        print(f"pack {args.command} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
