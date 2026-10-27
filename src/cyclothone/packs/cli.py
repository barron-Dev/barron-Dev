from __future__ import annotations

import argparse
import sys

from cyclothone.packs.compiler import PackCompileError, build_pack_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyclothone pack")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="validate and compile a declarative reference pack")
    build.add_argument("source", help="path to a declarative pack YAML file")
    build.add_argument("--out", required=True, help="path for deterministic compiled JSON artifact")
    build.add_argument(
        "--capabilities",
        help="JSON registry with services and delivery_bindings arrays; omitted means preview-only",
    )
    args = parser.parse_args(argv)
    try:
        artifact = build_pack_file(args.source, args.out, capabilities_file=args.capabilities)
    except PackCompileError as exc:
        print(f"pack build failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"{artifact['pack_id']}: {artifact['publication_state']} "
        f"sha256={artifact['artifact_sha256']} output={args.out}"
    )
    if artifact["publication_state"] == "preview":
        print("unresolved references remain; this artifact is not conformant or production-ready", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
