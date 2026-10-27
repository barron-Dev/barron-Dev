"""Cyclothone developer CLI entrypoint."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyclothone.packs.compiler import PackCompileError, compile_pack, load_pack


def _pack_build(args: argparse.Namespace) -> int:
    try:
        pack = load_pack(args.pack_file)
        manifest = compile_pack(pack)
        output = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output, encoding="utf-8")
            print(f"Compiled {manifest['pack_id']} -> {destination}")
            print(f"Pack SHA-256: {manifest['pack_sha256']}")
            print("Status: compiled_unverified (conformance not run)")
        else:
            sys.stdout.write(output)
        return 0
    except PackCompileError as exc:
        print(f"cyclothone pack build: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyclothone", description="Cyclothone developer tools")
    commands = parser.add_subparsers(dest="command", required=True)
    pack_parser = commands.add_parser("pack", help="declarative industry pack operations")
    pack_commands = pack_parser.add_subparsers(dest="pack_command", required=True)
    build = pack_commands.add_parser("build", help="validate and compile a declarative YAML pack")
    build.add_argument("pack_file", help="path to a pack YAML file")
    build.add_argument("--output", "-o", help="write compiled JSON manifest to this path")
    build.set_defaults(handler=_pack_build)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
