from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "sql"
VERSIONED = re.compile(r"^(?P<number>\d{3})_(?P<name>[a-zA-Z0-9][a-zA-Z0-9_-]*)\.sql$")


def main() -> int:
    files = sorted(SQL.glob("*.sql"))
    numbered: list[tuple[int, Path]] = []
    seen: set[int] = set()
    errors: list[str] = []

    for path in files:
        match = VERSIONED.match(path.name)
        if not match:
            continue
        number = int(match.group("number"))
        if number in seen:
            errors.append(f"duplicate migration number: {number:03d}")
        seen.add(number)
        numbered.append((number, path))

        text = path.read_text(encoding="utf-8")
        if re.search(r"\b(TODO|FIXME)\b", text, flags=re.IGNORECASE):
            errors.append(f"unresolved marker in migration: {path.name}")

    numbered.sort()
    if not numbered:
        errors.append("no numbered SQL migrations found")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    numbers = [n for n, _ in numbered]
    print(f"validated {len(numbered)} numbered SQL migration sources")
    print("migration numbers:", ", ".join(f"{n:03d}" for n in numbers))
    if any(b - a > 1 for a, b in zip(numbers, numbers[1:])):
        print("note: migration numbering contains non-sequential gaps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
