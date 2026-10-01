from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "sql"
VERSIONED = re.compile(r"^(?P<number>\d{3})_(?P<name>[a-zA-Z0-9][a-zA-Z0-9_-]*)\.sql$")
MARKER = re.compile(r"--[^\n\r]*(?:TODO|FIXME)\b", flags=re.IGNORECASE)


def main() -> int:
    files = sorted(SQL.glob("*.sql"))
    numbered: list[tuple[int, Path]] = []
    errors: list[str] = []
    seen_names: set[str] = set()

    for path in files:
        match = VERSIONED.match(path.name)
        if not match:
            continue

        if path.name in seen_names:
            errors.append(f"duplicate migration filename: {path.name}")
        seen_names.add(path.name)
        number = int(match.group("number"))
        numbered.append((number, path))

        text = path.read_text(encoding="utf-8")
        # Only flag unresolved markers in SQL comments. SQL literals such as
        # status = 'todo' are valid data values and must not fail validation.
        if MARKER.search(text):
            errors.append(f"unresolved marker in migration comment: {path.name}")

    numbered.sort(key=lambda item: (item[0], item[1].name))
    if not numbered:
        errors.append("no numbered SQL migrations found")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    numbers = [n for n, _ in numbered]
    print(f"validated {len(numbered)} numbered SQL migration sources")
    print("migration numbers:", ", ".join(f"{n:03d}" for n in numbers))
    unique_numbers = sorted(set(numbers))
    duplicates = sorted({n for n in unique_numbers if numbers.count(n) > 1})
    if duplicates:
        print(
            "note: historical source files share numeric prefixes: "
            + ", ".join(f"{n:03d}" for n in duplicates)
        )
    if any(b - a > 1 for a, b in zip(unique_numbers, unique_numbers[1:])):
        print("note: migration numbering contains non-sequential gaps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
