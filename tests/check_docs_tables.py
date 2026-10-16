"""Check that the check tables in docs/audit-scripts.md match the scripts.

Usage:
    audit/linux/cssr-audit.sh --list-checks --markdown | python3 tests/check_docs_tables.py linux
    powershell -File audit/windows/CSSR-Audit.ps1 -ListChecks -Markdown | python tests/check_docs_tables.py windows

With --write, replace the table in the docs instead of comparing.
"""
import difflib
import pathlib
import re
import sys

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "audit-scripts.md"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--write" in sys.argv
    if len(args) != 1 or args[0] not in ("linux", "windows"):
        print(__doc__, file=sys.stderr)
        return 2
    name = args[0].upper()
    generated = "\n".join(line.rstrip() for line in sys.stdin.read().strip().splitlines())
    text = DOC.read_text(encoding="utf-8").replace("\r\n", "\n")
    pattern = re.compile(
        rf"(<!-- BEGIN {name} CHECKS -->\n)(.*?)(<!-- END {name} CHECKS -->)", re.S
    )
    match = pattern.search(text)
    if not match:
        print(f"{DOC}: no BEGIN/END {name} CHECKS markers", file=sys.stderr)
        return 1
    if write:
        DOC.write_text(pattern.sub(lambda m: m.group(1) + generated + "\n" + m.group(3), text),
                       encoding="utf-8")
        print(f"Updated the {name.lower()} table in {DOC}")
        return 0
    if match.group(2).strip() != generated:
        diff = difflib.unified_diff(match.group(2).strip().splitlines(), generated.splitlines(),
                                    "docs", "script", lineterm="")
        print("\n".join(diff), file=sys.stderr)
        print(f"The {name.lower()} check table in {DOC} is out of date. Regenerate it with:\n"
              f"  ... --list-checks --markdown | python3 tests/check_docs_tables.py "
              f"{name.lower()} --write", file=sys.stderr)
        return 1
    print(f"{name.lower()} check table is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
