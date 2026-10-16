"""Every `goto LABEL` in a batch file must have a matching `:LABEL`.

Run from anywhere: python3 tests/check_bat_labels.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    problems = 0
    files = sorted(p for p in ROOT.rglob("*") if p.suffix.lower() in (".bat", ".cmd")
                   and ".git" not in p.parts)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        labels = {m.group(1).lower() for m in re.finditer(r"^\s*:([^\s:]+)", text, re.M)}
        for m in re.finditer(r"\bgoto\s+:?([^\s)&|\"]+)", text, re.I):
            target = m.group(1).lower()
            if target == "eof" or "%" in target:
                continue
            if target not in labels:
                line = text.count("\n", 0, m.start()) + 1
                print(f"{path.relative_to(ROOT)}:{line}: goto {m.group(1)} has no label",
                      file=sys.stderr)
                problems += 1
    print(f"checked {len(files)} batch files, {problems} unmatched gotos")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
