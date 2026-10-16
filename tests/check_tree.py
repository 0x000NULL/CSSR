"""Repository hygiene: no bundled binaries or documents, no large files, no known secrets.

Run from anywhere: python3 tests/check_tree.py
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BANNED_EXTENSIONS = {
    ".pdf", ".exe", ".msi", ".msu", ".dll", ".sys", ".jar", ".pyd", ".mui", ".zip", ".7z",
    ".rar", ".iso", ".vmdk", ".ova", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".odt",
}
MAX_BYTES = 2 * 1024 * 1024
# Strings that must never come back: private keys and the passwords the old scripts shared.
# Built from pieces so this file doesn't contain them (the history scrub rewrites literals).
BANNED_STRINGS = [
    "BEGIN " + "RSA PRIVATE KEY", "BEGIN " + "OPENSSH PRIVATE KEY", "BEGIN " + "PRIVATE KEY",
    "abc123" + "ABC123@@", "AllWeDo" + "IsWin", '"Cyber' + 'Patriot1"',
]


def main() -> int:
    files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                           capture_output=True).stdout.decode().split("\0")
    problems = []
    for name in filter(None, files):
        path = ROOT / name
        if not path.is_file():
            continue
        if path.suffix.lower() in BANNED_EXTENSIONS:
            problems.append(f"{name}: {path.suffix} files don't belong in the repo; link to them instead")
        if path.stat().st_size > MAX_BYTES:
            problems.append(f"{name}: larger than 2 MB")
        data = path.read_bytes()
        for s in BANNED_STRINGS:
            if s.encode() in data:
                problems.append(f"{name}: contains banned string {s!r}")
    for p in problems:
        print(p, file=sys.stderr)
    print(f"checked {len([f for f in files if f])} files, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
