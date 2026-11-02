#!/usr/bin/env python3
"""Compile every YARA rule and check each test file hits exactly the rules
listed for it in testdata/rules/expect.json. Also fails if a rule has no
positive test at all, so a new rule can't land untested.

    pip install yara-python
    python3 scripts/test_rules.py
"""
import json
import pathlib
import sys

import yara

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    rules_dir = ROOT / "rules" / "yara"
    sources = {p.stem: str(p) for p in sorted(rules_dir.glob("*.yar"))}
    rules = yara.compile(filepaths=sources)
    declared = set()
    for path in sources.values():
        for r in yara.compile(filepath=path):
            declared.add(r.identifier)

    expect = json.loads((ROOT / "testdata" / "rules" / "expect.json").read_text())
    expect.pop("_comment", None)

    failures = 0
    covered = set()
    for rel, want in sorted(expect.items()):
        path = ROOT / rel
        if not path.exists():
            print(f"MISSING  {rel}")
            failures += 1
            continue
        got = sorted({m.rule for m in rules.match(str(path))})
        covered.update(got)
        if got != sorted(want):
            print(f"FAIL     {rel}\n         want {sorted(want)}\n         got  {got}")
            failures += 1
        else:
            print(f"ok       {rel}  {', '.join(got) or '(no match)'}")

    untested = declared - covered
    for r in sorted(untested):
        print(f"UNTESTED {r}: no positive sample in expect.json")
        failures += 1

    print(f"\n{len(expect)} files, {len(declared)} rules, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
