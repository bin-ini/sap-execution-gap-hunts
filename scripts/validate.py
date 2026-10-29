#!/usr/bin/env python3
"""Repo validation used by CI and locally. Stdlib only — no pip install needed.

Checks:
  * every notebook is valid JSON with a 'cells' list, and every code cell parses as Python;
  * every hunt .kql is non-empty, carries the required header fields, and has balanced ()/[] /{}.

Run: python scripts/validate.py
"""
from __future__ import annotations
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_HEADER_FIELDS = ("Hunt ID", "Title", "Hypothesis", "MITRE", "Data")

errors: list[str] = []


def check_notebooks() -> None:
    nbs = sorted((ROOT / "notebooks").glob("*.ipynb"))
    if not nbs:
        errors.append("notebooks/: no .ipynb found")
        return
    for nb_path in nbs:
        try:
            nb = json.loads(nb_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{nb_path.name}: invalid JSON — {exc}")
            continue
        if not isinstance(nb.get("cells"), list):
            errors.append(f"{nb_path.name}: missing 'cells' list")
            continue
        for i, cell in enumerate(nb["cells"]):
            if cell.get("cell_type") != "code":
                continue
            src = "".join(cell.get("source", []))
            code = "\n".join(l for l in src.split("\n") if not l.strip().startswith("%"))
            try:
                ast.parse(code)
            except SyntaxError as exc:
                errors.append(f"{nb_path.name}: code cell {i} syntax error — {exc}")
        print(f"ok   {nb_path.relative_to(ROOT)} ({len(nb['cells'])} cells)")


def check_hunts() -> None:
    kqls = sorted((ROOT / "hunts").glob("*.kql"))
    if not kqls:
        errors.append("hunts/: no .kql found")
        return
    pairs = {"(": ")", "[": "]", "{": "}"}
    for kql in kqls:
        text = kql.read_text(encoding="utf-8")
        if not text.strip():
            errors.append(f"{kql.name}: empty")
            continue
        low = text.lower()
        for field in REQUIRED_HEADER_FIELDS:
            f = field.lower()
            if f"// {f}" not in low and f"//{f}" not in low:
                errors.append(f"{kql.name}: missing header field '{field}'")
        # balance check on executable (non-comment) lines only
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
        counts = {k: body.count(k) - body.count(v) for k, v in pairs.items()}
        unbalanced = {k: c for k, c in counts.items() if c != 0}
        if unbalanced:
            errors.append(f"{kql.name}: unbalanced brackets {unbalanced}")
        print(f"ok   {kql.relative_to(ROOT)}")


def main() -> int:
    check_notebooks()
    check_hunts()
    if errors:
        print("\nVALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
