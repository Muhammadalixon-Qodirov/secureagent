"""Validate knowledge cards in data/knowledge_cards against the built knowledge base.

Checks
  - every id in a `refs` / `refs_*` list exists in data/knowledge/chunks.jsonl
  - card CWE ids belong to the card's family in data/security_catalog.yaml
  - every claim item has either refs or `basis: reviewer_reasoning`
  - examples are labelled with their origin

    python scripts/validate_cards.py          # validate
    python scripts/validate_cards.py --show   # also print the title of every cited chunk
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CARDS = ROOT / "data" / "knowledge_cards"
CLAIM_LISTS = ("sinks", "effective_controls", "ineffective_or_partial_controls",
               "false_positive_patterns", "protected_operations")


def collect_refs(node, path="") -> list[tuple[str, str]]:
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k.startswith("refs") and isinstance(v, list):
                out += [(f"{path}.{k}", r) for r in v]
            else:
                out += collect_refs(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += collect_refs(v, f"{path}[{i}]")
    return out


def main() -> int:
    show = "--show" in sys.argv
    chunks = {}
    with (ROOT / "data" / "knowledge" / "chunks.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            c = json.loads(line)
            chunks[c["id"]] = c
    catalog = yaml.safe_load((ROOT / "data" / "security_catalog.yaml").read_text(encoding="utf-8"))
    families = {f["id"]: f for f in catalog["families"]}

    errors: list[str] = []
    totals = {"cards": 0, "refs": 0, "sourced_claims": 0, "reasoning_claims": 0}
    for path in sorted(CARDS.glob("*.yaml")):
        name = path.name
        totals["cards"] += 1
        try:
            card = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{name}: invalid YAML: {exc}")
            continue

        fam = families.get(card.get("family"))
        if fam is None:
            errors.append(f"{name}: unknown family {card.get('family')!r}")
        else:
            allowed = {c["id"] for c in fam["cwe"]}
            used = {card["cwe"]["primary"], *card["cwe"].get("related", [])}
            if used - allowed:
                errors.append(f"{name}: CWE ids not in catalog family: {sorted(used - allowed)}")

        for where, ref in collect_refs(card):
            totals["refs"] += 1
            if ref not in chunks:
                errors.append(f"{name}{where}: unknown chunk id {ref}")
            elif show:
                print(f"  {name:28s} {ref:62s} {chunks[ref]['title'][:70]}")

        for key in CLAIM_LISTS:
            for i, item in enumerate(card.get(key, []) or []):
                has_refs = any(k.startswith("refs") for k in item)
                reasoning = item.get("basis") == "reviewer_reasoning"
                if has_refs:
                    totals["sourced_claims"] += 1
                elif reasoning:
                    totals["reasoning_claims"] += 1
                else:
                    errors.append(f"{name}.{key}[{i}]: claim has neither refs nor basis: reviewer_reasoning")

        if not str(card.get("example", {}).get("origin", "")).strip():
            errors.append(f"{name}: example.origin is missing")

    print(f"cards: {totals['cards']}  refs: {totals['refs']}  "
          f"sourced claims: {totals['sourced_claims']}  reviewer-reasoning claims: {totals['reasoning_claims']}")
    if errors:
        print(f"\n{len(errors)} error(s):")
        for e in errors:
            print("  -", e)
        return 1
    print("all cards valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
