#!/usr/bin/env python3
"""Validate the threat registry and (re)generate docs/threat-test-map.md."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gateheal.threatmap import (
    RENDERED_RELATIVE_PATH,
    collect_all_tests,
    render_markdown,
    unmapped_tests,
    validate_registry,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wp8_threat_map", description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write", action="store_true", help="Rewrite docs/threat-test-map.md.")
    parser.add_argument(
        "--unmapped", action="store_true", help="List tests that no threat references."
    )
    args = parser.parse_args(argv)
    root: Path = args.repo_root

    errors = validate_registry(root)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1
    if args.unmapped:
        total = sum(len(names) for names in collect_all_tests(root).values())
        left = unmapped_tests(root)
        print(f"{sum(len(v) for v in left.values())} of {total} tests are not mapped to a threat")
        for file_path, names in left.items():
            print(f"{file_path}: {len(names)}")
            for name in names:
                print(f"  {name}")
        return 0
    rendered = render_markdown(root)
    target = root / RENDERED_RELATIVE_PATH
    if args.write:
        target.write_text(rendered, encoding="utf-8")
        print(f"Wrote {target}")
        return 0
    if not target.is_file() or target.read_text(encoding="utf-8") != rendered:
        print(f"ERROR: {RENDERED_RELATIVE_PATH} is stale; run with --write.", file=sys.stderr)
        return 1
    print("Threat map OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
