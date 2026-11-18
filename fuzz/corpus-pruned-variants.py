#!/usr/bin/env python3
"""Add page-pruner selector variants for the deterministic multi-page seeds.

Usage: corpus-pruned-variants.py INPUT_DIR OUTPUT_DIR

The first byte of reader corpus inputs is a target selector. Bit 3 requests
plain/pruned/sparse page-scan cross-checks. Restricting variants to the large
split-page seeds keeps the corpus small while guaranteeing that pruning can
skip at least one physical page.
"""

from __future__ import annotations

import argparse
from pathlib import Path


PREFIX = "gen-width-split-"
PRUNED_BIT = 0x08


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        parser.error(f"input directory does not exist: {args.input_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for source in sorted(args.input_dir.glob(f"{PREFIX}*.bin")):
        payload = source.read_bytes()
        if not payload:
            continue
        # Bit 0 selects projection, which bypasses the file-schema pruning
        # oracle. Such files are intentionally left alone.
        if payload[0] & 0x01:
            continue
        destination = args.output_dir / f"pruned-{source.name}"
        if destination.exists():
            continue
        destination.write_bytes(bytes([payload[0] | PRUNED_BIT]) + payload[1:])
        count += 1
    print(f"wrote {count} pruned variants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
