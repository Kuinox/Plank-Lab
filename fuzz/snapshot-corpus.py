#!/usr/bin/env python3
"""Freeze a fuzz input tree for one coverage run.

Queue inputs are immutable, so hard-linking them avoids copying a gigabyte of
saved cases. Generated seed files can be rewritten, so use --copy for those.
Files removed by a live AFL worker during traversal are skipped; every ISA
tier still replays the same completed snapshot.
"""
import argparse
import os
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('destination')
    parser.add_argument('--copy', action='store_true', help='copy bytes instead of hard-linking')
    args = parser.parse_args()
    if not os.path.isdir(args.source):
        parser.error(f'not a directory: {args.source}')
    os.makedirs(args.destination, exist_ok=True)
    copied = missing = 0
    for root, dirs, files in os.walk(args.source):
        relative = os.path.relpath(root, args.source)
        target = os.path.join(args.destination, relative)
        os.makedirs(target, exist_ok=True)
        for name in files:
            source = os.path.join(root, name)
            destination = os.path.join(target, name)
            try:
                if args.copy:
                    shutil.copy2(source, destination)
                else:
                    os.link(source, destination)
                copied += 1
            except FileNotFoundError:
                missing += 1
    print(f'{copied} inputs snapshotted; {missing} disappeared during traversal')


if __name__ == '__main__':
    main()
