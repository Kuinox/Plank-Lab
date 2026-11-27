#!/usr/bin/env bash
# Cross-ISA differential: compare the per-input digests two replay runs wrote with PLANK_FUZZ_DIGEST_FILE.
# Usage: digest-compare.sh dg-avx512.txt dg-scalar.txt   (prints differing inputs; exit 1 if any)
set -eu
join -t $'\t' <(sort -u "$1") <(sort -u "$2") | awk -F'\t' '$2 != $3 { print "DIFF", $1, $2, $3; bad=1 } END { print NR " inputs compared"; exit bad }'
