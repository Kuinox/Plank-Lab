#!/usr/bin/env python3
"""Line / branch coverage of the codec code from two coverlet cobertura files (before, after).

Groups: Plank write-side codecs (Writing/Compression), Plank zlib glue (Compression/), Plank read-side decompressors
(Reading/*Decompressor*, GzipInflater), and the vendored Plank.K4os.LZ4 package (split into the encoder side,
the decoder side and the rest by file name).

Usage: codec-coverage.py before.xml after.xml
"""
import re
import sys
import xml.etree.ElementTree as ET


def load(path):
    files = {}
    root = ET.parse(path).getroot()
    for package in root.iter("package"):
        for cls in package.iter("class"):
            name = cls.get("filename", "").replace("\\", "/")
            entry = files.setdefault((package.get("name"), name), {"lines": {}, "branches": {}})
            for line in cls.iter("line"):
                number = int(line.get("number"))
                hits = int(line.get("hits"))
                entry["lines"][number] = max(entry["lines"].get(number, 0), hits)
                if line.get("branch") == "True":
                    m = re.search(r"\((\d+)/(\d+)\)", line.get("condition-coverage", ""))
                    if m:
                        covered, total = int(m.group(1)), int(m.group(2))
                        old = entry["branches"].get(number, (0, total))
                        entry["branches"][number] = (max(old[0], covered), total)
    return files


def group(package, name):
    low = name.lower()
    if package == "Plank.K4os.LZ4" or "k4os" in low:
        if "encode" in low or "encoder" in low or "pickler" in low:
            return "K4os LZ4 (encoder)"
        if "decode" in low or "decoder" in low:
            return "K4os LZ4 (decoder)"
        return "K4os LZ4 (other)"
    if "writing/compression/" in low:
        return "Plank Writing/Compression"
    if "/compression/" in low and "plank/" in low:
        return "Plank zlib glue (Compression/)"
    if "decompressor" in low or "gzipinflater" in low:
        return "Plank read-side decompressors"
    return None


def totals(files):
    out = {}
    for (package, name), entry in files.items():
        g = group(package, name)
        if g is None:
            continue
        t = out.setdefault(g, [0, 0, 0, 0])
        t[0] += sum(1 for h in entry["lines"].values() if h > 0)
        t[1] += len(entry["lines"])
        t[2] += sum(c for c, _ in entry["branches"].values())
        t[3] += sum(n for _, n in entry["branches"].values())
    return out


before, after = totals(load(sys.argv[1])), totals(load(sys.argv[2]))
print(f"{'group':36s} {'lines before':>16s} {'lines after':>16s} {'branches before':>18s} {'branches after':>18s}")
for g in sorted(set(before) | set(after)):
    b, a = before.get(g, [0, 0, 0, 0]), after.get(g, [0, 0, 0, 0])
    pct = lambda x, y: f"{100 * x / y:5.1f}% ({x}/{y})" if y else "n/a"
    print(f"{g:36s} {pct(b[0], b[1]):>16s} {pct(a[0], a[1]):>16s} {pct(b[2], b[3]):>18s} {pct(a[2], a[3]):>18s}")
