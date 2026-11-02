#!/usr/bin/env python3
"""Read-only identification of factory kernel, Android ramdisk and E2312 evidence."""
import gzip
import json
import re
from pathlib import Path

out = Path("extracted")
root = out / "segments"
findings = {"kernel_versions": [], "ramdisk_matches": [], "device_tree_matches": [], "note": "Indicators only. Exact E2312 hardware compatibility and Wi-Fi module ABI remain unverified."}

kernel = (root / "segment_00.bin").read_bytes()
for match in re.finditer(rb"Linux version [^\x00\r\n]{8,180}", kernel):
    s = match.group().decode("ascii", "replace")
    if s not in findings["kernel_versions"]:
        findings["kernel_versions"].append(s[:180])
        if len(findings["kernel_versions"]) >= 8:
            break

ramdisk = gzip.decompress((root / "segment_01.bin").read_bytes())
pos = 0
target = re.compile(r"(^|/)(init[^/]*\.(?:rc|sh)|default\.prop|fstab[^/]*)$")
terms = re.compile(r"wcnss|wlan|pronto|insmod|tulip|sony|e2312|wpa_supplicant|cnss|firmware", re.I)
while pos + 110 <= len(ramdisk):
    header = ramdisk[pos:pos + 110]
    if header[:6] not in (b"070701", b"070702"):
        break
    try:
        size = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
    except ValueError:
        break
    if namesize < 1 or namesize > 4096:
        break
    nstart = pos + 110
    name = ramdisk[nstart:nstart + namesize].rstrip(b"\x00").decode("utf-8", "replace")
    if name == "TRAILER!!!":
        break
    content_start = (nstart + namesize + 3) & ~3
    content_end = content_start + size
    if content_end > len(ramdisk):
        break
    if target.search(name) and size <= 2_000_000:
        body = ramdisk[content_start:content_end].decode("utf-8", "replace")
        for lineno, line in enumerate(body.splitlines(), 1):
            if terms.search(line):
                findings["ramdisk_matches"].append({"file": name, "line": lineno, "text": line.strip()[:240]})
                if len(findings["ramdisk_matches"]) >= 150:
                    break
    pos = (content_end + 3) & ~3
    if len(findings["ramdisk_matches"]) >= 150:
        break

for dtb in sorted(root.glob("*_dtb_*.dtb")):
    blob = dtb.read_bytes()
    indicators = []
    for term in (b"sony", b"somc", b"tulip", b"e2312", b"msm8939", b"msm8936", b"msm8916"):
        if term in blob.lower():
            indicators.append(term.decode())
    findings["device_tree_matches"].append({"file": dtb.name, "string_indicators": indicators})

(out / "factory-identification.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n")
print("=== FACTORY IDENTIFICATION ===")
print("Kernel versions:", findings["kernel_versions"])
print("RAMDISK Wi-Fi and model references:", len(findings["ramdisk_matches"]))
for row in findings["ramdisk_matches"][:35]:
    print(f"{row['file']}:{row['line']}: {row['text']}")
for row in findings["device_tree_matches"]:
    print(row["file"], row["string_indicators"])
print(findings["note"])
