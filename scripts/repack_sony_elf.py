#!/usr/bin/env python3
"""Repack Sony ELF PT_LOAD segments without changing their load addresses.

This is an experimental offline artifact. Never flash without verifying bootloader
acceptance, DTB selection, memory layout and on-device behavior.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("original", type=Path)
p.add_argument("output", type=Path)
p.add_argument("--ramdisk", type=Path, help="Optional replacement gzip CPIO ramdisk")
a = p.parse_args()
original = a.original.read_bytes()
if original[:4] != b"\x7fELF" or original[4] != 2 or original[5] != 1:
    raise SystemExit("Expected little-endian ELF64 Sony container")
eh = bytearray(original[:64])
phoff = struct.unpack_from("<Q", eh, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", eh, 54)
if phnum != 3 or phentsize < 56 or phoff != 64:
    raise SystemExit("Unknown Sony ELF layout. Refusing to repackage.")
headers = []
for i in range(phnum):
    entry = bytearray(original[phoff + i * phentsize:phoff + (i + 1) * phentsize])
    if len(entry) != phentsize:
        raise SystemExit("Truncated ELF program headers")
    typ, flags, offset, va, pa, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", entry, 0)
    if typ != 1 or offset + filesz > len(original):
        raise SystemExit("Unsupported ELF program segment")
    headers.append({"entry": entry, "offset": offset, "size": filesz, "memsize": memsz, "paddr": pa})
if [h["paddr"] for h in headers] != [0x80080000, 0x82000000, 0x81e00000]:
    raise SystemExit("Unexpected load addresses, refusing to repack")
segments = [original[h["offset"]:h["offset"]+h["size"]] for h in headers]
if a.ramdisk:
    import gzip
    ramdisk = a.ramdisk.read_bytes()
    if not ramdisk.startswith(b"\x1f\x8b") or not gzip.decompress(ramdisk).startswith((b"070701",b"070702")):
        raise SystemExit("Replacement ramdisk must be gzip CPIO newc")
    # Keep memory layout bounds conservative until boot testing.
    if len(ramdisk) > 4 * 1024 * 1024:
        raise SystemExit("Experimental ramdisk exceeds 4 MiB conservative limit")
    segments[1] = ramdisk
body = bytearray(eh)
for h in headers:
    body.extend(h["entry"])
for idx, (h, payload) in enumerate(zip(headers, segments)):
    new_offset = len(body)
    # preserve physical load addresses and keep memsz sufficient
    struct.pack_into("<Q", body, phoff + idx * phentsize + 8, new_offset)
    struct.pack_into("<Q", body, phoff + idx * phentsize + 32, len(payload))
    struct.pack_into("<Q", body, phoff + idx * phentsize + 40, max(h["memsize"], len(payload)))
    body.extend(payload)
last_end = max(h["offset"] + h["size"] for h in headers)
# Sony may append padding/trailer bytes outside PT_LOAD. Preserve them.
body.extend(original[last_end:])
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_bytes(body)
# Verifying unchanged source image round trip is important before replacing ramdisk.
identical = bytes(body) == original
report = {
    "original_sha256": hashlib.sha256(original).hexdigest(),
    "output_sha256": hashlib.sha256(body).hexdigest(),
    "identical_to_original": identical,
    "ramdisk_replaced": bool(a.ramdisk),
    "segments": [
        {"index": i, "paddr": hex(h["paddr"]), "size": len(payload)}
        for i, (h, payload) in enumerate(zip(headers, segments))
    ],
    "warning": "Research Sony ELF container, NOT a verified fastboot-flashable boot.img"
}
print(json.dumps(report, indent=2))
if not a.ramdisk and not identical:
    raise SystemExit("ERROR: unmodified round trip must be byte-identical")
