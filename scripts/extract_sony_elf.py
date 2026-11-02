#!/usr/bin/env python3
"""Inspect and extract PT_LOAD segments from a Sony Xperia ELF container.
No flashing, repacking, or image assumptions.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "kernel.elf")
dest = Path(sys.argv[2] if len(sys.argv) > 2 else "extracted")
dest.mkdir(parents=True, exist_ok=True)
with src.open("rb") as handle:
    eh = handle.read(64)
    if len(eh) < 64 or eh[:4] != b"\x7fELF" or eh[4] != 2 or eh[5] != 1:
        raise SystemExit("ERROR: expected ELF64 little-endian container")
    if struct.unpack_from("<H", eh, 18)[0] != 183:
        raise SystemExit("ERROR: expected AArch64 ELF (e_machine=183)")
    phoff = struct.unpack_from("<Q", eh, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", eh, 54)
    if phentsize < 56 or phnum == 0 or phnum > 128:
        raise SystemExit("ERROR: implausible ELF program header table")
    handle.seek(0, 2)
    length = handle.tell()
    if phoff + phentsize * phnum > length:
        raise SystemExit("ERROR: program header table outside file")
    segments = []
    for n in range(phnum):
        handle.seek(phoff + n * phentsize)
        ph = handle.read(56)
        typ, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack("<IIQQQQQQ", ph)
        if typ != 1:
            continue
        if offset > length or filesz > length - offset:
            raise SystemExit(f"ERROR: segment {n} exceeds file bounds")
        if filesz > 100 * 1024 * 1024:
            raise SystemExit(f"ERROR: segment {n} unreasonably large")
        handle.seek(offset)
        data = handle.read(filesz)
        if len(data) != filesz:
            raise SystemExit(f"ERROR: short read of segment {n}")
        label = "unknown"
        if data.startswith(b"ANDROID!"):
            label = "android_boot_image"
        elif data.startswith(b"\x1f\x8b"):
            label = "gzip"
        elif data.startswith(b"\xfd7zXZ\x00"):
            label = "xz"
        elif data.startswith(b"\x04\x22\x4d\x18"):
            label = "lz4_frame"
        elif data[:4] == b"\xd0\x0d\xfe\xed":
            label = "device_tree_blob"
        elif data.startswith(b"070701") or data.startswith(b"070702"):
            label = "cpio_newc"
        elif data[:4] == b"\x7fELF":
            label = "elf"
        name = f"segment_{n:02d}.bin"
        (dest / name).write_bytes(data)
        segments.append({"file": name, "file_offset": offset, "size": filesz, "load_address": hex(paddr), "virtual_address": hex(vaddr), "flags": flags, "signature": label, "sha256": hashlib.sha256(data).hexdigest()})
    if not segments:
        raise SystemExit("ERROR: no PT_LOAD segments found")
    report = {"source_name": src.name, "source_size": length, "segments": segments, "note": "Segment signatures are preliminary; this is not a flashable boot.img. No boot or hardware compatibility claim."}
    (dest / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
