#!/usr/bin/env python3
"""Non-destructive signature and ramdisk inspection of Sony ELF segments."""
import gzip
import json
import struct
from pathlib import Path

root = Path("extracted/segments")
result = {}
for path in sorted(root.glob("segment_*.bin")):
    data = path.read_bytes()
    info = {"size": len(data), "first32_hex": data[:32].hex()}
    if data.startswith(b"\x1f\x8b"):
        try:
            decoded = gzip.decompress(data)
            info["gzip_uncompressed_size"] = len(decoded)
            info["gzip_first16_hex"] = decoded[:16].hex()
            info["gzip_is_cpio_newc"] = decoded.startswith((b"070701", b"070702"))
            if info["gzip_is_cpio_newc"]:
                entries = []
                off = 0
                while off + 110 <= len(decoded) and len(entries) < 5000:
                    hdr = decoded[off:off + 110]
                    if hdr[:6] not in (b"070701", b"070702"):
                        break
                    namesize = int(hdr[94:102], 16)
                    filesize = int(hdr[54:62], 16)
                    if namesize < 1 or namesize > 4096:
                        break
                    start = off + 110
                    name = decoded[start:start + namesize].rstrip(b"\x00").decode("utf-8", "replace")
                    if name == "TRAILER!!!":
                        break
                    entries.append(name)
                    content = (start + namesize + 3) & ~3
                    off = (content + filesize + 3) & ~3
                info["cpio_file_count_listed"] = len(entries)
                info["cpio_sample_paths"] = entries[:100]
        except Exception as exc:
            info["gzip_error"] = str(exc)
    dtbs = []
    magic = b"\xd0\x0d\xfe\xed"
    start = 0
    while len(dtbs) < 32:
        off = data.find(magic, start)
        if off < 0: break
        start = off + 4
        if off + 40 > len(data): continue
        size = struct.unpack_from(">I", data, off + 4)[0]
        version = struct.unpack_from(">I", data, off + 20)[0]
        if size < 40 or off + size > len(data) or not (1 <= version <= 30): continue
        dtbs.append({"offset": off, "size": size, "version": version})
        (root / f"{path.stem}_dtb_{len(dtbs):02d}.dtb").write_bytes(data[off:off + size])
    info["embedded_dtbs"] = dtbs
    info["qcdt_offsets"] = [i for i in range(len(data)) if data.startswith(b"QCDT",i)][:10] if len(data)<3_000_000 else []
    result[path.name] = info
Path("extracted/payload-analysis.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
