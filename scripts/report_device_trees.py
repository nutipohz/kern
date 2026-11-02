#!/usr/bin/env python3
"""Generate readable hardware identification report for extracted Qualcomm DTBs."""
import json
import subprocess
from pathlib import Path

root = Path("extracted/segments")
report = []
for dtb in sorted(root.glob("*_dtb_*.dtb")):
    record = {"file": dtb.name}
    for prop in ("model", "compatible", "qcom,msm-id", "qcom,board-id", "qcom,pmic-id"):
        cmd = ["fdtget", "-t", "x" if prop.startswith("qcom,") else "s", str(dtb), "/", prop]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            record[prop] = result.stdout.strip()
    report.append(record)

out = Path("extracted/device-trees.json")
out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
for entry in report:
    print(f"DTB {entry['file']}: model={entry.get('model', 'n/a')}; compatible={entry.get('compatible', 'n/a')}; msm-id={entry.get('qcom,msm-id', 'n/a')}; board-id={entry.get('qcom,board-id', 'n/a')}")
print(f"Inspected {len(report)} DTBs; no flashable image created.")
