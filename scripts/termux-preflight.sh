#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
ROOT="$HOME/aurora-mobile"
RFS="$ROOT/build/rootfs"
STAGE="$ROOT/build/wifi-stage"
echo "=== Aurora 0.6: Termux preflight ==="
for f in "$RFS/sbin/init" "$ROOT/build/aurora-initramfs/init" "$HOME/aurora-kernel-analysis/zImage"; do
 if [ -f "$f" ]; then echo "OK $f"; else echo "MISSING $f"; fi
done
mkdir -p "$STAGE"
echo
echo "=== Search stock Wi-Fi files (read-only) ==="
for path in "$HOME/storage/downloads/aurora-wifi" "$HOME/aurora-wifi" "$ROOT/vendor"; do
 [ -d "$path" ] || continue
 find "$path" -type f \( -name 'pronto_wlan.ko' -o -name 'wlan.ko' -o -name 'WCNSS_qcom_wlan_nv.bin' \) -print
done
echo
echo "=== Stage files only when available ==="
for name in pronto_wlan.ko WCNSS_qcom_wlan_nv.bin; do
 found=""
 for dir in "$HOME/storage/downloads/aurora-wifi" "$HOME/aurora-wifi" "$ROOT/vendor"; do
  if [ -f "$dir/$name" ]; then found="$dir/$name"; break; fi
 done
 if [ -n "$found" ]; then cp "$found" "$STAGE/$name"; echo "STAGED $name"; else echo "NOT FOUND $name"; fi
done
echo
echo "=== Rootfs network binaries ==="
for bin in /usr/sbin/sshd /usr/sbin/wpa_supplicant /usr/sbin/iw /sbin/udhcpc /usr/bin/ssh /usr/bin/iw; do
 [ ! -e "$RFS$bin" ] || echo "PRESENT $bin"
done
echo
echo "=== Staged checksums ==="
find "$STAGE" -maxdepth 1 -type f -exec sha256sum {} \;
echo "No partitions, boot images, or existing rootfs files were changed."
