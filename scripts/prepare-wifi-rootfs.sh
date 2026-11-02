#!/data/data/com.termux/files/usr/bin/bash
# Stage stock firmware in the Alpine rootfs; never flash or load kernel modules.
set -euo pipefail
ROOT="$HOME/aurora-mobile"
RFS="$ROOT/build/rootfs"
STAGE="$ROOT/build/wifi-stage"
MODULE="$STAGE/pronto_wlan.ko"
NV="$STAGE/WCNSS_qcom_wlan_nv.bin"
[ -s "$MODULE" ] || { echo "Missing pronto_wlan.ko: run termux-preflight.sh"; exit 1; }
[ -s "$NV" ] || { echo "Missing WCNSS_qcom_wlan_nv.bin: run termux-preflight.sh"; exit 1; }
[ -d "$RFS/etc" ] || { echo "Alpine rootfs missing"; exit 1; }
install -d "$RFS/lib/modules/pronto" "$RFS/lib/firmware/wlan/prima"
# Preserve any existing firmware or modules as .before-aurora backups.
copy_safe() {
  local source="$1" target="$2"
  if [ -e "$target" ] && ! cmp -s "$source" "$target"; then
    if [ ! -e "$target.before-aurora" ]; then cp -p "$target" "$target.before-aurora"; fi
  fi
  cp "$source" "$target"
  chmod 644 "$target"
}
copy_safe "$MODULE" "$RFS/lib/modules/pronto/pronto_wlan.ko"
copy_safe "$NV" "$RFS/lib/firmware/wlan/prima/WCNSS_qcom_wlan_nv.bin"
ln -sfn /lib/modules/pronto/pronto_wlan.ko "$RFS/lib/modules/wlan.ko"
echo "=== Aurora rootfs Wi-Fi files ==="
ls -lh "$RFS/lib/modules/pronto/pronto_wlan.ko" "$RFS/lib/modules/wlan.ko" "$RFS/lib/firmware/wlan/prima/WCNSS_qcom_wlan_nv.bin"
echo "=== Configuration checks ==="
for name in WCNSS_cfg.dat WCNSS_qcom_cfg.ini; do
  if [ -s "$RFS/lib/firmware/wlan/prima/$name" ]; then
    echo "PRESENT $name"
  else
    echo "MISSING $name (source from matched Sony firmware)"
  fi
done
echo "Staging complete. No boot image or device partition changed."
