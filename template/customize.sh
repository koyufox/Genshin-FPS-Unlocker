# shellcheck shell=sh disable=SC2034
SKIPUNZIP=1
[ "$BOOTMODE" = true ] || abort "Install from Magisk or KernelSU Manager"
[ "$ARCH" = arm64 ] || abort "Only ARM64 devices are supported"
unzip -o "$ZIPFILE" verify.sh -d "$TMPDIR" >&2
[ -f "$TMPDIR/verify.sh" ] || abort "Missing verification script"
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" files.list "$TMPDIR"
while IFS= read -r entry; do
  case "$entry" in
    ''|/*|*..*) abort "Invalid package manifest" ;;
  esac
  extract "$ZIPFILE" "$entry" "$MODPATH"
done < "$TMPDIR/files.list"
# Remove installer-only files left by an earlier package.
rm -f "$MODPATH/verify.sh" "$MODPATH/verify.sh.sha256" || abort "Cannot remove installation verifier"
rm -rf "$MODPATH/native-libs" || abort "Cannot remove obsolete library directory"
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0644
set_perm_recursive "$MODPATH/lib" 0 0 0755 0644
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
for script in action.sh status.sh service.sh uninstall.sh; do
  set_perm "$MODPATH/$script" 0 0 0755
done
"$MODPATH/bin/genshin-control" initialize "$MODPATH" || abort "Configuration initialization failed"
ui_print "- Enable your Zygisk provider and reboot to load the module"
