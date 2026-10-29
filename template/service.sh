#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/bin/genshin-control" status "$MODDIR"
