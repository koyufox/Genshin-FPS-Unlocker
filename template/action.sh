#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/bin/genshin-control" toggle "$MODDIR"
