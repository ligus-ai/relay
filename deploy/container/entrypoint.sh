#!/bin/sh
# Make the persistence dir writable by the unprivileged user, then drop
# privileges to run the relay. Hosts mount volumes root-owned, so we chown once
# at boot. If the dir is unset/unavailable (or DATABASE_URL is used) the relay
# just runs without a local snapshot.
set -e

# Image default: snapshot store in /data unless LANGSTROTH_RELAY_DATA_DIR is
# set (even empty).
if [ -z "${LANGSTROTH_RELAY_DATA_DIR+x}" ]; then
  export LANGSTROTH_RELAY_DATA_DIR=/data
fi
DATA_DIR="$LANGSTROTH_RELAY_DATA_DIR"
if [ -n "$DATA_DIR" ]; then
  mkdir -p "$DATA_DIR" 2>/dev/null || true
  chown -R langstroth:langstroth "$DATA_DIR" 2>/dev/null || true
fi

# Drop to `langstroth` (UID 1000). Prefer su-exec (alpine), then setpriv
# (util-linux), then su.
if command -v su-exec >/dev/null 2>&1; then
  exec su-exec langstroth:langstroth /usr/local/bin/langstroth-relay "$@"
elif command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid=langstroth --regid=langstroth --init-groups /usr/local/bin/langstroth-relay "$@"
else
  exec su langstroth -c "/usr/local/bin/langstroth-relay $*"
fi
