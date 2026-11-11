#!/bin/bash
# Wrapper script for Hickory DNS that handles reloads gracefully.
#
# hickory-dns exits when its config or zone files change (that is how a
# reload is performed) and expects to be started again. A clean exit (status
# 0) is therefore restarted immediately to keep the interruption of port 53 as
# short as possible; a failing exit is retried after a short back-off so a
# broken configuration does not spin. SIGTERM/SIGINT (docker stop) are forwarded
# to the server and end the wrapper instead of being restarted.

HICKORY_BIN="${HICKORY_BIN:-/usr/local/bin/hickory-dns}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

stopping=0
child=0

on_signal() {
    stopping=1
    if [ "$child" -ne 0 ]; then
        kill -TERM "$child" 2>/dev/null
    fi
}
trap on_signal TERM INT

log "Starting Hickory DNS wrapper..."

while [ "$stopping" -eq 0 ]; do
    log "Starting hickory-dns server..."
    "$HICKORY_BIN" "$@" 2>&1 &
    child=$!

    # `wait` returns early when a trapped signal arrives; keep waiting until
    # the child is really gone.
    while kill -0 "$child" 2>/dev/null; do
        wait "$child"
        code=$?
    done
    wait "$child" 2>/dev/null
    code=$?
    child=0
    log "Hickory DNS exited with code: $code"

    [ "$stopping" -ne 0 ] && break

    if [ "$code" -eq 0 ]; then
        log "Reload requested, restarting..."
    else
        log "Unexpected exit, restarting in 2 seconds..."
        sleep 2
    fi
done

log "Wrapper stopped"
exit 0
