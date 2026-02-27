#!/bin/bash
# Wrapper script for Hickory DNS that handles reloads gracefully
# Instead of stopping the container on config changes, we restart just the DNS process

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting Hickory DNS wrapper..."

# Function to run hickory-dns and handle restarts
run_hickory() {
    while true; do
        log "Starting hickory-dns server..."
        
        # Run hickory-dns in foreground
        /usr/local/bin/hickory-dns "$@" 2>&1
        
        EXIT_CODE=$?
        log "Hickory DNS exited with code: $EXIT_CODE"
        
        # Check if it's a normal exit (reload) or an error
        # Exit code 0 or -15 (SIGTERM from file watcher) means reload - we should restart
        
        # Check if there's a reload trigger file
        if [ -f /tmp/hickory-reload ]; then
            log "Reload requested, restarting..."
            rm -f /tmp/hickory-reload
            sleep 1
            continue
        fi
        
        log "Restarting hickory-dns in 2 seconds..."
        sleep 2
    done
}

# Run the DNS server
run_hickory "$@"
