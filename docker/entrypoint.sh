#!/bin/bash
# Huntress Attack Machine Entrypoint
# Configures tinyproxy from HUNTRESS_ALLOWED_DOMAINS before running user command.
# This is the last line of defense against out-of-scope testing.

set -e

# HUNTRESS_ALLOWED_DOMAINS must be set — refuse to start without scope
if [ -z "$HUNTRESS_ALLOWED_DOMAINS" ]; then
    echo "ERROR: HUNTRESS_ALLOWED_DOMAINS is not set. Cannot start without scope." >&2
    echo "Set it to a comma-separated list of allowed domains." >&2
    exit 1
fi

# Generate the filter file for tinyproxy from the env var.
# Tinyproxy filter with FilterDefaultDeny=Yes blocks everything NOT in this list.
# Each line is a regex pattern that is matched against the hostname.
> /etc/tinyproxy/filter
IFS=',' read -ra DOMAINS <<< "$HUNTRESS_ALLOWED_DOMAINS"
for domain in "${DOMAINS[@]}"; do
    # Trim whitespace
    domain=$(echo "$domain" | xargs)
    if [ -n "$domain" ]; then
        # Escape dots for regex, anchor to match exact domain and subdomains
        escaped=$(echo "$domain" | sed 's/\./\\./g')
        echo "^${escaped}$" >> /etc/tinyproxy/filter
        echo "\.${escaped}$" >> /etc/tinyproxy/filter
    fi
done

echo "[huntress] Scope-enforcing proxy configured for: $HUNTRESS_ALLOWED_DOMAINS"

# Start tinyproxy in the background
tinyproxy -c /etc/tinyproxy/tinyproxy.conf 2>/dev/null &
PROXY_PID=$!

# Wait briefly for proxy to start
sleep 0.5

# Set proxy env vars so all tools route through tinyproxy
export http_proxy="http://127.0.0.1:3128"
export https_proxy="http://127.0.0.1:3128"
export HTTP_PROXY="http://127.0.0.1:3128"
export HTTPS_PROXY="http://127.0.0.1:3128"

echo "[huntress] Proxy active on 127.0.0.1:3128 — all HTTP/HTTPS traffic is scope-enforced"

# Trap SIGTERM/SIGINT to clean up proxy
cleanup() {
    echo "[huntress] Shutting down proxy..."
    kill $PROXY_PID 2>/dev/null
    wait $PROXY_PID 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

# Build the command string with proper quoting
CMD_STR=""
for arg in "$@"; do
    CMD_STR="$CMD_STR '$(echo "$arg" | sed "s/'/'\\\\''/g")'"
done

# Run as the hunter user if we're currently root
if [ "$(id -u)" = "0" ]; then
    exec su -s /bin/bash hunter -c "export http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128 HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128 HUNTRESS_ALLOWED_DOMAINS='$HUNTRESS_ALLOWED_DOMAINS'; $CMD_STR"
else
    exec "$@"
fi
