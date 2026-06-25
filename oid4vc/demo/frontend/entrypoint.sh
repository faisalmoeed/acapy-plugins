#!/bin/bash
set -e

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

wait_for_tunnel() {
  local name=$1
  local url=""
  for i in $(seq 1 30); do
    url=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r --arg n "$name" '.tunnels[] | select(.name == $n) | .public_url')
    if [ -n "$url" ] && [ "$url" != "null" ]; then
      echo "$url"
      return 0
    fi
    echo "Waiting for ngrok tunnel '${name}' (attempt ${i}/30)..." >&2
    sleep 2
  done
  echo ""
}

AUTHSERVER_NGROK_URL=$(wait_for_tunnel "authserver")
export AUTHSERVER_NGROK_URL
echo "AUTHSERVER_NGROK_URL: $AUTHSERVER_NGROK_URL"

DEMO_APP_NGROK_URL=$(wait_for_tunnel "demo")
export DEMO_APP_NGROK_URL
echo "DEMO_APP_NGROK_URL: $DEMO_APP_NGROK_URL"

ISSUER_NGROK_URL=$(wait_for_tunnel "issuer")
export ISSUER_NGROK_URL
echo "ISSUER_NGROK_URL: $ISSUER_NGROK_URL"

exec "$@"
