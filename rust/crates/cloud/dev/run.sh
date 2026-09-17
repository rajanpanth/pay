#!/usr/bin/env bash
# Build and run pay-cloud locally with everything switched on: the
# onboarding pages, the Coinflow funding page, the MCP connector and its
# OAuth server. By default a mock Openfort runs beside it so the wallet
# flows work with no Openfort account.
#
#   rust/crates/cloud/dev/run.sh                 # mock Openfort, http://127.0.0.1:8402
#   rust/crates/cloud/dev/run.sh --real-openfort # use dashboard.openfort.io
#   rust/crates/cloud/dev/run.sh --public-url https://xyz.trycloudflare.com
#   rust/crates/cloud/dev/run.sh --static-token <token>   # header auth + a mock wallet for it
#   rust/crates/cloud/dev/run.sh --anonymous              # DEV ONLY: no-auth hosts act as that wallet
#
# Reads the repo-root .env (Coinflow sandbox settings) when present.
# Ctrl-C stops everything.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
PORT=8402
MOCK_PORT=8499
PUBLIC_URL=""
REAL_OPENFORT=0
SKIP_BUILD=0
STATIC_TOKEN=""
ANONYMOUS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --real-openfort) REAL_OPENFORT=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --static-token) STATIC_TOKEN="$2"; shift 2 ;;
    --anonymous) ANONYMOUS=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

PUBLIC_URL="${PUBLIC_URL:-http://127.0.0.1:$PORT}"

step() { printf '\n\033[1m› %s\033[0m\n' "$*"; }

if [ "$SKIP_BUILD" = 0 ]; then
  step "Building the web bundles"
  (cd "$ROOT/web-ui" && pnpm install --frozen-lockfile --silent && pnpm -s build >/dev/null && pnpm -s build:cloud >/dev/null)
  step "Building pay-cloud and the pay CLI"
  (cd "$ROOT/rust" && cargo build -q -p pay-cloud -p pay)
fi

pkill -f 'target/debug/pay-cloud' 2>/dev/null || true
pkill -f 'dev/mock_openfort.py' 2>/dev/null || true

if [ -f "$ROOT/.env" ]; then
  set -a; . "$ROOT/.env"; set +a
  step "Loaded $ROOT/.env (Coinflow: ${COINFLOW_ENV:-unset})"
fi

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

if [ "$REAL_OPENFORT" = 0 ]; then
  step "Starting mock Openfort on http://127.0.0.1:$MOCK_PORT"
  python3 "$ROOT/rust/crates/cloud/dev/mock_openfort.py" "$MOCK_PORT" &
  PIDS+=($!)
  export OPENFORT_BASE_URL="http://127.0.0.1:$MOCK_PORT"
  export OPENFORT_AUTH_PAGE_URL="http://127.0.0.1:$MOCK_PORT"
else
  unset OPENFORT_BASE_URL OPENFORT_AUTH_PAGE_URL
fi

export PAY_CLOUD_MCP=1
export RUST_LOG="${RUST_LOG:-info,pay_cloud=debug}"
if [ "$ANONYMOUS" = 1 ] && [ -z "$STATIC_TOKEN" ]; then
  STATIC_TOKEN="pay_dev_$(openssl rand -hex 16)"
fi
if [ -n "$STATIC_TOKEN" ]; then
  # A header-authenticated host; with the mock, the token gets a wallet too.
  export PAY_CLOUD_MCP_TOKENS="$STATIC_TOKEN"
  [ "$REAL_OPENFORT" = 0 ] && export PAY_CLOUD_DEV_MOCK_TENANTS=1
fi
if [ "$ANONYMOUS" = 1 ]; then
  # DEV ONLY: hosts that send no header and cannot finish OAuth act as the
  # static token's tenant. Anyone with the URL can use that mock wallet.
  export PAY_CLOUD_DEV_ANONYMOUS_TOKEN="$STATIC_TOKEN"
fi

step "Starting pay-cloud on http://127.0.0.1:$PORT (public URL $PUBLIC_URL)"
"$ROOT/rust/target/debug/pay-cloud" --port "$PORT" --public-url "$PUBLIC_URL" &
PIDS+=($!)
sleep 1
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || { echo "pay-cloud did not start" >&2; exit 1; }

cat <<EOF

────────────────────────────────────────────────────────────────────────
  pay-cloud is up.  $PUBLIC_URL
────────────────────────────────────────────────────────────────────────

$( [ -n "$STATIC_TOKEN" ] && printf '  Header-authenticated host (Grok custom connector, "headers" field):\n    Authorization: Bearer %s\n\n' "$STATIC_TOKEN" )  MCP connector (what Grok would use), with Claude Code as the host:
    claude mcp add --transport http paycloud $PUBLIC_URL/mcp
    then in Claude Code:  /mcp  → paycloud → Authenticate
    The browser lands on the consent page, creates a wallet$( [ "$REAL_OPENFORT" = 0 ] && printf ' (mock Openfort)' ), and returns.

  CLI, remote wallet setup (with the mock, use a scratch HOME so mock
  credentials never land in your real keychain):
    HOME=\$(mktemp -d) PAY_CLOUD_LOCAL=1 $ROOT/rust/target/debug/pay setup --backend cloud

  CLI, buy USDC with a card (Coinflow sandbox, test card 4242 4242 4242 4242):
    PAY_ONRAMP=coinflow PAY_CLOUD_LOCAL=1 $ROOT/rust/target/debug/pay topup

  Pages:  $PUBLIC_URL/onboard   $PUBLIC_URL/fund?address=<pubkey>   $PUBLIC_URL/authorize
  OAuth:  $PUBLIC_URL/.well-known/oauth-authorization-server

  For Grok itself you need a public HTTPS URL, for example:
    brew install cloudflared && cloudflared tunnel --url http://127.0.0.1:$PORT
    then rerun this script with --public-url https://<name>.trycloudflare.com
    and add https://<name>.trycloudflare.com/mcp as a custom connector.

  Ctrl-C stops everything.
EOF

wait
