#!/usr/bin/env bash
# Start the demo from a clean slate (module 10, docs/DEMO_SCRIPT.md).
# The same steps as scripts/reset_demo.ps1 (Windows):
#   1. creates .env from .env.example if missing, generating every secret, and
#      adds any module 10 setting an older .env lacks (existing values are kept);
#   2. deletes the stack's containers AND its database volume, after asking;
#   3. rebuilds and starts everything; the stack seeds itself with demo data.
#
#   ./scripts/reset_demo.sh          (from the repository root; --yes skips the question)
set -euo pipefail
cd "$(dirname "$0")/.."

secret() {  # URL-safe base64 of N random bytes (a Fernet key is N=32)
  head -c "${1:-18}" /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'
}

created=false
if [ ! -f .env ]; then
  cp .env.example .env
  created=true
  echo "Created .env from .env.example"
fi

new_admin_password=""
ensure() {  # ensure NAME VALUE: set NAME when it's missing or empty in .env
  local name=$1 value=$2 current
  current=$(sed -n "s/^$name=//p" .env | head -n 1)
  if [ -n "$current" ] && ! { $created && [ "$name" = LOCAL_MODEL_DEMO_PRICE_PER_MILLION ]; }; then
    return
  fi
  if grep -q "^$name=" .env; then
    # | as the sed delimiter: the generated values never contain it.
    sed -i.bak "s|^$name=.*|$name=$value|" .env && rm -f .env.bak
  else
    printf '\n%s=%s\n' "$name" "$value" >> .env
  fi
  case $name in
    *SECRET*|*PASSWORD*|REDACTION_VAULT_KEY) echo "  .env: $name generated" ;;
    *) echo "  .env: $name=$value" ;;
  esac
  if [ "$name" = DEMO_ADMIN_PASSWORD ]; then new_admin_password=$value; fi
}

ensure REDACTION_VAULT_KEY "$(secret 32)"
ensure POSTGRES_APP_PASSWORD "$(secret)"
ensure DEMO_SEED true
ensure DEMO_SECRET "$(secret 24)"
ensure DEMO_ADMIN_USERNAME admin
ensure DEMO_ADMIN_PASSWORD "$(secret 15)"
ensure DEMO_MODEL local-llama3:latest
ensure OLLAMA_BASE_URL http://host.docker.internal:11434/v1
ensure LOCAL_MODEL_DEMO_PRICE_PER_MILLION 60

if [ "${1:-}" != "--yes" ]; then
  echo
  echo "This DELETES the stack's database (all teams, keys and audit entries) and starts fresh."
  read -r -p "Type yes to continue: " answer
  [ "$answer" = yes ] || { echo "Nothing changed."; exit 1; }
fi

docker compose down --volumes --remove-orphans
docker compose up -d --build
echo "Waiting for the demo traffic to finish (the classifier loads first, ~30 s)..."
docker compose wait seed-traffic > /dev/null
docker compose logs --no-log-prefix seed-traffic

admin=$(sed -n 's/^DEMO_ADMIN_USERNAME=//p' .env | head -n 1)
echo
echo "Ready."
echo "  Dashboard: http://localhost:3000   (user: $admin)"
if [ -n "$new_admin_password" ]; then
  echo "  Password:  $new_admin_password   (new - it's also in .env as DEMO_ADMIN_PASSWORD)"
else
  echo "  Password:  DEMO_ADMIN_PASSWORD in .env"
fi
echo "  Gateway:   http://localhost:8000"
echo "  Demo steps: docs/DEMO_SCRIPT.md"
