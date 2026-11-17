#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

export PANEL_APP_ROOT="$test_root/app"
export PANEL_DATA_DIR="$test_root/data"
export PANEL_HEALTH_TRIES=2
export PANEL_HEALTH_DELAY=0
export TEST_RESTART_LOG="$test_root/restarts"
export TEST_HEALTH_FILE="$test_root/health"
export PANEL_TEST_RESTART="$test_root/restart"
export PANEL_TEST_HEALTH="$test_root/health-check"

mkdir -p "$PANEL_APP_ROOT/incoming" "$PANEL_DATA_DIR"
cat > "$PANEL_TEST_RESTART" <<'EOF'
#!/usr/bin/env bash
echo restart >> "$TEST_RESTART_LOG"
EOF
cat > "$PANEL_TEST_HEALTH" <<'EOF'
#!/usr/bin/env bash
[[ $(cat "$TEST_HEALTH_FILE") == ok ]]
EOF
chmod +x "$PANEL_TEST_RESTART" "$PANEL_TEST_HEALTH"

upload() {
    local tag=$1
    local content=$2
    mkdir -p "$PANEL_APP_ROOT/incoming/$tag"
    printf '%s' "$content" > "$PANEL_APP_ROOT/incoming/$tag/vless-sharing-panel"
    sha256sum "$PANEL_APP_ROOT/incoming/$tag/vless-sharing-panel" | cut -d' ' -f1
}

sha=$(upload v0.1.0 first)
echo ok > "$TEST_HEALTH_FILE"
if bash "$script_dir/activate.sh" v0.1.0 "$sha" > /dev/null 2>&1; then
    echo 'Expected deployment to require initialized data' >&2
    exit 1
fi
[[ ! -e "$PANEL_APP_ROOT/current" ]]

for name in key admin.hash totp.secret shares.sqlite3; do touch "$PANEL_DATA_DIR/$name"; done
bash "$script_dir/activate.sh" v0.1.0 "$sha" > /dev/null
[[ $(readlink "$PANEL_APP_ROOT/current") == "$PANEL_APP_ROOT/releases/v0.1.0" ]]
[[ $(wc -l < "$TEST_RESTART_LOG") == 1 ]]

bad_sha=$(upload v0.2.0 second)
if bash "$script_dir/activate.sh" v0.2.0 "$(printf '0%.0s' {1..64})" > /dev/null 2>&1; then
    echo 'Expected checksum mismatch' >&2
    exit 1
fi
[[ $(readlink "$PANEL_APP_ROOT/current") == "$PANEL_APP_ROOT/releases/v0.1.0" ]]
[[ $(wc -l < "$TEST_RESTART_LOG") == 1 ]]

echo fail > "$TEST_HEALTH_FILE"
if bash "$script_dir/activate.sh" v0.2.0 "$bad_sha" > /dev/null 2>&1; then
    echo 'Expected unhealthy release to fail' >&2
    exit 1
fi
[[ $(readlink "$PANEL_APP_ROOT/current") == "$PANEL_APP_ROOT/releases/v0.1.0" ]]
[[ $(wc -l < "$TEST_RESTART_LOG") == 3 ]]

old_sha=$(upload v0.0.9 old)
if bash "$script_dir/activate.sh" v0.0.9 "$old_sha" > /dev/null 2>&1; then
    echo 'Expected older tag to be rejected' >&2
    exit 1
fi
[[ $(readlink "$PANEL_APP_ROOT/current") == "$PANEL_APP_ROOT/releases/v0.1.0" ]]
[[ $(wc -l < "$TEST_RESTART_LOG") == 3 ]]

echo 'Deployment activation, checksum, downgrade and rollback tests passed'
