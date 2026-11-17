#!/usr/bin/env bash
# Runs on the VPS as the unprivileged deployment user.
set -euo pipefail

tag=${1:?version tag required}
expected_sha=${2:?SHA-256 required}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 2; }
[[ $expected_sha =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid SHA-256' >&2; exit 2; }

app_root=${PANEL_APP_ROOT:-/opt/vless-panel}
data_dir=${PANEL_DATA_DIR:-/var/lib/vless-panel}
current="$app_root/current"
incoming="$app_root/incoming/$tag/vless-sharing-panel"
release="$app_root/releases/$tag"
binary="$release/vless-sharing-panel"

for name in key admin.hash totp.secret shares.sqlite3; do
    [[ -f "$data_dir/$name" ]] || { echo 'Panel data is not initialized; see deploy/README.md' >&2; exit 1; }
done
[[ -f $incoming && ! -L $incoming ]] || { echo 'Uploaded binary is missing or is a symlink' >&2; exit 1; }
[[ $(sha256sum "$incoming" | cut -d' ' -f1) == "$expected_sha" ]] || { echo 'Upload checksum mismatch' >&2; exit 1; }

install -d -m 0755 "$app_root/releases"
if [[ -e $binary ]]; then
    [[ -f $binary && ! -L $binary ]] || { echo 'Existing release is invalid' >&2; exit 1; }
else
    install -d -m 0755 "$release"
    install -m 0755 "$incoming" "$binary"
fi
[[ $(sha256sum "$binary" | cut -d' ' -f1) == "$expected_sha" ]] || { echo 'Release checksum mismatch' >&2; exit 1; }

old=''
if [[ -L $current ]]; then
    old=$(readlink -f "$current")
    [[ -d $old && $old == "$app_root/releases/"* ]] || { echo 'Current release link is invalid' >&2; exit 1; }
    current_tag=${old##*/}
    if [[ $(printf '%s\n%s\n' "$tag" "$current_tag" | sort -V | tail -n 1) != "$tag" ]]; then
        echo 'Refusing to deploy an older tag' >&2
        exit 1
    fi
elif [[ -e $current ]]; then
    echo 'Current release path must be a symlink' >&2
    exit 1
fi

restart_service() {
    if [[ -n ${PANEL_TEST_RESTART:-} ]]; then
        "$PANEL_TEST_RESTART"
    else
        sudo -n /usr/bin/systemctl restart vless-panel.service
    fi
}

health_ok() {
    if [[ -n ${PANEL_TEST_HEALTH:-} ]]; then
        "$PANEL_TEST_HEALTH"
    else
        curl --fail --silent --show-error --max-time 2 --output /dev/null http://127.0.0.1:3000/healthz
    fi
}

switch_to() {
    local target=$1
    local pending="$app_root/.current.$$.next"
    ln -s "$target" "$pending"
    mv -Tf "$pending" "$current"
}

switched=0
rollback_on_exit() {
    local status=$?
    trap - EXIT
    if (( status != 0 && switched == 1 )); then
        echo "Release $tag failed health check; restoring previous version" >&2
        if [[ -n $old ]]; then
            switch_to "$old" || true
        else
            rm -f "$current"
        fi
        restart_service || true
    fi
    exit "$status"
}
trap rollback_on_exit EXIT

switch_to "$release"
switched=1
restart_service

tries=${PANEL_HEALTH_TRIES:-15}
delay=${PANEL_HEALTH_DELAY:-2}
for (( attempt=1; attempt<=tries; attempt++ )); do
    if health_ok; then
        switched=0
        echo "Deployed $tag (sha256:$expected_sha)"
        exit 0
    fi
    sleep "$delay"
done
echo "Health check did not pass after $tries attempts" >&2
exit 1
