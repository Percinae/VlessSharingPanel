#!/usr/bin/env bash
# One-time setup on the Russian VPS. Run as root from a trusted checkout.
set -euo pipefail

[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
public_url=${1:?HTTPS origin required}
deploy_key_file=${2:?SSH public key file required}
[[ $public_url =~ ^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$ ]] || {
    echo 'Expected HTTPS origin without a path' >&2
    exit 2
}
[[ -f $deploy_key_file ]] || { echo 'Public key file not found' >&2; exit 1; }
mapfile -t public_keys < "$deploy_key_file"
[[ ${#public_keys[@]} == 1 && ${public_keys[0]} == ssh-ed25519\ * ]] || {
    echo 'Expected exactly one Ed25519 public key' >&2
    exit 2
}
ssh-keygen -lf "$deploy_key_file" > /dev/null
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if ! id vless-panel > /dev/null 2>&1; then
    useradd --system --home-dir /var/lib/vless-panel --shell /usr/sbin/nologin vless-panel
fi
if ! id vless-deploy > /dev/null 2>&1; then
    useradd --create-home --home-dir /home/vless-deploy --shell /bin/bash vless-deploy
fi

install -d -m 0700 -o vless-panel -g vless-panel /var/lib/vless-panel
install -d -m 0755 -o vless-deploy -g vless-deploy /opt/vless-panel
install -d -m 0750 -o vless-deploy -g vless-deploy /opt/vless-panel/incoming
install -d -m 0755 -o vless-deploy -g vless-deploy /opt/vless-panel/releases
install -d -m 0700 -o vless-deploy -g vless-deploy /home/vless-deploy/.ssh
touch /home/vless-deploy/.ssh/authorized_keys
chmod 0600 /home/vless-deploy/.ssh/authorized_keys
chown vless-deploy:vless-deploy /home/vless-deploy/.ssh/authorized_keys
key=${public_keys[0]}
if ! grep -Fqx -- "$key" /home/vless-deploy/.ssh/authorized_keys; then
    printf '%s\n' "$key" >> /home/vless-deploy/.ssh/authorized_keys
fi

install -d -m 0755 /etc/vless-panel
printf 'PANEL_PUBLIC_URL=%s\n' "$public_url" > /etc/vless-panel/panel.env
chmod 0600 /etc/vless-panel/panel.env
install -m 0644 "$script_dir/vless-panel.service" /etc/systemd/system/vless-panel.service
tmp_sudoers=$(mktemp)
trap 'rm -f "$tmp_sudoers"' EXIT
printf '%s\n' 'vless-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart vless-panel.service' > "$tmp_sudoers"
visudo -cf "$tmp_sudoers" > /dev/null
install -m 0440 "$tmp_sudoers" /etc/sudoers.d/vless-panel-deploy
systemctl daemon-reload
systemctl enable vless-panel.service

echo 'Bootstrap complete. Initialize /var/lib/vless-panel before activating the first release.'
