#!/usr/bin/env bash
# Operator-owned SSH hardening for a CloudPanel server. Does not replace UFW,
# Nginx, PHP, database settings or the panel's Fail2ban configuration.
set -euo pipefail
mode=${1:---audit}
case "$mode" in --audit|--apply) ;; *) echo 'Use --audit or --apply --key-login-confirmed' >&2; exit 2 ;; esac
test "$(id -u)" = 0 || { echo 'Run as root.' >&2; exit 1; }
for tool in sshd ufw fail2ban-client; do command -v "$tool" >/dev/null; done
test -d /home/clp/htdocs/app || { echo 'CloudPanel installation not found.' >&2; exit 1; }
if [ "$mode" = --apply ]; then
    test "${2:-}" = --key-login-confirmed || {
        echo 'First verify a separate SSH-key login; then pass --key-login-confirmed.' >&2; exit 1;
    }
    test -n "${SSH_CONNECTION:-}" || { echo 'Apply from a verified SSH session.' >&2; exit 1; }
    test -s /root/.ssh/authorized_keys || { echo 'No root SSH keys found.' >&2; exit 1; }
    target=/etc/ssh/sshd_config.d/10-cloudpanel-companion.conf
    test ! -L "$target"
    candidate=$(mktemp /etc/ssh/sshd_config.d/.companion-XXXXXXXX)
    trap 'rm -f -- "$candidate"' EXIT
    cat > "$candidate" <<'CONFIG'
# Managed by CloudPanel Companion; vendor configuration remains untouched.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
X11Forwarding no
CONFIG
    if [ -e "$target" ] && ! cmp -s "$candidate" "$target"; then
        echo 'An existing operator SSH policy differs; review it before replacement.' >&2
        exit 1
    fi
    if [ ! -e "$target" ]; then
        install -o root -g root -m 600 "$candidate" "$target"
        if ! sshd -t; then
            rm -- "$target"
            exit 1
        fi
        effective=$(sshd -T)
        if ! grep -qx 'passwordauthentication no' <<<"$effective" ||
           ! grep -qx 'kbdinteractiveauthentication no' <<<"$effective"; then
            rm -- "$target"
            echo 'Existing SSH rules take precedence; nothing reloaded.' >&2
            exit 1
        fi
        systemctl reload ssh
    fi
fi
echo 'SSH effective authentication policy:'
sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|permitemptypasswords|x11forwarding) '
echo 'Firewall:'
ufw status verbose
echo 'Fail2ban:'
fail2ban-client status
echo 'Listening TCP endpoints (check private services against firewall policy):'
ss -lnt
echo 'This baseline is not a WAF or a complete server security assessment.'
