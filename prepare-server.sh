#!/usr/bin/env bash
# Prepare a fresh Ubuntu 24.04 server for CloudPanel and the Companion.
#
#   sudo bash prepare-server.sh --admin-user NAME --authorized-keys FILE --ssh-port PORT [options]
#   sudo bash prepare-server.sh --close-old-ssh-port      (after testing the new port)
#
# Safe to run again: finished steps are skipped. SSH moves to a new port in two
# steps so a mistake can never lock you out: the first run opens the new port
# next to 22; once a key login on the new port works, --close-old-ssh-port
# closes 22.
set -euo pipefail

ssh_port=''
admin_user=''
keys_file=''
php_version=8.3
db_buffer_pool=1G
close_old_port=false
reboot_when_needed=true

usage() {
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --admin-user NAME        named sudo user for SSH logins; root can log in with the
                           same keys. SSH never accepts passwords. The root password
                           is not changed, so the provider's web console keeps working.
  --authorized-keys FILE   public keys allowed to log in as that user (one per line)
  --ssh-port PORT          the new SSH port you choose (1024-65535, not 8443)
  --php VERSION            PHP version the websites use; other PHP-FPM versions are
                           turned off (default 8.3; "keep-all" leaves them all on)
  --db-buffer-pool SIZE    MariaDB InnoDB buffer pool (default 1G)
  --no-reboot              don't reboot automatically after a kernel update
  --close-old-ssh-port     close port 22 after you tested the new port
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --admin-user) admin_user=${2:?}; shift 2 ;;
        --authorized-keys) keys_file=${2:?}; shift 2 ;;
        --ssh-port) ssh_port=${2:?}; shift 2 ;;
        --php) php_version=${2:?}; shift 2 ;;
        --db-buffer-pool) db_buffer_pool=${2:?}; shift 2 ;;
        --no-reboot) reboot_when_needed=false; shift ;;
        --close-old-ssh-port) close_old_port=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'Stopped: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'run it with sudo'
[ "$(. /etc/os-release; echo "$VERSION_ID")" = 24.04 ] || fail 'this script is tested on Ubuntu 24.04 only'
# Closing 22 later needs no options: the port is the one the first run configured.
if [ "$close_old_port" = true ] && [ -z "$ssh_port" ]; then
    ssh_port=$(sed -n 's/^Port \([0-9]*\)$/\1/p' /etc/ssh/sshd_config.d/00-companion-hardening.conf 2>/dev/null | head -1)
    [ -n "$ssh_port" ] || fail 'no SSH port configured by this script yet; run it with --ssh-port first'
fi
[[ $ssh_port =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1024 ] && [ "$ssh_port" -le 65535 ] && [ "$ssh_port" != 8443 ] \
    || fail '--ssh-port is required: a port between 1024 and 65535 (not 8443)'

if [ "$close_old_port" = true ]; then
    step "Closing the old SSH port 22"
    ss -ltn "sport = :$ssh_port" | grep -q LISTEN || fail "SSH is not listening on $ssh_port; nothing was closed"
    rm -f /etc/ssh/sshd_config.d/01-companion-old-port.conf
    touch /etc/ssh/sshd_config.d/.companion-old-port-closed   # later runs keep 22 closed
    sshd -t
    systemctl daemon-reload
    systemctl restart ssh.socket 2>/dev/null || systemctl restart ssh
    ufw delete allow 22/tcp >/dev/null 2>&1 || true
    # CloudPanel rebuilds UFW from its own firewall list whenever that list is saved,
    # so 22 leaves the list too; otherwise the next save would open it again.
    python3 - <<'PY'
import sqlite3
db = sqlite3.connect('/home/clp/htdocs/app/data/db.sq3')
db.execute("DELETE FROM firewall_rule WHERE port_range = '22'")
db.commit()
PY
    ss -ltn | grep -q ':22 ' && fail 'port 22 is still listening; check /etc/ssh/sshd_config.d'
    echo "Port 22 is closed. SSH: ssh -p $ssh_port $(ls /etc/sudoers.d/90-companion-admin-* 2>/dev/null | sed 's/.*admin-//' | head -1)@<server>"
    exit 0
fi

[[ $admin_user =~ ^[a-z][a-z0-9_-]{1,30}$ ]] || fail '--admin-user is required (lowercase letters, digits, - or _)'
[ -n "$keys_file" ] && [ -r "$keys_file" ] || fail '--authorized-keys must point to a readable file of public keys'
grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com) ' "$keys_file" \
    || fail "$keys_file holds no public keys"
grep -q 'PRIVATE KEY' "$keys_file" && fail "$keys_file contains a private key; give only .pub keys"

step "System updates and base tools"
cloud-init status --wait >/dev/null 2>&1 || true
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold upgrade
apt-get -y -q install curl wget sudo ufw sysstat

step "Admin user $admin_user (SSH keys only, sudo without a password)"
if ! id "$admin_user" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$admin_user"
fi
passwd --lock "$admin_user" >/dev/null   # no password exists, so password login is impossible
install -d -m 700 -o "$admin_user" -g "$admin_user" "/home/$admin_user/.ssh"
grep -E '^(ssh-|ecdsa-|sk-)' "$keys_file" | install -m 600 -o "$admin_user" -g "$admin_user" /dev/stdin "/home/$admin_user/.ssh/authorized_keys"
sudoers="/etc/sudoers.d/90-companion-admin-$admin_user"
printf '%s ALL=(ALL:ALL) NOPASSWD:ALL\n' "$admin_user" > "$sudoers.new"
chmod 440 "$sudoers.new"
visudo -cf "$sudoers.new" >/dev/null
mv "$sudoers.new" "$sudoers"
# Root accepts the same keys. Keys already there (the provider's) are kept, and
# the root password is left as the provider set it for console recovery.
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -E '^(ssh-|ecdsa-|sk-)' "$keys_file" | while read -r key; do
    grep -qxF "$key" /root/.ssh/authorized_keys || printf '%s\n' "$key" >> /root/.ssh/authorized_keys
done

step "CloudPanel with MariaDB 11.4"
if [ ! -d /home/clp/htdocs/app ]; then
    workdir=$(mktemp -d)
    curl -fsSL https://installer.cloudpanel.io/ce/v2/install.sh -o "$workdir/install.sh"
    echo "8146dbe0a488e7088b04071b0c34d59aa0ab1fe9dcec382d395fd155c9e6c476  $workdir/install.sh" | sha256sum -c --quiet \
        || fail 'the CloudPanel installer changed; review it and update its checksum here'
    DB_ENGINE=MARIADB_11.4 bash "$workdir/install.sh"
    rm -rf "$workdir"
fi
step "Firewall"
# CloudPanel's installer resets UFW to its own list, and its admin area rebuilds
# UFW from the firewall rules it stores whenever that list is saved. So the SSH
# port goes into CloudPanel's own list (IPv4 and IPv6, as it stores ports) and
# into UFW now, after the installer: saving the list later can never drop it.
python3 - "$ssh_port" <<'PY'
import datetime, sqlite3, sys
port = sys.argv[1]
db = sqlite3.connect('/home/clp/htdocs/app/data/db.sq3')
columns = {row[1] for row in db.execute('PRAGMA table_info(firewall_rule)')}
if not {'created_at', 'updated_at', 'port_range', 'source', 'description'} <= columns:
    sys.exit('CloudPanel firewall table changed; add the SSH port in Admin Area > Security > Firewall by hand.')
now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
for source in ('0.0.0.0/0', '::/0'):
    if not db.execute('SELECT 1 FROM firewall_rule WHERE port_range = ? AND source = ?', (port, source)).fetchone():
        db.execute('INSERT INTO firewall_rule (created_at, updated_at, port_range, source, description) '
                   'VALUES (?, ?, ?, ?, ?)', (now, now, port, source, 'SSH'))
db.commit()
PY
ufw allow "$ssh_port/tcp" >/dev/null
[ -e /etc/ssh/sshd_config.d/.companion-old-port-closed ] || ufw allow 22/tcp >/dev/null   # until --close-old-ssh-port
ufw --force enable >/dev/null
ufw status | grep -q "^$ssh_port/tcp .*ALLOW" || fail "the firewall does not allow SSH on $ssh_port"

step "SSH on port $ssh_port, keys only, for $admin_user and root"
cat > /etc/ssh/sshd_config.d/00-companion-hardening.conf <<EOF
# Managed by prepare-server.sh. Files in this folder are read in name order and
# the first value wins, so this file overrides the image's defaults.
Port $ssh_port
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers $admin_user root
EOF
if [ ! -e /etc/ssh/sshd_config.d/.companion-old-port-closed ]; then
    echo 'Port 22' > /etc/ssh/sshd_config.d/01-companion-old-port.conf
fi
sshd -t
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || systemctl restart ssh
ss -ltn | grep -q ":$ssh_port " || fail "SSH did not start on port $ssh_port"

step "MariaDB: working log rotation, buffer pool $db_buffer_pool, slow query log"
# The packaged rotation flushes logs as a password-less root, which CloudPanel's
# MariaDB refuses, so every rotation fails. Rotate and flush as the
# socket-authenticated mysql account instead, as the packaged file intends.
sed -i 's/^  #su mysql mysql$/  su mysql mysql/' /etc/logrotate.d/mariadb
grep -q '^  su mysql mysql$' /etc/logrotate.d/mariadb || fail 'the MariaDB logrotate file changed; review it'
python3 - /etc/logrotate.d/mariadb <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
flush = ('  postrotate\n'
         '    # As the socket-authenticated mysql account (see the su line above).\n'
         '    /usr/sbin/runuser -u mysql -- /usr/bin/mariadb-admin --local flush-error-log \\\n'
         '      flush-engine-log flush-general-log flush-slow-log\n'
         '  endscript\n')
if flush not in text:
    blocks = re.findall(r'  postrotate\n.*?  endscript\n', text, flags=re.S)
    if len(blocks) != 1 or 'mariadb-admin $EXTRAPARAM --local flush-error-log' not in blocks[0]:
        sys.exit('The packaged MariaDB logrotate script changed; review /etc/logrotate.d/mariadb by hand.')
    open(path, 'w').write(text.replace(blocks[0], flush))
PY
sizing=/etc/mysql/mariadb.conf.d/110-companion-sizing.cnf
printf '[mysqld]\ninnodb_buffer_pool_size = %s\nslow_query_log = 1\nslow_query_log_file = /var/log/mysql/slow.log\nlong_query_time = 1\n' \
    "$db_buffer_pool" > "$sizing.new"
if ! cmp -s "$sizing.new" "$sizing"; then
    mv "$sizing.new" "$sizing"
    systemctl restart mariadb
else
    rm -f "$sizing.new"
fi
/usr/sbin/runuser -u mysql -- /usr/bin/mariadb-admin --local flush-error-log flush-engine-log flush-general-log flush-slow-log

if [ "$php_version" != keep-all ]; then
    step "PHP-FPM: only $php_version (and CloudPanel's own PHP) stay on"
    systemctl list-unit-files 'php*-fpm.service' --no-legend | awk '{print $1}' | while read -r unit; do
        if [ "$unit" = "php$php_version-fpm.service" ]; then
            systemctl enable --now "$unit" >/dev/null
        else
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
        fi
    done
fi

step "Housekeeping"
# Ubuntu's news fetcher fails on this image (203/EXEC) and would leave a failed unit.
systemctl disable --now motd-news.timer >/dev/null 2>&1 || true
systemctl mask motd-news.timer motd-news.service >/dev/null 2>&1 || true
systemctl reset-failed motd-news.service 2>/dev/null || true
# Prove rotation works now, while no site exists: CloudPanel forces a dated
# rotation every night, so starting it by hand later fails on existing names.
if [ ! -e /var/lib/companion-prepare-logrotate-proved ]; then
    systemctl reset-failed logrotate.service 2>/dev/null || true
    systemctl start logrotate.service
    [ "$(systemctl show logrotate.service --property=Result --value)" = success ] || fail 'log rotation failed'
    touch /var/lib/companion-prepare-logrotate-proved
fi
if failed=$(systemctl --failed --plain --no-legend) && [ -n "$failed" ]; then
    printf 'Failed units:\n%s\n' "$failed" >&2
    exit 1
fi

cat <<EOF

Server prepared. Next:
  1. From your computer, test: ssh -p $ssh_port $admin_user@<server>   then   sudo -v
  2. If that works:            sudo bash prepare-server.sh --close-old-ssh-port
  3. Create CloudPanel's admin account on https://<server>:8443 (or: sudo clpctl user:add ...)
  4. Then run: sudo bash install.sh
EOF
if [ -e /run/reboot-required ]; then
    if [ "$reboot_when_needed" = true ]; then
        echo 'A new kernel was installed: rebooting now. Reconnect in a minute on port '"$ssh_port"'.'
        systemctl reboot
    else
        echo 'A new kernel was installed: reboot (sudo systemctl reboot) before adding websites.'
    fi
fi
