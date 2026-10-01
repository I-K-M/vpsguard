#!/usr/bin/env bash

# VPSGuard - interactive VPS baseline auditor/hardener
# Target: Ubuntu 22.04/24.04 (Debian-family support is intentionally conservative)
# Usage:
#   sudo ./vpsguard.sh            # interactive audit + remediation
#   sudo ./vpsguard.sh --audit    # read-only audit
#
# Design goals:
# - idempotent: safe to rerun
# - validate before reload
# - back up every file before changing it
# - never intentionally close the current SSH access path
# - conservative defaults; risky changes require explicit confirmation

set -uo pipefail
IFS=$'\n\t'

VERSION="0.1.0"
MODE="interactive"
BACKUP_ROOT="/var/backups/vpsguard"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$BACKUP_ROOT/$RUN_ID"
LOG_FILE="/var/log/vpsguard.log"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CHANGE_COUNT=0

if [[ "${1:-}" == "--audit" ]]; then
  MODE="audit"
elif [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<USAGE
VPSGuard $VERSION

Usage:
  sudo ./vpsguard.sh          Interactive audit and remediation
  sudo ./vpsguard.sh --audit Read-only audit
USAGE
  exit 0
elif [[ $# -gt 0 ]]; then
  echo "Unknown option: $1" >&2
  exit 2
fi

if [[ -t 1 ]]; then
  C_GREEN='\033[0;32m'
  C_YELLOW='\033[0;33m'
  C_RED='\033[0;31m'
  C_BLUE='\033[0;34m'
  C_DIM='\033[2m'
  C_RESET='\033[0m'
else
  C_GREEN='' C_YELLOW='' C_RED='' C_BLUE='' C_DIM='' C_RESET=''
fi

log_raw() {
  local line="$1"
  printf '%b\n' "$line"
  if [[ $EUID -eq 0 && "$MODE" != "audit" ]]; then
    printf '%s\n' "$(date -Is) ${line//$'\033'/}" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

info() { log_raw "${C_BLUE}[INFO]${C_RESET} $*"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); log_raw "${C_GREEN}[PASS]${C_RESET} $*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); log_raw "${C_YELLOW}[WARN]${C_RESET} $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); log_raw "${C_RED}[FAIL]${C_RESET} $*"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); log_raw "${C_DIM}[SKIP]${C_RESET} $*"; }
changed() { CHANGE_COUNT=$((CHANGE_COUNT + 1)); log_raw "${C_GREEN}[CHANGED]${C_RESET} $*"; }

section() {
  printf '\n%b\n' "${C_BLUE}== $* ==${C_RESET}"
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 ${1:-}" >&2
    exit 1
  fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

is_audit() { [[ "$MODE" == "audit" ]]; }

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local suffix="[y/N]"
  local answer

  if is_audit; then
    return 1
  fi

  [[ "$default" == "Y" ]] && suffix="[Y/n]"
  while true; do
    read -r -p "$prompt $suffix " answer || return 1
    answer="${answer:-$default}"
    case "$answer" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Answer y or n." ;;
    esac
  done
}

backup_file() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  mkdir -p "$BACKUP_DIR$(dirname "$path")"
  cp -a "$path" "$BACKUP_DIR$path"
}

install_packages() {
  local packages=("$@")
  if is_audit; then
    return 1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get update || return 1
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

service_active() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

get_ssh_port() {
  local p=""
  if command_exists sshd; then
    p="$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}')"
  fi
  if [[ -z "$p" ]]; then
    p="${SSH_CONNECTION:-}"
    p="${p##* }"
  fi
  [[ "$p" =~ ^[0-9]+$ ]] || p="22"
  printf '%s' "$p"
}

safe_sshd_reload() {
  if ! command_exists sshd; then
    fail "sshd binary not found; cannot validate SSH configuration."
    return 1
  fi
  if ! sshd -t; then
    fail "SSH configuration validation failed. Restoring backup is required."
    return 1
  fi
  if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
    pass "SSH configuration validates and service reloaded."
    return 0
  fi
  fail "SSH configuration validates, but reload failed."
  return 1
}

write_file_if_changed() {
  local path="$1"
  local mode="$2"
  local content="$3"
  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "$content" > "$tmp"

  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    pass "$path already matches the VPSGuard baseline."
    return 0
  fi

  if is_audit; then
    rm -f "$tmp"
    warn "$path does not match the VPSGuard baseline."
    return 1
  fi

  backup_file "$path"
  install -m "$mode" "$tmp" "$path"
  rm -f "$tmp"
  changed "Updated $path"
}

check_os() {
  section "1. Platform and preflight"

  if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release missing. Unsupported platform."
    exit 1
  fi

  # shellcheck disable=SC1091
  . /etc/os-release
  info "Detected: ${PRETTY_NAME:-unknown}"

  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04)
      pass "Supported Ubuntu LTS release."
      ;;
    ubuntu:*)
      warn "Ubuntu ${VERSION_ID:-unknown} is not in the tested matrix. Audit is safe; remediation should be reviewed."
      ;;
    debian:*)
      warn "Debian detected. Most checks work, but remediation is only tested primarily on Ubuntu."
      ;;
    *)
      fail "Unsupported distribution for automatic remediation. Use --audit only."
      if ! is_audit; then
        exit 1
      fi
      ;;
  esac

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    pass "Current session is SSH; lockout protections will preserve its SSH port."
  else
    warn "No SSH_CONNECTION detected. If this is a remote console, verify provider console access before firewall/SSH changes."
  fi

  local root_use
  root_use="$(df -P / | awk 'NR==2 {gsub("%", "", $5); print $5}')"
  if [[ "$root_use" =~ ^[0-9]+$ ]] && (( root_use >= 90 )); then
    fail "Root filesystem is ${root_use}% full. Fix disk pressure before upgrades."
  elif [[ "$root_use" =~ ^[0-9]+$ ]] && (( root_use >= 80 )); then
    warn "Root filesystem is ${root_use}% full."
  else
    pass "Root filesystem usage is acceptable (${root_use:-unknown}%)."
  fi

  if systemctl --failed --no-legend 2>/dev/null | grep -q .; then
    warn "systemd has failed units:"
    systemctl --failed --no-pager || true
  else
    pass "No failed systemd units."
  fi
}

check_updates() {
  section "2. Package updates"

  if ! command_exists apt-get; then
    skip "APT not present."
    return
  fi

  local upgrades
  if is_audit; then
    info "Audit mode: using the existing APT cache; package metadata is not modified."
  else
    if apt-get update -qq; then
      pass "APT package metadata refreshed."
    else
      fail "apt-get update failed."
      return
    fi
  fi

  upgrades="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / {count++} END {print count+0}')"
  if [[ "$upgrades" == "0" ]]; then
    pass "No package upgrades pending."
  else
    warn "$upgrades package upgrade(s) pending."
    if ask_yes_no "Install available upgrades now?" "Y"; then
      if DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; then
        changed "Installed package upgrades."
      else
        fail "Package upgrade failed."
      fi
    fi
  fi

  if [[ -f /var/run/reboot-required ]]; then
    warn "A reboot is required. Reboot is never performed automatically by VPSGuard."
  else
    pass "No reboot currently required."
  fi
}

check_time_sync() {
  section "3. Time synchronization"
  if command_exists timedatectl; then
    local synced
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    if [[ "$synced" == "yes" ]]; then
      pass "NTP synchronization is active."
    else
      warn "NTP is not currently synchronized."
      if ask_yes_no "Enable systemd time synchronization?" "Y"; then
        timedatectl set-ntp true && changed "Enabled NTP synchronization." || fail "Could not enable NTP."
      fi
    fi
  else
    skip "timedatectl unavailable."
  fi
}

list_public_listeners() {
  if ! command_exists ss; then
    skip "ss command unavailable; cannot enumerate listeners."
    return
  fi

  info "Listening TCP/UDP sockets:"
  ss -H -lntup 2>/dev/null | sed 's/^/  /' || true

  local suspicious
  suspicious="$(ss -H -lntup 2>/dev/null | awk '$5 ~ /(^|\])0\.0\.0\.0:|^\*:|^\[::\]:/ {print}')"
  if [[ -n "$suspicious" ]]; then
    warn "Services are listening on all interfaces. Review every exposed port."
  else
    pass "No wildcard listeners detected by the basic listener check."
  fi
}

check_firewall() {
  section "4. Network exposure and host firewall"
  list_public_listeners

  local ssh_port
  ssh_port="$(get_ssh_port)"
  info "Detected SSH port: $ssh_port/tcp"

  if command_exists ufw; then
    local status
    status="$(ufw status 2>/dev/null | head -n1 || true)"
    if grep -q 'Status: active' <<<"$status"; then
      pass "UFW firewall is active."
      ufw status numbered || true
    else
      warn "UFW is installed but inactive."
    fi
  else
    warn "UFW is not installed."
    if ask_yes_no "Install UFW?" "Y"; then
      if install_packages ufw; then
        changed "Installed UFW."
      else
        fail "Could not install UFW."
        return
      fi
    else
      return
    fi
  fi

  if is_audit; then
    return
  fi

  if ! command_exists ufw; then
    return
  fi

  if ask_yes_no "Apply a default-deny inbound firewall baseline? Existing explicit UFW rules are preserved." "Y"; then
    ufw default deny incoming || { fail "Could not set default incoming policy."; return; }
    ufw default allow outgoing || { fail "Could not set default outgoing policy."; return; }
    ufw allow "${ssh_port}/tcp" comment 'VPSGuard SSH' >/dev/null || { fail "Could not allow SSH port."; return; }
    changed "Ensured SSH $ssh_port/tcp is allowed before firewall activation."

    if ask_yes_no "Allow HTTP 80/tcp?" "Y"; then
      ufw allow 80/tcp comment 'HTTP' >/dev/null && changed "Allowed HTTP 80/tcp."
    fi
    if ask_yes_no "Allow HTTPS 443/tcp?" "Y"; then
      ufw allow 443/tcp comment 'HTTPS' >/dev/null && changed "Allowed HTTPS 443/tcp."
    fi

    if ufw --force enable; then
      pass "UFW enabled. Current SSH port remains explicitly allowed."
      ufw status numbered || true
    else
      fail "UFW activation failed."
    fi
  fi
}

find_admin_key_user() {
  local candidate="${SUDO_USER:-}"
  if [[ -n "$candidate" && "$candidate" != "root" && -s "/home/$candidate/.ssh/authorized_keys" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 ]] || continue
    [[ "$shell" != */nologin && "$shell" != */false ]] || continue
    if [[ -s "$home/.ssh/authorized_keys" ]]; then
      printf '%s' "$user"
      return 0
    fi
  done < /etc/passwd
  return 1
}

create_admin_user() {
  local username
  read -r -p "New admin username: " username
  if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    fail "Invalid username."
    return 1
  fi
  if id "$username" >/dev/null 2>&1; then
    warn "User $username already exists."
  else
    adduser --disabled-password --gecos '' "$username" || return 1
    usermod -aG sudo "$username" || return 1
    changed "Created sudo admin user $username."
  fi

  local source_keys=""
  if [[ -s /root/.ssh/authorized_keys ]]; then
    source_keys="/root/.ssh/authorized_keys"
  elif [[ -n "${SUDO_USER:-}" && -s "/home/${SUDO_USER}/.ssh/authorized_keys" ]]; then
    source_keys="/home/${SUDO_USER}/.ssh/authorized_keys"
  fi

  if [[ -n "$source_keys" ]]; then
    local home
    home="$(getent passwd "$username" | cut -d: -f6)"
    install -d -m 700 -o "$username" -g "$username" "$home/.ssh"
    install -m 600 -o "$username" -g "$username" "$source_keys" "$home/.ssh/authorized_keys"
    changed "Copied existing authorized_keys to $username."
  else
    warn "No existing authorized_keys found to copy. Add an SSH key before disabling password/root login."
  fi
}

check_accounts() {
  section "5. Accounts and privileged access"

  local uid0
  uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')"
  if [[ "$uid0" == "root " ]]; then
    pass "Only root has UID 0."
  else
    warn "UID 0 accounts: $uid0"
  fi

  local admin_user=""
  admin_user="$(find_admin_key_user || true)"
  if [[ -n "$admin_user" ]]; then
    pass "Found non-root SSH-key user: $admin_user"
  else
    warn "No non-root user with authorized_keys was found."
    if ask_yes_no "Create a sudo admin user and copy an existing SSH key if available?" "Y"; then
      create_admin_user || fail "Admin user creation failed."
    fi
  fi
}

check_ssh() {
  section "6. SSH hardening"

  if ! command_exists sshd; then
    fail "OpenSSH server not detected."
    return
  fi

  local effective
  effective="$(sshd -T 2>/dev/null || true)"
  if [[ -z "$effective" ]]; then
    fail "Could not read effective sshd configuration."
    return
  fi

  local root_login password_auth empty_pw max_tries x11
  root_login="$(awk '$1=="permitrootlogin" {print $2; exit}' <<<"$effective")"
  password_auth="$(awk '$1=="passwordauthentication" {print $2; exit}' <<<"$effective")"
  empty_pw="$(awk '$1=="permitemptypasswords" {print $2; exit}' <<<"$effective")"
  max_tries="$(awk '$1=="maxauthtries" {print $2; exit}' <<<"$effective")"
  x11="$(awk '$1=="x11forwarding" {print $2; exit}' <<<"$effective")"

  [[ "$root_login" == "no" ]] && pass "SSH root login disabled." || warn "PermitRootLogin=$root_login"
  [[ "$password_auth" == "no" ]] && pass "SSH password authentication disabled." || warn "PasswordAuthentication=$password_auth"
  [[ "$empty_pw" == "no" ]] && pass "Empty SSH passwords disabled." || warn "PermitEmptyPasswords=$empty_pw"
  [[ "$max_tries" =~ ^[0-9]+$ ]] && (( max_tries <= 3 )) && pass "MaxAuthTries=$max_tries" || warn "MaxAuthTries=$max_tries"
  [[ "$x11" == "no" ]] && pass "X11 forwarding disabled." || warn "X11Forwarding=$x11"

  if is_audit; then
    return
  fi

  local admin_user=""
  admin_user="$(find_admin_key_user || true)"
  if [[ -z "$admin_user" ]]; then
    warn "SSH hardening not offered because no non-root key-based admin account was detected. This prevents accidental lockout."
    return
  fi

  if ! ask_yes_no "Apply the conservative SSH hardening baseline now?" "Y"; then
    return
  fi

  local dropin_dir="/etc/ssh/sshd_config.d"
  local dropin="$dropin_dir/99-vpsguard.conf"
  mkdir -p "$dropin_dir"

  local content
  content=$(cat <<'SSHEOF'
# Managed by VPSGuard. Re-running VPSGuard may update this file.
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
SSHEOF
)

  backup_file "$dropin"
  printf '%s\n' "$content" > "$dropin"
  chmod 600 "$dropin"

  if safe_sshd_reload; then
    changed "Applied SSH hardening in $dropin."
    warn "Keep this current SSH session open until you verify a NEW SSH login as $admin_user in a second terminal."
  else
    if [[ -f "$BACKUP_DIR$dropin" ]]; then
      cp -a "$BACKUP_DIR$dropin" "$dropin"
    else
      rm -f "$dropin"
    fi
    safe_sshd_reload || true
    fail "SSH hardening rolled back."
  fi
}

check_unattended_upgrades() {
  section "7. Automatic security updates"

  if pkg_installed unattended-upgrades; then
    pass "unattended-upgrades is installed."
  else
    warn "unattended-upgrades is not installed."
    if ask_yes_no "Install unattended-upgrades?" "Y"; then
      install_packages unattended-upgrades && changed "Installed unattended-upgrades." || { fail "Install failed."; return; }
    else
      return
    fi
  fi

  local cfg="/etc/apt/apt.conf.d/20auto-upgrades"
  local content='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'

  if [[ -f "$cfg" ]] && grep -q 'Unattended-Upgrade "1"' "$cfg" && grep -q 'Update-Package-Lists "1"' "$cfg"; then
    pass "Daily automatic package list refresh and unattended upgrades are enabled."
  else
    warn "Automatic upgrade schedule is not fully enabled."
    if ask_yes_no "Enable daily unattended upgrades?" "Y"; then
      write_file_if_changed "$cfg" 644 "$content" || true
    fi
  fi
}

check_fail2ban() {
  section "8. SSH brute-force protection"

  if pkg_installed fail2ban; then
    pass "Fail2ban is installed."
  else
    warn "Fail2ban is not installed."
    if ask_yes_no "Install Fail2ban for SSH protection?" "Y"; then
      install_packages fail2ban && changed "Installed Fail2ban." || { fail "Fail2ban install failed."; return; }
    else
      return
    fi
  fi

  local jail="/etc/fail2ban/jail.d/vpsguard.conf"
  local ssh_port
  ssh_port="$(get_ssh_port)"
  local content
  content=$(cat <<EOF2
[sshd]
enabled = true
port = $ssh_port
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 5
EOF2
)

  if [[ -f "$jail" ]] && cmp -s <(printf '%s\n' "$content") "$jail"; then
    pass "Fail2ban VPSGuard SSH jail is configured."
  else
    warn "Fail2ban SSH jail does not match the VPSGuard baseline."
    if ask_yes_no "Write the VPSGuard SSH jail?" "Y"; then
      write_file_if_changed "$jail" 644 "$content" || true
      if fail2ban-client -t >/dev/null 2>&1 && systemctl enable --now fail2ban >/dev/null 2>&1 && systemctl restart fail2ban; then
        changed "Enabled and validated Fail2ban SSH jail."
      else
        fail "Fail2ban validation/start failed. Review $jail."
      fi
    fi
  fi

  if command_exists fail2ban-client && fail2ban-client status sshd >/dev/null 2>&1; then
    pass "Fail2ban sshd jail is active."
  else
    warn "Fail2ban sshd jail is not currently active."
  fi
}

check_sysctl() {
  section "9. Conservative kernel/network hardening"

  local cfg="/etc/sysctl.d/99-vpsguard.conf"
  local content
  content=$(cat <<'SYSCTLEOF'
# Managed by VPSGuard - conservative internet-facing server baseline.
# Intentionally does not disable IPv6 or IP forwarding globally because that
# can break Docker, VPNs, routing, Kubernetes, and cloud networking.

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1

kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
SYSCTLEOF
)

  local differs=0
  [[ -f "$cfg" ]] && cmp -s <(printf '%s\n' "$content") "$cfg" || differs=1
  if (( differs == 0 )); then
    pass "VPSGuard sysctl baseline is installed."
  else
    warn "VPSGuard sysctl baseline is not installed."
    if ask_yes_no "Install the conservative sysctl baseline?" "Y"; then
      write_file_if_changed "$cfg" 644 "$content" || true
      if sysctl --system >/dev/null 2>&1; then
        changed "Applied sysctl baseline."
      else
        fail "sysctl --system returned an error. Review $cfg."
      fi
    fi
  fi
}

check_apparmor() {
  section "10. AppArmor"
  if command_exists aa-status; then
    if aa-status --enabled >/dev/null 2>&1; then
      pass "AppArmor is enabled."
      aa-status 2>/dev/null | sed -n '1,6p' | sed 's/^/  /' || true
    else
      warn "AppArmor tools exist but AppArmor is not enabled."
    fi
  elif [[ -d /sys/kernel/security/apparmor ]]; then
    pass "AppArmor kernel interface detected."
  else
    warn "AppArmor not detected."
    if ask_yes_no "Install AppArmor utilities?" "Y"; then
      install_packages apparmor apparmor-utils && changed "Installed AppArmor packages." || fail "AppArmor install failed."
    fi
  fi
}

check_nginx() {
  section "11. Nginx reverse proxy"

  if command_exists nginx; then
    pass "Nginx is installed: $(nginx -v 2>&1)"
  else
    warn "Nginx is not installed."
    if ask_yes_no "Install Nginx?" "Y"; then
      install_packages nginx && changed "Installed Nginx." || { fail "Nginx install failed."; return; }
    else
      return
    fi
  fi

  if ! command_exists nginx; then
    return
  fi

  if nginx -t >/dev/null 2>&1; then
    pass "Current Nginx configuration validates."
  else
    fail "Current Nginx configuration is invalid. VPSGuard will not modify/reload it."
    nginx -t || true
    return
  fi

  local cfg="/etc/nginx/conf.d/00-vpsguard-security.conf"
  local content='server_tokens off;'
  if [[ -f "$cfg" ]] && grep -Eq '^server_tokens[[:space:]]+off;' "$cfg"; then
    pass "Nginx version tokens are disabled."
  else
    warn "Nginx server_tokens hardening is not installed."
    if ask_yes_no "Disable Nginx version tokens globally?" "Y"; then
      backup_file "$cfg"
      printf '%s\n' "$content" > "$cfg"
      if nginx -t >/dev/null 2>&1 && systemctl reload nginx; then
        changed "Disabled Nginx version tokens."
      else
        [[ -f "$BACKUP_DIR$cfg" ]] && cp -a "$BACKUP_DIR$cfg" "$cfg" || rm -f "$cfg"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
        fail "Nginx change failed and was rolled back."
      fi
    fi
  fi

  if service_active nginx; then
    pass "Nginx service is active."
  else
    warn "Nginx is installed but inactive."
    if ask_yes_no "Enable and start Nginx?" "Y"; then
      systemctl enable --now nginx && changed "Enabled and started Nginx." || fail "Could not start Nginx."
    fi
  fi

  if command_exists certbot; then
    pass "Certbot is installed."
  else
    warn "Certbot is not installed. TLS certificate provisioning remains to be done once a domain points at this VPS."
  fi
}

check_database_exposure() {
  section "12. Database/cache exposure"
  if ! command_exists ss; then
    skip "ss unavailable."
    return
  fi

  local ports='3306|5432|6379|27017|9200|11211'
  local exposed
  exposed="$(ss -H -lntp 2>/dev/null | awk -v re=":("$ports")$" '$4 ~ re && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\[::\]:/ || $4 ~ /^\*:/) {print}')"

  if [[ -n "$exposed" ]]; then
    fail "A common database/cache port appears bound to all interfaces:"
    printf '%s\n' "$exposed" | sed 's/^/  /'
  else
    pass "No common DB/cache ports detected on wildcard addresses."
  fi
}

check_docker() {
  section "13. Docker exposure"
  if ! command_exists docker; then
    skip "Docker is not installed."
    return
  fi

  pass "Docker is installed."
  local published
  published="$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:' || true)"
  if [[ -n "$published" ]]; then
    warn "Docker containers publish ports on all interfaces. Docker-published ports can bypass normal UFW expectations; review these bindings:"
    printf '%s\n' "$published" | sed 's/^/  /'
    info "Prefer 127.0.0.1:HOSTPORT:CONTAINERPORT for services that should only be reached through Nginx."
  else
    pass "No running Docker container found publishing a port on all interfaces."
  fi
}

check_logging() {
  section "14. Logging and journal persistence"

  if [[ -d /var/log/journal ]]; then
    pass "Persistent systemd journal directory exists."
  else
    warn "Persistent journal directory is absent; logs may be volatile depending on journald configuration."
    if ask_yes_no "Enable persistent journald storage?" "Y"; then
      mkdir -p /var/log/journal
      systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
      systemctl restart systemd-journald && changed "Enabled persistent journal storage." || fail "Could not restart journald."
    fi
  fi

  if command_exists logrotate; then
    pass "logrotate is installed."
  else
    warn "logrotate is not installed."
    if ask_yes_no "Install logrotate?" "Y"; then
      install_packages logrotate && changed "Installed logrotate." || fail "Could not install logrotate."
    fi
  fi
}

check_permissions() {
  section "15. Critical file permissions"
  local bad=0

  if [[ -e /root/.ssh ]]; then
    local mode
    mode="$(stat -c '%a' /root/.ssh 2>/dev/null || true)"
    if [[ "$mode" == "700" ]]; then
      pass "/root/.ssh mode is 700."
    else
      warn "/root/.ssh mode is ${mode:-unknown}; expected 700."
      bad=1
    fi
  fi

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 ]] || continue
    [[ "$shell" != */nologin && "$shell" != */false ]] || continue
    if [[ -f "$home/.ssh/authorized_keys" ]]; then
      local keymode
      keymode="$(stat -c '%a' "$home/.ssh/authorized_keys" 2>/dev/null || true)"
      if [[ "$keymode" == "600" ]]; then
        pass "$user authorized_keys mode is 600."
      else
        warn "$user authorized_keys mode is ${keymode:-unknown}; expected 600."
        bad=1
      fi
    fi
  done < /etc/passwd

  if (( bad == 1 )) && ! is_audit; then
    info "VPSGuard reports permission issues but does not automatically chmod user SSH files without an explicit per-user review."
  fi
}

check_optional_audit() {
  section "16. Optional deeper audit"

  if command_exists lynis; then
    pass "Lynis is installed."
    if ask_yes_no "Run 'lynis audit system --quick' now?" "N"; then
      lynis audit system --quick || warn "Lynis completed with a non-zero status. Review its report."
    fi
  else
    warn "Lynis is not installed."
    if ask_yes_no "Install Lynis for deeper system auditing?" "N"; then
      install_packages lynis && changed "Installed Lynis." || fail "Could not install Lynis."
    fi
  fi
}

final_report() {
  section "Final report"
  printf 'PASS:    %d\n' "$PASS_COUNT"
  printf 'WARN:    %d\n' "$WARN_COUNT"
  printf 'FAIL:    %d\n' "$FAIL_COUNT"
  printf 'SKIP:    %d\n' "$SKIP_COUNT"
  printf 'CHANGED: %d\n' "$CHANGE_COUNT"
  printf '\n'
  if is_audit; then
    info "Audit mode: no persistent VPSGuard log or configuration backup was written."
  else
    info "Log: $LOG_FILE"
  fi
  if [[ -d "$BACKUP_DIR" ]]; then
    info "Backups from this run: $BACKUP_DIR"
  fi

  if (( FAIL_COUNT > 0 )); then
    return 2
  elif (( WARN_COUNT > 0 )); then
    return 1
  fi
  return 0
}

main() {
  need_root
  if ! is_audit; then
    touch "$LOG_FILE" 2>/dev/null || true
    chmod 600 "$LOG_FILE" 2>/dev/null || true
  fi

  echo "VPSGuard $VERSION - mode: $MODE"
  echo "Safe baseline for a small internet-facing web VPS"

  check_os
  check_updates
  check_time_sync
  check_firewall
  check_accounts
  check_ssh
  check_unattended_upgrades
  check_fail2ban
  check_sysctl
  check_apparmor
  check_nginx
  check_database_exposure
  check_docker
  check_logging
  check_permissions
  check_optional_audit

  final_report
}

main "$@"