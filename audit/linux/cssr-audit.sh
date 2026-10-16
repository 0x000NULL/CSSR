#!/usr/bin/env bash
# cssr-audit.sh - check-only security audit for CyberPatriot-style Linux images.
#
# Reports what looks wrong and prints the command that would fix it. It never changes the
# system: it only reads files, /proc and the output of status commands, and makes no
# network calls (no `apt update`).
#
# Targets Ubuntu 22.04/24.04; Debian 12 and Linux Mint work on a best-effort basis.
# Part of CSSR (https://github.com/0x000NULL/CSSR), MIT License.

# shellcheck disable=SC2317,SC2329,SC1091  # checks are called via the CHECKS registry; os-release is sourced at runtime
set -u

CSSR_AUDIT_VERSION="2026.1"

# Thresholds (CIS-style). Keep in sync with docs/guides/linux-hardening.md.
PASS_MAX_DAYS_MAX=90     # login.defs PASS_MAX_DAYS must be <= this
PASS_MIN_DAYS_MIN=1      # login.defs PASS_MIN_DAYS must be >= this
PASS_WARN_AGE_MIN=7      # login.defs PASS_WARN_AGE must be >= this
PW_MINLEN_PASS=14        # pam_pwquality minlen: PASS at or above
PW_MINLEN_FAIL=10        # ...FAIL below this, WARN in between
PW_REMEMBER_MIN=5        # password history (pam_pwhistory/pam_unix remember)
LOCKOUT_DENY_MAX=5       # pam_faillock deny must be 1..this
SSH_MAX_AUTH_TRIES_MAX=4

# Packages that are almost never allowed on a CyberPatriot image. Always check the README:
# if it says a tool is required for the scenario, it is not a vulnerability.
HACKING_PACKAGES=(john john-data hydra hydra-gtk nmap zenmap ncat wireshark wireshark-qt
  wireshark-gtk tshark ophcrack ophcrack-cli aircrack-ng netcat-traditional nikto sqlmap
  ettercap-common ettercap-graphical ettercap-text-only medusa kismet fcrackzip hashcat
  dsniff yersinia)
GAME_P2P_PACKAGES=(aisleriot gnome-mines gnome-sudoku gnome-mahjongg freeciv-client-gtk3
  minetest supertuxkart wesnoth transmission-gtk transmission-cli transmission-daemon
  deluge deluge-gtk qbittorrent frostwire)
RISKY_SERVICES=(telnet.socket inetd xinetd vsftpd proftpd pure-ftpd tftpd-hpa apache2 nginx
  smbd nmbd nfs-server rpcbind snmpd rsh.socket rlogin.socket avahi-daemon slapd)
MEDIA_EXTENSIONS=(mp3 mp4 m4a m4v avi mkv mov wmv flv wav flac ogg aac wma 3gp mid midi)
NETCAT_NAMES=(nc ncat netcat nc.traditional nc.openbsd socat)

# ---------------------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: sudo ./cssr-audit.sh [options]

Check-only audit: reports findings and fix commands, changes nothing.

Options:
  --users FILE     Authorized users (one name per line, # comments allowed).
                   Use every user the README lists, administrators included.
  --admins FILE    Authorized administrators (same format).
  --json FILE      Also write a JSON report to FILE.
  --list-checks    Print the list of checks and exit.
  --markdown       With --list-checks, print a Markdown table.
  --no-color       Disable colored output.
  -h, --help       Show this help.

Exit codes: 0 no FAIL findings, 1 at least one FAIL, 2 usage error.
EOF
}

USERS_FILE=""
ADMINS_FILE=""
JSON_FILE=""
LIST_CHECKS=0
MARKDOWN=0
COLOR=1
[ -t 1 ] || COLOR=0

while [ $# -gt 0 ]; do
  case "$1" in
    --users) [ $# -ge 2 ] || { usage >&2; exit 2; }; USERS_FILE=$2; shift 2 ;;
    --admins) [ $# -ge 2 ] || { usage >&2; exit 2; }; ADMINS_FILE=$2; shift 2 ;;
    --json) [ $# -ge 2 ] || { usage >&2; exit 2; }; JSON_FILE=$2; shift 2 ;;
    --list-checks) LIST_CHECKS=1; shift ;;
    --markdown) MARKDOWN=1; shift ;;
    --no-color) COLOR=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for f in "$USERS_FILE" "$ADMINS_FILE"; do
  if [ -n "$f" ] && [ ! -r "$f" ]; then
    echo "Cannot read $f" >&2
    exit 2
  fi
done

# ---------------------------------------------------------------------------------------
# Check registry: ID|Category|Description|function

CHECKS=()
register() { CHECKS+=("$1|$2|$3|$4"); }

register LNX-USR-01 Users "No account other than root has UID 0" chk_uid0
register LNX-USR-02 Users "No account has an empty password" chk_empty_passwords
register LNX-USR-03 Users "Every human account is an authorized user (--users)" chk_unauthorized_users
register LNX-USR-04 Users "Every authorized user exists (--users)" chk_missing_users
register LNX-USR-05 Users "Only authorized admins are in sudo/admin/wheel (--admins)" chk_admin_groups
register LNX-USR-06 Users "sudoers has no NOPASSWD or !authenticate rules" chk_sudoers
register LNX-USR-07 Users "No guest session or automatic login (LightDM/GDM)" chk_guest_autologin
register LNX-PWD-01 Passwords "PASS_MAX_DAYS <= ${PASS_MAX_DAYS_MAX} in /etc/login.defs" chk_pass_max_days
register LNX-PWD-02 Passwords "PASS_MIN_DAYS >= ${PASS_MIN_DAYS_MIN} in /etc/login.defs" chk_pass_min_days
register LNX-PWD-03 Passwords "PASS_WARN_AGE >= ${PASS_WARN_AGE_MIN} in /etc/login.defs" chk_pass_warn_age
register LNX-PWD-04 Passwords "Existing users' passwords expire within ${PASS_MAX_DAYS_MAX} days" chk_user_max_days
register LNX-PWD-05 Passwords "pam_pwquality is enabled with minlen >= ${PW_MINLEN_PASS}" chk_pwquality_minlen
register LNX-PWD-06 Passwords "Password complexity requires several character classes" chk_pwquality_classes
register LNX-PWD-07 Passwords "Password history remembers >= ${PW_REMEMBER_MIN} passwords" chk_pw_history
register LNX-PWD-08 Passwords "pam_unix does not allow empty passwords (nullok)" chk_nullok
register LNX-PWD-09 Passwords "Account lockout (pam_faillock) after <= ${LOCKOUT_DENY_MAX} failures" chk_lockout
register LNX-SSH-01 SSH "PermitRootLogin no" chk_ssh_root_login
register LNX-SSH-02 SSH "PermitEmptyPasswords no" chk_ssh_empty_passwords
register LNX-SSH-03 SSH "X11Forwarding no" chk_ssh_x11
register LNX-SSH-04 SSH "MaxAuthTries <= ${SSH_MAX_AUTH_TRIES_MAX}" chk_ssh_max_auth_tries
register LNX-FW-01 Firewall "UFW is installed and active" chk_ufw_active
register LNX-FW-02 Firewall "UFW denies incoming traffic by default" chk_ufw_default
register LNX-UPD-01 Updates "Package lists are refreshed automatically" chk_apt_periodic_update
register LNX-UPD-02 Updates "Unattended security upgrades are enabled" chk_apt_unattended
register LNX-UPD-03 Updates "No upgradable packages in the local apt cache" chk_upgradable
register LNX-KRN-01 Kernel "TCP SYN cookies on (net.ipv4.tcp_syncookies=1)" chk_sysctl_syncookies
register LNX-KRN-02 Kernel "IP forwarding off (net.ipv4.ip_forward=0)" chk_sysctl_ip_forward
register LNX-KRN-03 Kernel "ICMP redirects ignored (accept_redirects=0)" chk_sysctl_accept_redirects
register LNX-KRN-04 Kernel "ICMP redirects not sent (send_redirects=0)" chk_sysctl_send_redirects
register LNX-KRN-05 Kernel "Source-routed packets rejected (accept_source_route=0)" chk_sysctl_source_route
register LNX-KRN-06 Kernel "Reverse path filtering on (rp_filter=1)" chk_sysctl_rp_filter
register LNX-KRN-07 Kernel "Full ASLR (kernel.randomize_va_space=2)" chk_sysctl_aslr
register LNX-KRN-08 Kernel "No core dumps from setuid programs (fs.suid_dumpable=0)" chk_sysctl_suid_dumpable
register LNX-KRN-09 Kernel "Martian packets logged (log_martians=1)" chk_sysctl_martians
register LNX-AUD-01 Auditing "auditd is running" chk_auditd
register LNX-AUD-02 Auditing "AppArmor is enabled" chk_apparmor
register LNX-SVC-01 Services "No commonly-unwanted network services are running" chk_risky_services
register LNX-PKG-01 Software "No hacking tools are installed" chk_hacking_packages
register LNX-PKG-02 Software "No games or torrent clients are installed" chk_game_packages
register LNX-FIL-01 Files "No media files in /home" chk_media_files
register LNX-FIL-02 Files "/etc/shadow is owned by root and not world-readable" chk_shadow_perms
register LNX-FIL-03 Files "/etc/passwd and /etc/group are root-owned and not writable by others" chk_passwd_perms
register LNX-FIL-04 Files "No world-writable files in /etc" chk_world_writable_etc
register LNX-NET-01 Network "Listening ports (review against the README)" chk_listening
register LNX-NET-02 Network "No netcat or socat listeners" chk_netcat_listeners
register LNX-NET-03 Network "/etc/hosts has only default entries" chk_hosts
register LNX-NET-04 Network "Cron jobs (review for persistence)" chk_cron
register LNX-NET-05 Network "APT sources are official repositories" chk_apt_sources

if [ "$LIST_CHECKS" -eq 1 ]; then
  if [ "$MARKDOWN" -eq 1 ]; then
    echo "| ID | Category | Check |"
    echo "|---|---|---|"
  fi
  for entry in "${CHECKS[@]}"; do
    IFS='|' read -r id cat desc _ <<<"$entry"
    if [ "$MARKDOWN" -eq 1 ]; then
      echo "| \`$id\` | $cat | $desc |"
    else
      printf '%-11s %-10s %s\n' "$id" "$cat" "$desc"
    fi
  done
  exit 0
fi

# ---------------------------------------------------------------------------------------
# Helpers

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
HAVE_SYSTEMD=0
[ -d /run/systemd/system ] && HAVE_SYSTEMD=1

R_STATUS=(); R_ID=(); R_CAT=(); R_MSG=(); R_FIX=()
CURRENT_ID=""; CURRENT_CAT=""

report() { # STATUS MESSAGE [FIX]
  R_STATUS+=("$1"); R_ID+=("$CURRENT_ID"); R_CAT+=("$CURRENT_CAT")
  R_MSG+=("$2"); R_FIX+=("${3:-}")
}
pass() { report PASS "$1"; }
fail() { report FAIL "$1" "${2:-}"; }
warn() { report WARN "$1" "${2:-}"; }
info() { report INFO "$1" "${2:-}"; }
skip() { report SKIP "$1"; }

need_root() {
  if [ "$IS_ROOT" -ne 1 ]; then
    skip "Needs root; run with sudo."
    return 1
  fi
}
need_systemd() {
  if [ "$HAVE_SYSTEMD" -ne 1 ]; then
    skip "systemd is not running here."
    return 1
  fi
}

# Read a name list: one name per line, comments and blank lines ignored.
read_list() {
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$1" | grep -v '^$' | sort -u
}

join_csv() { local IFS=',' s; s="$*"; echo "${s//,/, }"; }

# Human (login-capable, regular-UID) accounts.
human_users() {
  local min max
  min=$(awk '$1=="UID_MIN" {print $2}' /etc/login.defs 2>/dev/null); min=${min:-1000}
  max=$(awk '$1=="UID_MAX" {print $2}' /etc/login.defs 2>/dev/null); max=${max:-60000}
  awk -F: -v min="$min" -v max="$max" \
    '$3>=min && $3<=max && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | sort -u
}

# Value of KEY in /etc/login.defs (last uncommented occurrence).
login_defs() {
  awk -v k="$1" '$1==k {v=$2} END {print v}' /etc/login.defs 2>/dev/null
}

# Uncommented module lines from a PAM file.
pam_lines() {
  local file="/etc/pam.d/$1"
  [ -r "$file" ] && grep -E '^\s*[^#[:space:]]' "$file"
}

# Value of NAME=VALUE argument on PAM lines matching MODULE in FILE (last wins).
pam_arg() { # FILE MODULE NAME
  pam_lines "$1" | grep -E "$2" | grep -oE "(^|[[:space:]])$3=[^[:space:]]+" | tail -n1 | cut -d= -f2
}

# Value of KEY from a "key = value" config file (last uncommented occurrence).
conf_value() { # FILE KEY
  [ -r "$1" ] || return 0
  sed -n -E "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*([^[:space:]#]+).*/\1/p" "$1" | tail -n1
}

is_int() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

package_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# Effective sshd setting: `sshd -T` when it works, else parse sshd_config (first match wins,
# Include expanded, Match blocks ignored), else the OpenSSH default passed as $2.
SSHD_T=""
SSHD_T_TRIED=0
sshd_setting() { # KEYWORD DEFAULT
  local key=${1,,} def=$2 val=""
  if [ "$SSHD_T_TRIED" -eq 0 ]; then
    SSHD_T_TRIED=1
    if [ "$IS_ROOT" -eq 1 ] && command -v sshd >/dev/null 2>&1; then
      SSHD_T=$(sshd -T 2>/dev/null || true)
    fi
  fi
  if [ -n "$SSHD_T" ]; then
    val=$(awk -v k="$key" 'tolower($1)==k {print $2; exit}' <<<"$SSHD_T")
  else
    val=$(sshd_config_lines /etc/ssh/sshd_config | awk -v k="$key" \
      'tolower($1)=="match" {exit} tolower($1)==k {print $2; exit}')
  fi
  echo "${val:-$def}"
}
sshd_config_lines() {
  local file=$1 line inc
  [ -r "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    if [[ "${line,,}" =~ ^[[:space:]]*include[[:space:]] ]]; then
      local rest
      rest=$(sed -E 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]+//' <<<"$line")
      for inc in $rest; do
        [[ "$inc" = /* ]] || inc="/etc/ssh/$inc"
        for f in $inc; do sshd_config_lines "$f"; done
      done
    else
      echo "$line"
    fi
  done <"$file"
}
sshd_installed() {
  if [ ! -e /usr/sbin/sshd ] && ! command -v sshd >/dev/null 2>&1; then
    skip "OpenSSH server is not installed."
    return 1
  fi
}

# ---------------------------------------------------------------------------------------
# Users

chk_uid0() {
  local extra
  extra=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | paste -sd, - | sed 's/,/, /g')
  if [ -n "$extra" ]; then
    fail "Accounts with UID 0 besides root: $extra" \
      "Remove the account (userdel NAME) or give it its own UID (usermod -u NEW_UID NAME)."
  else
    pass "Only root has UID 0."
  fi
}

chk_empty_passwords() {
  need_root || return
  local empty
  empty=$(awk -F: '$2=="" {print $1}' /etc/shadow | paste -sd, - | sed 's/,/, /g')
  if [ -n "$empty" ]; then
    fail "Accounts with an empty password: $empty" "passwd NAME   (or lock it: passwd -l NAME)"
  else
    pass "No account has an empty password."
  fi
}

chk_unauthorized_users() {
  if [ -z "$USERS_FILE" ]; then
    skip "Pass --users FILE with the users from the README."
    return
  fi
  local bad
  bad=$(comm -23 <(human_users) <(read_list "$USERS_FILE") | paste -sd, - | sed 's/,/, /g')
  if [ -n "$bad" ]; then
    warn "Human accounts not in the authorized list: $bad" \
      "Confirm against the README, then: deluser NAME   (keep their files if the README asks)"
  else
    pass "Every human account is authorized."
  fi
}

chk_missing_users() {
  if [ -z "$USERS_FILE" ]; then
    skip "Pass --users FILE with the users from the README."
    return
  fi
  local missing
  missing=$(comm -13 <(cut -d: -f1 /etc/passwd | sort -u) <(read_list "$USERS_FILE") \
    | paste -sd, - | sed 's/,/, /g')
  if [ -n "$missing" ]; then
    warn "Authorized users that don't exist: $missing" "adduser NAME   (if the README asks for it)"
  else
    pass "Every authorized user exists."
  fi
}

chk_admin_groups() {
  local members g
  members=$(for g in sudo admin wheel; do
      getent group "$g" | cut -d: -f4 | tr ',' '\n'
    done | grep -v '^$' | sort -u)
  if [ -z "$ADMINS_FILE" ]; then
    info "Members of sudo/admin/wheel: $(echo "$members" | paste -sd, - | sed 's/,/, /g'). Pass --admins FILE to compare with the README."
    return
  fi
  local bad
  bad=$(comm -23 <(echo "$members" | grep -v '^$') <(read_list "$ADMINS_FILE") \
    | paste -sd, - | sed 's/,/, /g')
  if [ -n "$bad" ]; then
    fail "Unauthorized administrators: $bad" "gpasswd -d NAME sudo   (and admin/wheel if present)"
  else
    pass "Only authorized administrators have sudo."
  fi
}

chk_sudoers() {
  need_root || return
  local hits
  hits=$(grep -HnsE '^[^#]*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
    | cut -c1-120)
  if [ -n "$hits" ]; then
    fail "sudo rules that skip the password: $(echo "$hits" | paste -sd ';' -)" \
      "visudo   (or visudo -f /etc/sudoers.d/FILE) and remove NOPASSWD / !authenticate"
  else
    pass "No passwordless sudo rules."
  fi
}

chk_guest_autologin() {
  local hits f
  hits=""
  for f in /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf \
           /usr/share/lightdm/lightdm.conf.d/*.conf; do
    [ -r "$f" ] || continue
    grep -qiE '^\s*allow-guest\s*=\s*true' "$f" && hits+="$f: allow-guest=true; "
    grep -qiE '^\s*autologin-user\s*=\s*\S' "$f" && hits+="$f: autologin-user; "
  done
  for f in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf; do
    [ -r "$f" ] || continue
    grep -qiE '^\s*AutomaticLoginEnable\s*=\s*true' "$f" && hits+="$f: AutomaticLoginEnable=true; "
    grep -qiE '^\s*TimedLoginEnable\s*=\s*true' "$f" && hits+="$f: TimedLoginEnable=true; "
  done
  if [ -n "$hits" ]; then
    fail "Guest or automatic login is enabled: ${hits%; }" \
      "LightDM: set allow-guest=false and remove autologin-user. GDM: set AutomaticLoginEnable=false in /etc/gdm3/custom.conf."
  else
    pass "No guest session or automatic login configured."
  fi
}

# ---------------------------------------------------------------------------------------
# Passwords

chk_pass_max_days() {
  local v; v=$(login_defs PASS_MAX_DAYS)
  if is_int "$v" && [ "$v" -le "$PASS_MAX_DAYS_MAX" ] && [ "$v" -gt 0 ]; then
    pass "PASS_MAX_DAYS is $v."
  else
    fail "PASS_MAX_DAYS is ${v:-unset}." \
      "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${PASS_MAX_DAYS_MAX}/' /etc/login.defs"
  fi
}

chk_pass_min_days() {
  local v; v=$(login_defs PASS_MIN_DAYS)
  if is_int "$v" && [ "$v" -ge "$PASS_MIN_DAYS_MIN" ]; then
    pass "PASS_MIN_DAYS is $v."
  else
    fail "PASS_MIN_DAYS is ${v:-unset}." \
      "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${PASS_MIN_DAYS_MIN}/' /etc/login.defs"
  fi
}

chk_pass_warn_age() {
  local v; v=$(login_defs PASS_WARN_AGE)
  if is_int "$v" && [ "$v" -ge "$PASS_WARN_AGE_MIN" ]; then
    pass "PASS_WARN_AGE is $v."
  else
    fail "PASS_WARN_AGE is ${v:-unset}." \
      "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${PASS_WARN_AGE_MIN}/' /etc/login.defs"
  fi
}

chk_user_max_days() {
  need_root || return
  local bad
  bad=$(comm -12 <(human_users) <(awk -F: -v m="$PASS_MAX_DAYS_MAX" \
      '$2 !~ /^[!*]/ && ($5=="" || $5>m) {print $1}' /etc/shadow | sort -u) \
    | paste -sd, - | sed 's/,/, /g')
  if [ -n "$bad" ]; then
    warn "login.defs only applies to new accounts. These users' passwords don't expire within ${PASS_MAX_DAYS_MAX} days: $bad" \
      "chage -M ${PASS_MAX_DAYS_MAX} -m ${PASS_MIN_DAYS_MIN} -W ${PASS_WARN_AGE_MIN} NAME"
  else
    pass "Every human account's password expires within ${PASS_MAX_DAYS_MAX} days."
  fi
}

chk_pwquality_minlen() {
  if ! pam_lines common-password | grep -q 'pam_pwquality.so'; then
    fail "pam_pwquality is not enabled in /etc/pam.d/common-password." \
      "apt install libpam-pwquality   (adds it to common-password), then set minlen = ${PW_MINLEN_PASS} in /etc/security/pwquality.conf"
    return
  fi
  local v
  v=$(pam_arg common-password pam_pwquality.so minlen)
  [ -n "$v" ] || v=$(conf_value /etc/security/pwquality.conf minlen)
  v=${v:-8}
  if ! is_int "$v"; then
    warn "Couldn't read minlen ($v)." "Set minlen = ${PW_MINLEN_PASS} in /etc/security/pwquality.conf"
  elif [ "$v" -ge "$PW_MINLEN_PASS" ]; then
    pass "Minimum password length is $v."
  elif [ "$v" -ge "$PW_MINLEN_FAIL" ]; then
    warn "Minimum password length is $v (CIS recommends ${PW_MINLEN_PASS})." \
      "Set minlen = ${PW_MINLEN_PASS} in /etc/security/pwquality.conf"
  else
    fail "Minimum password length is $v." "Set minlen = ${PW_MINLEN_PASS} in /etc/security/pwquality.conf"
  fi
}

chk_pwquality_classes() {
  if ! pam_lines common-password | grep -q 'pam_pwquality.so'; then
    skip "pam_pwquality is not enabled (see LNX-PWD-05)."
    return
  fi
  local minclass credits=0 k v
  minclass=$(pam_arg common-password pam_pwquality.so minclass)
  [ -n "$minclass" ] || minclass=$(conf_value /etc/security/pwquality.conf minclass)
  for k in ucredit lcredit dcredit ocredit; do
    v=$(pam_arg common-password pam_pwquality.so "$k")
    [ -n "$v" ] || v=$(conf_value /etc/security/pwquality.conf "$k")
    is_int "$v" && [ "$v" -lt 0 ] && credits=$((credits + 1))
  done
  if { is_int "$minclass" && [ "$minclass" -ge 3 ]; } || [ "$credits" -ge 3 ]; then
    pass "Passwords must mix character classes (minclass=${minclass:-0}, required classes=$credits)."
  else
    fail "Passwords don't have to mix upper/lower/digits/symbols." \
      "In /etc/security/pwquality.conf set: minclass = 4   (or ucredit = -1, lcredit = -1, dcredit = -1, ocredit = -1)"
  fi
}

chk_pw_history() {
  local v
  v=$(pam_arg common-password 'pam_pwhistory.so' remember)
  if [ -z "$v" ] && pam_lines common-password | grep -q pam_pwhistory.so; then
    v=$(conf_value /etc/security/pwhistory.conf remember)
    v=${v:-10}
  fi
  [ -n "$v" ] || v=$(pam_arg common-password 'pam_unix.so' remember)
  if is_int "$v" && [ "$v" -ge "$PW_REMEMBER_MIN" ]; then
    pass "The last $v passwords are remembered."
  else
    fail "Password history is ${v:-not enabled}." \
      "Add to /etc/pam.d/common-password before pam_unix: password required pam_pwhistory.so remember=${PW_REMEMBER_MIN} use_authtok"
  fi
}

chk_nullok() {
  local hits
  hits=$( { pam_lines common-auth; pam_lines common-password; } | grep -E 'pam_unix\.so.*\bnullok')
  if [ -n "$hits" ]; then
    fail "pam_unix allows empty passwords (nullok)." \
      "sed -i 's/ nullok//' /etc/pam.d/common-auth /etc/pam.d/common-password"
  else
    pass "nullok is not set on pam_unix."
  fi
}

chk_lockout() {
  local auth deny
  auth=$(pam_lines common-auth)
  if grep -q 'pam_faillock.so' <<<"$auth"; then
    deny=$(pam_arg common-auth pam_faillock.so deny)
    [ -n "$deny" ] || deny=$(conf_value /etc/security/faillock.conf deny)
    deny=${deny:-3}
  elif grep -q 'pam_tally2.so' <<<"$auth"; then
    deny=$(pam_arg common-auth pam_tally2.so deny)
  else
    fail "No account lockout: pam_faillock is not in /etc/pam.d/common-auth." \
      "Enable pam_faillock with pam-auth-update (steps: https://0x000null.github.io/CSSR/guides/linux-hardening/#password-policy), then set deny = ${LOCKOUT_DENY_MAX} and unlock_time = 900 in /etc/security/faillock.conf"
    return
  fi
  if is_int "$deny" && [ "$deny" -ge 1 ] && [ "$deny" -le "$LOCKOUT_DENY_MAX" ]; then
    pass "Accounts lock after $deny failed attempts."
  else
    fail "Lockout threshold is ${deny:-unset}." "Set deny = ${LOCKOUT_DENY_MAX} in /etc/security/faillock.conf"
  fi
}

# ---------------------------------------------------------------------------------------
# SSH

chk_ssh_root_login() {
  sshd_installed || return
  local v; v=$(sshd_setting PermitRootLogin prohibit-password)
  if [ "${v,,}" = "no" ]; then
    pass "PermitRootLogin is no."
  else
    fail "PermitRootLogin is $v." \
      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then systemctl restart ssh"
  fi
}

chk_ssh_empty_passwords() {
  sshd_installed || return
  local v; v=$(sshd_setting PermitEmptyPasswords no)
  if [ "${v,,}" = "no" ]; then
    pass "PermitEmptyPasswords is no."
  else
    fail "PermitEmptyPasswords is $v." \
      "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config, then systemctl restart ssh"
  fi
}

chk_ssh_x11() {
  sshd_installed || return
  local v; v=$(sshd_setting X11Forwarding no)
  if [ "${v,,}" = "no" ]; then
    pass "X11Forwarding is no."
  else
    warn "X11Forwarding is $v." "Set 'X11Forwarding no' in /etc/ssh/sshd_config, then systemctl restart ssh"
  fi
}

chk_ssh_max_auth_tries() {
  sshd_installed || return
  local v; v=$(sshd_setting MaxAuthTries 6)
  if is_int "$v" && [ "$v" -le "$SSH_MAX_AUTH_TRIES_MAX" ]; then
    pass "MaxAuthTries is $v."
  else
    warn "MaxAuthTries is $v." \
      "Set 'MaxAuthTries ${SSH_MAX_AUTH_TRIES_MAX}' in /etc/ssh/sshd_config, then systemctl restart ssh"
  fi
}

# ---------------------------------------------------------------------------------------
# Firewall

UFW_STATUS=""
ufw_status() {
  if [ -z "$UFW_STATUS" ]; then
    UFW_STATUS=$(ufw status verbose 2>/dev/null || true)
  fi
  echo "$UFW_STATUS"
}

chk_ufw_active() {
  if ! command -v ufw >/dev/null 2>&1; then
    fail "UFW is not installed." "apt install ufw && ufw enable"
    return
  fi
  need_root || return
  if ufw_status | grep -q '^Status: active'; then
    pass "UFW is active."
  else
    fail "UFW is installed but not active." "ufw enable"
  fi
}

chk_ufw_default() {
  command -v ufw >/dev/null 2>&1 || { skip "UFW is not installed (see LNX-FW-01)."; return; }
  need_root || return
  local s; s=$(ufw_status)
  if ! grep -q '^Status: active' <<<"$s"; then
    skip "UFW is not active (see LNX-FW-01)."
  elif grep -qE '^Default:.*(deny|reject) \(incoming\)' <<<"$s"; then
    pass "Incoming traffic is denied by default."
  else
    fail "UFW doesn't deny incoming traffic by default." "ufw default deny incoming"
  fi
}

# ---------------------------------------------------------------------------------------
# Updates

apt_periodic() { # KEY -> last value set in apt.conf.d (files read in lexical order)
  local f v=""
  for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
    [ -r "$f" ] || continue
    local x
    x=$(sed -n -E "s/^[[:space:]]*APT::Periodic::$1[[:space:]]+\"?([0-9a-zA-Z]+)\"?.*/\1/p" "$f" | tail -n1)
    [ -n "$x" ] && v=$x
  done
  echo "$v"
}

chk_apt_periodic_update() {
  local v; v=$(apt_periodic Update-Package-Lists)
  if [ -n "$v" ] && [ "$v" != "0" ]; then
    pass "APT::Periodic::Update-Package-Lists is $v."
  else
    fail "Package lists are not refreshed automatically." \
      "dpkg-reconfigure -plow unattended-upgrades   (or set APT::Periodic::Update-Package-Lists \"1\"; in /etc/apt/apt.conf.d/20auto-upgrades)"
  fi
}

chk_apt_unattended() {
  local v; v=$(apt_periodic Unattended-Upgrade)
  if ! package_installed unattended-upgrades; then
    fail "unattended-upgrades is not installed." "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"
  elif [ -n "$v" ] && [ "$v" != "0" ]; then
    pass "Unattended upgrades are enabled."
  else
    fail "Unattended upgrades are installed but turned off." \
      "dpkg-reconfigure -plow unattended-upgrades   (sets APT::Periodic::Unattended-Upgrade \"1\";)"
  fi
}

chk_upgradable() {
  command -v apt >/dev/null 2>&1 || { skip "apt is not available."; return; }
  local n
  n=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable from')
  if [ "$n" -gt 0 ]; then
    warn "$n packages can be upgraded (from the local apt cache, which may be out of date)." \
      "apt update && apt upgrade"
  else
    info "The local apt cache lists no upgrades. Run 'apt update' first if it hasn't been refreshed." \
      "apt update && apt upgrade"
  fi
}

# ---------------------------------------------------------------------------------------
# Kernel parameters (runtime values from /proc/sys)

sysctl_check() { # STATUS_IF_BAD EXPECTED KEY...
  local bad_status=$1 want=$2; shift 2
  local key path val bad=""
  for key in "$@"; do
    path="/proc/sys/${key//.//}"
    if [ ! -r "$path" ]; then
      continue
    fi
    val=$(tr -s '[:space:]' ' ' <"$path" | sed 's/ $//')
    [ "$val" = "$want" ] || bad+="$key=$val "
  done
  if [ -n "$bad" ]; then
    local fixes="" k
    for k in $bad; do fixes+="${k%%=*} = $want; "; done
    report "$bad_status" "Not set to $want: ${bad% }" \
      "Add to /etc/sysctl.d/99-cssr.conf: ${fixes%; }   then: sysctl --system"
  else
    pass "$* = $want"
  fi
}

chk_sysctl_syncookies() { sysctl_check FAIL 1 net.ipv4.tcp_syncookies; }
chk_sysctl_ip_forward() { sysctl_check FAIL 0 net.ipv4.ip_forward; }
chk_sysctl_accept_redirects() {
  sysctl_check FAIL 0 net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
    net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects
}
chk_sysctl_send_redirects() {
  sysctl_check FAIL 0 net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects
}
chk_sysctl_source_route() {
  sysctl_check FAIL 0 net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route
}
chk_sysctl_rp_filter() {
  sysctl_check WARN 1 net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter
}
chk_sysctl_aslr() { sysctl_check FAIL 2 kernel.randomize_va_space; }
chk_sysctl_suid_dumpable() { sysctl_check FAIL 0 fs.suid_dumpable; }
chk_sysctl_martians() {
  sysctl_check WARN 1 net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians
}

# ---------------------------------------------------------------------------------------
# Auditing

chk_auditd() {
  if ! package_installed auditd; then
    warn "auditd is not installed." "apt install auditd && systemctl enable --now auditd"
    return
  fi
  need_systemd || return
  if systemctl is-active --quiet auditd; then
    pass "auditd is running."
  else
    warn "auditd is installed but not running." "systemctl enable --now auditd"
  fi
}

chk_apparmor() {
  if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
    pass "AppArmor is enabled in the kernel."
  else
    warn "AppArmor is not enabled." "apt install apparmor apparmor-utils && systemctl enable --now apparmor"
  fi
}

# ---------------------------------------------------------------------------------------
# Services and software

chk_risky_services() {
  need_systemd || return
  local svc running=()
  for svc in "${RISKY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      running+=("$svc")
    fi
  done
  if [ "${#running[@]}" -gt 0 ]; then
    warn "Running or enabled: $(join_csv "${running[@]}"). Keep only what the README says is a critical service." \
      "systemctl disable --now SERVICE   (and apt purge PACKAGE if it isn't needed)"
  else
    pass "None of the commonly-unwanted services are running."
  fi
}

installed_from_list() {
  local p found=()
  for p in "$@"; do package_installed "$p" && found+=("$p"); done
  [ "${#found[@]}" -gt 0 ] && join_csv "${found[@]}"
}

chk_hacking_packages() {
  command -v dpkg-query >/dev/null 2>&1 || { skip "dpkg is not available."; return; }
  local found; found=$(installed_from_list "${HACKING_PACKAGES[@]}")
  if [ -n "$found" ]; then
    warn "Installed: $found. Remove them unless the README requires them." "apt purge PACKAGE"
  else
    pass "None of the listed hacking tools are installed."
  fi
}

chk_game_packages() {
  command -v dpkg-query >/dev/null 2>&1 || { skip "dpkg is not available."; return; }
  local found; found=$(installed_from_list "${GAME_P2P_PACKAGES[@]}")
  if [ -n "$found" ]; then
    warn "Installed: $found. Remove them unless the README allows them." "apt purge PACKAGE"
  else
    pass "None of the listed games or torrent clients are installed."
  fi
}

# ---------------------------------------------------------------------------------------
# Files

chk_media_files() {
  local args=() e files count
  for e in "${MEDIA_EXTENSIONS[@]}"; do args+=(-o -iname "*.$e"); done
  files=$(find /home -xdev -type f \( "${args[@]:1}" \) 2>/dev/null)
  count=$(grep -c . <<<"$files")
  local note=""
  [ "$IS_ROOT" -eq 1 ] || note=" (run as root to search every home folder)"
  if [ "$count" -gt 0 ]; then
    warn "$count media files under /home$note, e.g.: $(head -n 10 <<<"$files" | paste -sd ';' -)" \
      "Answer forensics questions first, then delete what the README doesn't allow: rm 'PATH'"
  else
    pass "No media files found under /home$note."
  fi
}

perm_ok() { # FILE MAX_OCTAL_MODE -> true if no bits beyond the mask are set
  local mode; mode=$(stat -c '%a' "$1" 2>/dev/null) || return 1
  (( (8#$mode & ~8#$2) == 0 ))
}

chk_shadow_perms() {
  local f=/etc/shadow owner group mode
  [ -e "$f" ] || { skip "/etc/shadow not found."; return; }
  read -r mode owner group < <(stat -c '%a %U %G' "$f")
  if [ "$owner" = root ] && { [ "$group" = shadow ] || [ "$group" = root ]; } && perm_ok "$f" 640; then
    pass "/etc/shadow is $mode $owner:$group."
  else
    fail "/etc/shadow is $mode $owner:$group." "chown root:shadow /etc/shadow && chmod 640 /etc/shadow"
  fi
}

chk_passwd_perms() {
  local f bad="" mode owner group
  for f in /etc/passwd /etc/group; do
    read -r mode owner group < <(stat -c '%a %U %G' "$f")
    if [ "$owner" != root ] || ! perm_ok "$f" 644; then bad+="$f is $mode $owner:$group; "; fi
  done
  if [ -n "$bad" ]; then
    fail "${bad%; }" "chown root:root /etc/passwd /etc/group && chmod 644 /etc/passwd /etc/group"
  else
    pass "/etc/passwd and /etc/group are root-owned and 644 or stricter."
  fi
}

chk_world_writable_etc() {
  local files
  files=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 20)
  if [ -n "$files" ]; then
    fail "World-writable files in /etc: $(paste -sd ' ' - <<<"$files")" "chmod o-w FILE"
  else
    pass "No world-writable files in /etc."
  fi
}

# ---------------------------------------------------------------------------------------
# Network and persistence

SS_OUT=""
listening() {
  if [ -z "$SS_OUT" ] && command -v ss >/dev/null 2>&1; then
    SS_OUT=$(ss -H -tulpn 2>/dev/null || true)
  fi
  echo "$SS_OUT"
}

chk_listening() {
  command -v ss >/dev/null 2>&1 || { skip "ss is not available."; return; }
  local summary
  summary=$(listening | awk '{
      proc=""; if (match($0, /users:\(\("[^"]+"/)) { proc=substr($0, RSTART+9, RLENGTH-10) }
      printf "%s %s%s\n", $1, $5, (proc=="" ? "" : " (" proc ")")
    }' | sort -u | paste -sd ';' -)
  if [ -n "$summary" ]; then
    info "Listening: ${summary//;/; }" "Stop anything the README doesn't need: systemctl disable --now SERVICE"
  else
    info "Nothing is listening on TCP/UDP."
  fi
}

chk_netcat_listeners() {
  command -v ss >/dev/null 2>&1 || { skip "ss is not available."; return; }
  need_root || return
  local name hits
  hits=$(for name in "${NETCAT_NAMES[@]}"; do
      listening | grep -F "((\"$name\"," | awk -v n="$name" '{print $1" "$5" ("n")"}'
    done | paste -sd ';' -)
  if [ -n "$hits" ]; then
    fail "netcat/socat is listening: $hits. This is a common backdoor." \
      "Find what starts it (crontab -l, /etc/cron*, systemd units, rc.local), remove that, then kill the process."
  else
    pass "No netcat or socat listeners."
  fi
}

chk_hosts() {
  local extra
  extra=$(grep -vE '^\s*(#|$)' /etc/hosts 2>/dev/null \
    | grep -vE '^\s*(127\.0\.0\.1|127\.0\.1\.1|::1|fe00::0|ff00::0|ff02::[0-9])\s' \
    | paste -sd ';' -)
  if [ -n "$extra" ]; then
    warn "Extra /etc/hosts entries: $extra" "Remove entries the README doesn't explain from /etc/hosts"
  else
    pass "/etc/hosts has only default entries."
  fi
}

chk_cron() {
  local items=() f
  for f in /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
      e2scrub_all|popularity-contest|anacron|sysstat|.placeholder|php) continue ;;
    esac
    items+=("$f")
  done
  if grep -qvE '^\s*(#|$|SHELL=|PATH=|[0-9*].*(run-parts|test -x /usr/sbin/anacron))' /etc/crontab 2>/dev/null; then
    items+=("/etc/crontab (non-default lines)")
  fi
  if [ "${#items[@]}" -gt 0 ]; then
    info "Review these cron entries for persistence: $(join_csv "${items[@]}")" \
      "crontab -l -u USER ; crontab -r -u USER to remove a user's crontab"
  else
    info "No custom cron jobs found."
  fi
}

chk_apt_sources() {
  local f lines=""
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -r "$f" ] || continue
    lines+=$(grep -hE '^\s*deb(-src)?\s' "$f" | grep -oE '(https?|ftp)://[^ ]+')$'\n'
  done
  for f in /etc/apt/sources.list.d/*.sources; do
    [ -r "$f" ] || continue
    lines+=$(sed -n -E 's/^URIs:\s*//p' "$f" | tr ' ' '\n')$'\n'
  done
  local odd
  odd=$(grep -v '^$' <<<"$lines" | grep -vE '://([a-z0-9-]+\.)?(archive|security|ports)\.ubuntu\.com|://deb\.debian\.org|://security\.debian\.org|://packages\.linuxmint\.com|://([a-z0-9-]+\.)?mirrors?\.' \
    | sort -u | paste -sd ' ' -)
  if [ -n "$odd" ]; then
    info "Non-default APT sources: $odd" "Remove sources the README doesn't need from /etc/apt/sources.list(.d)"
  else
    info "APT sources point at the distribution's own repositories."
  fi
}

# ---------------------------------------------------------------------------------------
# Run

for entry in "${CHECKS[@]}"; do
  IFS='|' read -r CURRENT_ID CURRENT_CAT _ fn <<<"$entry"
  "$fn"
done

if [ "$COLOR" -eq 1 ]; then
  C_PASS=$'\e[32m'; C_FAIL=$'\e[31m'; C_WARN=$'\e[33m'; C_INFO=$'\e[36m'; C_SKIP=$'\e[90m'
  C_DIM=$'\e[2m'; C_OFF=$'\e[0m'
else
  C_PASS=""; C_FAIL=""; C_WARN=""; C_INFO=""; C_SKIP=""; C_DIM=""; C_OFF=""
fi

declare -A COUNT=([PASS]=0 [FAIL]=0 [WARN]=0 [INFO]=0 [SKIP]=0)
echo "CSSR Linux audit ${CSSR_AUDIT_VERSION} - $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown OS}") - $(hostname)"
[ "$IS_ROOT" -eq 1 ] || echo "Not running as root: some checks are skipped. Re-run with sudo."
echo "This script only reads; it changes nothing."
echo
for i in "${!R_ID[@]}"; do
  s=${R_STATUS[$i]}
  COUNT[$s]=$((COUNT[$s] + 1))
  case "$s" in
    PASS) c=$C_PASS ;; FAIL) c=$C_FAIL ;; WARN) c=$C_WARN ;; INFO) c=$C_INFO ;; *) c=$C_SKIP ;;
  esac
  printf '%s[%s]%s %-11s %s\n' "$c" "$s" "$C_OFF" "${R_ID[$i]}" "${R_MSG[$i]}"
  if [ -n "${R_FIX[$i]}" ] && [ "$s" != PASS ]; then
    printf '       %sfix: %s%s\n' "$C_DIM" "${R_FIX[$i]}" "$C_OFF"
  fi
done
echo
echo "Summary: ${COUNT[FAIL]} FAIL, ${COUNT[WARN]} WARN, ${COUNT[PASS]} PASS, ${COUNT[INFO]} INFO, ${COUNT[SKIP]} SKIP"

json_escape() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  printf '%s' "$s"
}

if [ -n "$JSON_FILE" ]; then
  {
    printf '{\n  "tool": "cssr-audit",\n  "version": "%s",\n' "$CSSR_AUDIT_VERSION"
    printf '  "os": "%s",\n' "$(json_escape "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")")"
    printf '  "host": "%s",\n  "root": %s,\n' "$(json_escape "$(hostname)")" \
      "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
    printf '  "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "summary": {"FAIL": %d, "WARN": %d, "PASS": %d, "INFO": %d, "SKIP": %d},\n' \
      "${COUNT[FAIL]}" "${COUNT[WARN]}" "${COUNT[PASS]}" "${COUNT[INFO]}" "${COUNT[SKIP]}"
    printf '  "results": [\n'
    last=$((${#R_ID[@]} - 1))
    for i in "${!R_ID[@]}"; do
      printf '    {"id": "%s", "category": "%s", "status": "%s", "message": "%s", "fix": "%s"}%s\n' \
        "${R_ID[$i]}" "${R_CAT[$i]}" "${R_STATUS[$i]}" "$(json_escape "${R_MSG[$i]}")" \
        "$(json_escape "${R_FIX[$i]}")" "$([ "$i" -lt "$last" ] && echo ,)"
    done
    printf '  ]\n}\n'
  } >"$JSON_FILE"
  echo "JSON report written to $JSON_FILE"
fi

[ "${COUNT[FAIL]}" -eq 0 ]
exit $?
