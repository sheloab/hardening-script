#!/usr/bin/env bash
# =============================================================================
#  LINUX SERVER HARDENING SCRIPT
#  Compatible: Debian 12/13, Ubuntu 20.04+, systemd-based distros
#  Author   : Generated for My_S3rv3R Server
#  Version  : 3.1 - Fixed UFW/iptables-persistent conflict
#              All custom rules use UFW hook files (before.rules/after.rules)
#              iptables-persistent is NOT used (conflicts with UFW)
#
#  USAGE    : sudo bash hardening.sh
# =============================================================================

set -uo pipefail

# =============================================================================
#                        USER CONFIGURATION SECTION
# =============================================================================

NEW_USER="guest"
NEW_USER_HOME="/home/guest"
NEW_USER_SHELL="/bin/bash"
NEW_USER_PASSWORD="CHANGE_ME_STRONG_PASSWORD"   # TODO: set a new password, never reuse the old one
NEW_HOSTNAME="CHANGE_ME_HOSTNAME"                # TODO: new server's hostname
ALERT_EMAIL="CHANGE_ME_ALERT_EMAIL"              # TODO: notification email

# Public key to install for NEW_USER (contents of an id_ed25519.pub / id_rsa.pub).
# If set, SSH password authentication is disabled and key-only login is enforced.
# If left empty, password authentication stays enabled (weaker, but you won't be
# locked out if you don't have a key ready yet).
NEW_USER_SSH_PUBKEY=""

# ONLY these IPs can SSH in — all others are blocked by UFW
# ⚠️  ENSURE YOUR CURRENT IP IS HERE OR YOU WILL BE LOCKED OUT
SSH_ALLOWED_IPS="CHANGE_ME_YOUR_CURRENT_IP"      # TODO: your actual admin IP, or you'll be locked out

# IPs that Fail2Ban will never ban
TRUSTED_IPS="${SSH_ALLOWED_IPS}"

TIMEZONE="Asia/Jakarta"
SSH_PORT="22"
HARDENING_LOG="/var/log/hardening_script.log"
TRAFFIC_LOG="/var/log/iptables_traffic.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
SYSLOG_MAX_SIZE="500M"
LOG_ROTATE_DAYS="90"
NTP_SERVERS="0.id.pool.ntp.org 1.id.pool.ntp.org time.google.com time.cloudflare.com"

# =============================================================================
#                     END OF USER CONFIGURATION SECTION
# =============================================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Step tracking ---
declare -A STEP_STATUS
STEP_NAMES=()

# =============================================================================
#  CORE FUNCTIONS
# =============================================================================

ts() { date '+%Y-%m-%d %H:%M:%S.%3N %Z'; }

log() {
    local level="$1"; shift
    local msg="$*"
    echo -e "[$(ts)] [${level}] ${msg}" \
        | sed 's/\x1b\[[0-9;]*m//g' >> "${HARDENING_LOG}"
    case "${level}" in
        INFO)   echo -e "${GREEN}[INFO]${NC}   ${msg}" ;;
        WARN)   echo -e "${YELLOW}[WARN]${NC}   ${msg}" ;;
        ERROR)  echo -e "${RED}[ERROR]${NC}  ${msg}" ;;
        STEP)
            echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${CYAN}${BOLD}  ${msg}${NC}"
            echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            ;;
        CHANGE) echo -e "${YELLOW}[CHANGE]${NC} ${msg}" ;;
        *)      echo -e "${msg}" ;;
    esac
}

log_change() {
    log CHANGE "Parameter : ${BOLD}${1}${NC}"
    log CHANGE "  BEFORE  : ${RED}${2}${NC}"
    log CHANGE "  AFTER   : ${GREEN}${3}${NC}"
    echo "[$(ts)] [CHANGE] ${1} | BEFORE: ${2} | AFTER: ${3}" >> "${HARDENING_LOG}"
}

step_ok() {
    STEP_STATUS["${1}"]="OK"
    STEP_NAMES+=("${1}:${2}")
    log INFO "✅ STEP ${1} COMPLETED: ${2}"
}

step_fail() {
    STEP_STATUS["${1}"]="FAIL"
    STEP_NAMES+=("${1}:${2}")
    log ERROR "❌ STEP ${1} FAILED: ${2} — ${3:-Unknown error}"
}

install_package() {
    local pkg="$1"
    local max=3
    local attempt=1

    if dpkg -s "${pkg}" &>/dev/null 2>&1 \
        && dpkg -s "${pkg}" 2>/dev/null | grep -q "^Status:.*installed"; then
        log INFO "Package '${pkg}' already installed — skipping"
        return 0
    fi

    log INFO "Installing: ${pkg}"
    while (( attempt <= max )); do
        if DEBIAN_FRONTEND=noninteractive apt-get install -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            "${pkg}" >> "${HARDENING_LOG}" 2>&1; then
            log INFO "✅ Installed '${pkg}'"
            return 0
        fi
        log WARN "Attempt ${attempt}/${max} failed for '${pkg}'"
        (( attempt < max )) && { sleep 5
            DEBIAN_FRONTEND=noninteractive apt-get update -y \
                >> "${HARDENING_LOG}" 2>&1 || true; }
        (( attempt++ ))
    done

    log ERROR "Failed to install '${pkg}' after ${max} attempts"
    return 1
}

# =============================================================================
#  PRE-FLIGHT CHECKS
# =============================================================================

preflight_checks() {
    log STEP "PRE-FLIGHT CHECKS"

    [[ "${EUID}" -ne 0 ]] && {
        echo -e "${RED}[FATAL]${NC} Must run as root: sudo bash $0"
        exit 1
    }

    local abort=0
    [[ -z "${NEW_USER_PASSWORD}" ]] && {
        echo -e "${RED}[FATAL]${NC} NEW_USER_PASSWORD not set"; abort=1; }
    [[ -z "${ALERT_EMAIL}" ]] && {
        echo -e "${RED}[FATAL]${NC} ALERT_EMAIL not set"; abort=1; }
    [[ -z "${SSH_ALLOWED_IPS}" ]] && {
        echo -e "${RED}[FATAL]${NC} SSH_ALLOWED_IPS is empty — you will be locked out!"; abort=1; }

    # Refuse to run with unedited CHANGE_ME_* placeholders. If SSH_ALLOWED_IPS
    # is left as the placeholder, ufw's "allow from CHANGE_ME_..." rule fails
    # silently (bad source address) while the firewall still enables with
    # default-deny incoming — total SSH lockout, not just an unwhitelisted IP.
    for var_name in NEW_USER_PASSWORD NEW_HOSTNAME ALERT_EMAIL SSH_ALLOWED_IPS; do
        if [[ "${!var_name}" == *CHANGE_ME* ]]; then
            echo -e "${RED}[FATAL]${NC} ${var_name} still contains the placeholder value '${!var_name}' — edit it before running"
            abort=1
        fi
    done
    [[ ${abort} -eq 1 ]] && exit 1

    # --- Warn about SSH whitelist ---
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  ⚠️  SSH WHITELIST — Only these IPs can SSH after this runs:${NC}"
    for ip in ${SSH_ALLOWED_IPS}; do
        echo -e "${YELLOW}    → ${ip}${NC}"
    done
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # --- Lockout detection ---
    local current_ip="${SSH_CLIENT:-}"
    current_ip="${current_ip%% *}"
    if [[ -n "${current_ip}" ]]; then
        local found=0
        for ip in ${SSH_ALLOWED_IPS}; do
            [[ "${ip}" == "${current_ip}" ]] && { found=1; break; }
        done
        if [[ ${found} -eq 0 ]]; then
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${RED}  ⛔ LOCKOUT RISK: Your IP ${current_ip} is NOT whitelisted!${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -n "Type IUNDERSTAND to continue anyway (Ctrl+C to abort): "
            read -r confirm
            [[ "${confirm}" != "IUNDERSTAND" ]] && { echo "Aborted."; exit 1; }
        else
            log INFO "✅ Current SSH IP (${current_ip}) is whitelisted — safe"
        fi
    fi

    # --- Countdown ---
    echo ""
    for i in {10..1}; do
        echo -ne "${CYAN}  Starting in ${i}... (Ctrl+C to abort)${NC}\r"
        sleep 1
    done
    echo ""

    # --- Setup log ---
    mkdir -p "$(dirname "${HARDENING_LOG}")"
    touch "${HARDENING_LOG}"
    chmod 640 "${HARDENING_LOG}"

    # --- Check for conflicting packages and REMOVE them ---
    # iptables-persistent conflicts with UFW — remove it if present
    if dpkg -s iptables-persistent &>/dev/null 2>&1; then
        log WARN "iptables-persistent detected — removing (conflicts with UFW)"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y \
            iptables-persistent netfilter-persistent \
            >> "${HARDENING_LOG}" 2>&1 || true
        log_change "iptables-persistent" "INSTALLED (conflicts with UFW)" "REMOVED"
    fi

    {
        echo "============================================================"
        echo "  HARDENING SCRIPT v3.1 SESSION START"
        echo "  Timestamp   : $(ts)"
        echo "  PID         : $$"
        echo "  OS          : $(grep PRETTY_NAME /etc/os-release 2>/dev/null \
                                | cut -d= -f2 | tr -d '"')"
        echo "  Kernel      : $(uname -r)"
        echo "  SSH IPs     : ${SSH_ALLOWED_IPS}"
        echo "  New User    : ${NEW_USER}"
        echo "  New Hostname: ${NEW_HOSTNAME}"
        echo "  SSH Port    : ${SSH_PORT}"
        echo "============================================================"
    } >> "${HARDENING_LOG}"

    log INFO "Pre-flight checks passed ✅"
}

# =============================================================================
#  STEP 01: SET TIMEZONE
# =============================================================================

step_timezone() {
    log STEP "STEP 01: SET TIMEZONE → ${TIMEZONE}"
    local before
    before=$(timedatectl show --property=Timezone --value 2>/dev/null \
             || cat /etc/timezone 2>/dev/null || echo "unknown")

    if timedatectl set-timezone "${TIMEZONE}" >> "${HARDENING_LOG}" 2>&1; then
        local after
        after=$(timedatectl show --property=Timezone --value 2>/dev/null \
                || echo "${TIMEZONE}")
        log_change "Timezone" "${before}" "${after}"
        step_ok "01" "Set Timezone to ${TIMEZONE}"
    else
        step_fail "01" "Set Timezone" "timedatectl failed"
    fi
}

# =============================================================================
#  STEP 02: APT UPDATE
# =============================================================================

step_apt_update() {
    log STEP "STEP 02: APT UPDATE"
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a >> "${HARDENING_LOG}" 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get -f install -y >> "${HARDENING_LOG}" 2>&1 || true

    if DEBIAN_FRONTEND=noninteractive apt-get update -y >> "${HARDENING_LOG}" 2>&1; then
        step_ok "02" "apt-get update"
    else
        step_fail "02" "apt-get update" "Non-zero exit code"
    fi
}

# =============================================================================
#  STEP 03: APT UPGRADE
# =============================================================================

step_apt_upgrade() {
    log STEP "STEP 03: APT UPGRADE"
    if DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" >> "${HARDENING_LOG}" 2>&1; then
        step_ok "03" "apt-get upgrade"
    else
        step_fail "03" "apt-get upgrade" "Non-zero exit code"
    fi
}

# =============================================================================
#  STEP 04: INSTALL TOOLS
# =============================================================================

step_install_tools() {
    log STEP "STEP 04: INSTALL DIAGNOSTIC TOOLS"
    local tools=("nmap" "telnet" "curl" "wget" "net-tools" "bind9-dnsutils"
                 "lsof" "htop" "unzip" "tcpdump")
    for tool in "${tools[@]}"; do
        install_package "${tool}" || log WARN "Non-critical: '${tool}' failed — continuing"
    done
    step_ok "04" "Install tools (nmap, telnet, curl, wget, net-tools, etc.)"
}

# =============================================================================
#  STEP 05: CREATE USER + SUDO
# =============================================================================

step_create_user() {
    log STEP "STEP 05: CREATE USER '${NEW_USER}' + SUDO"
    local failed=0

    install_package "sudo" || {
        step_fail "05" "Create user" "sudo package unavailable"
        return
    }

    if id "${NEW_USER}" &>/dev/null; then
        log WARN "User '${NEW_USER}' exists — updating password"
        echo "${NEW_USER}:${NEW_USER_PASSWORD}" | chpasswd >> "${HARDENING_LOG}" 2>&1 \
            || failed=1
    else
        useradd --create-home \
                --home-dir  "${NEW_USER_HOME}" \
                --shell     "${NEW_USER_SHELL}" \
                --comment   "Hardening Admin User" \
                "${NEW_USER}" >> "${HARDENING_LOG}" 2>&1 || failed=1
        echo "${NEW_USER}:${NEW_USER_PASSWORD}" | chpasswd >> "${HARDENING_LOG}" 2>&1 \
            || failed=1
        log_change "User" "(none)" "${NEW_USER}"
    fi

    usermod -aG sudo "${NEW_USER}" >> "${HARDENING_LOG}" 2>&1 || failed=1

    local sudoers_file="/etc/sudoers.d/${NEW_USER}"
    if [[ ! -f "${sudoers_file}" ]]; then
        echo "${NEW_USER} ALL=(ALL:ALL) ALL" > "${sudoers_file}"
        chmod 440 "${sudoers_file}"
    fi

    # --- Install SSH public key if provided (enables key-only login later) ---
    if [[ -n "${NEW_USER_SSH_PUBKEY}" ]]; then
        local ssh_dir="${NEW_USER_HOME}/.ssh"
        mkdir -p "${ssh_dir}"
        echo "${NEW_USER_SSH_PUBKEY}" >> "${ssh_dir}/authorized_keys"
        sort -u -o "${ssh_dir}/authorized_keys" "${ssh_dir}/authorized_keys"
        chmod 700 "${ssh_dir}"
        chmod 600 "${ssh_dir}/authorized_keys"
        chown -R "${NEW_USER}:${NEW_USER}" "${ssh_dir}"
        log_change "SSH key" "(none)" "installed for ${NEW_USER}"
    else
        log WARN "NEW_USER_SSH_PUBKEY not set — SSH password authentication will stay enabled"
    fi

    [[ ${failed} -eq 0 ]] \
        && step_ok   "05" "Create user '${NEW_USER}' + sudo" \
        || step_fail "05" "Create user '${NEW_USER}'" "One or more sub-steps failed"
}

# =============================================================================
#  STEP 06: SSH BANNER
# =============================================================================

step_ssh_banner() {
    log STEP "STEP 06: SSH LOGIN BANNER"
    local banner_file="/etc/ssh/banner_sshd.txt"

    cat > "${banner_file}" << 'BANNER_EOF'

***************************************************************************
                            RESTRICTED ACCESS
  This system is for authorized users only. All activities on this system
  are monitored and recorded. Unauthorized access is strictly prohibited
  and will be fully investigated and reported to law enforcement.

  IF YOU ARE NOT AN AUTHORIZED USER, DISCONNECT IMMEDIATELY!
***************************************************************************
             WELCOME TO My_S3rv3R, SPEAK FRIEND AND ENTER.......
***************************************************************************

BANNER_EOF

    chmod 644 "${banner_file}"
    step_ok "06" "SSH banner created"
}

# =============================================================================
#  STEP 07: HARDEN SSH
# =============================================================================

step_harden_ssh() {
    log STEP "STEP 07: HARDEN SSH CONFIGURATION"
    local sshd_config="/etc/ssh/sshd_config"

    [[ ! -f "${sshd_config}" ]] && {
        step_fail "07" "Harden SSH" "sshd_config not found"
        return
    }

    local backup="${sshd_config}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${sshd_config}" "${backup}"
    log INFO "Backup: ${backup}"

    set_sshd_param() {
        local key="$1" value="$2"
        sed -i -E "/^[[:space:]]*#*[[:space:]]*${key}[[:space:]]/d" "${sshd_config}"
        echo "${key} ${value}" >> "${sshd_config}"
        log INFO "sshd: ${key} = ${value}"
    }

    # Only disable password auth if we actually installed a key for NEW_USER —
    # otherwise disabling it here would lock everyone out with no way back in.
    local password_auth="yes"
    if [[ -n "${NEW_USER_SSH_PUBKEY}" ]] \
        && [[ -s "${NEW_USER_HOME}/.ssh/authorized_keys" ]]; then
        password_auth="no"
        log INFO "SSH key confirmed for ${NEW_USER} — disabling password authentication"
    else
        log WARN "No SSH key installed for ${NEW_USER} — leaving PasswordAuthentication yes"
    fi

    set_sshd_param "Port"                            "${SSH_PORT}"
    set_sshd_param "AddressFamily"                   "inet"
    set_sshd_param "ListenAddress"                   "0.0.0.0"
    set_sshd_param "PermitRootLogin"                 "no"
    set_sshd_param "MaxAuthTries"                    "5"
    set_sshd_param "MaxSessions"                     "5"
    set_sshd_param "LoginGraceTime"                  "30"
    set_sshd_param "PermitEmptyPasswords"            "no"
    set_sshd_param "PasswordAuthentication"          "${password_auth}"
    set_sshd_param "PubkeyAuthentication"            "yes"
    set_sshd_param "ChallengeResponseAuthentication" "no"
    set_sshd_param "UsePAM"                          "yes"
    set_sshd_param "X11Forwarding"                   "no"
    set_sshd_param "AllowAgentForwarding"            "no"
    set_sshd_param "AllowTcpForwarding"              "no"
    set_sshd_param "GatewayPorts"                    "no"
    set_sshd_param "PermitTunnel"                    "no"
    set_sshd_param "ClientAliveInterval"             "300"
    set_sshd_param "ClientAliveCountMax"             "2"
    set_sshd_param "LogLevel"                        "VERBOSE"
    set_sshd_param "SyslogFacility"                  "AUTH"
    set_sshd_param "PrintLastLog"                    "yes"
    set_sshd_param "Banner"                          "/etc/ssh/banner_sshd.txt"
    set_sshd_param "Compression"                     "no"
    set_sshd_param "TCPKeepAlive"                    "yes"
    set_sshd_param "AllowUsers"                      "${NEW_USER}"

    if sshd -t >> "${HARDENING_LOG}" 2>&1; then
        log INFO "sshd config validation: PASSED ✅"
        systemctl restart ssh  >> "${HARDENING_LOG}" 2>&1 \
            || systemctl restart sshd >> "${HARDENING_LOG}" 2>&1
        step_ok "07" "SSH hardened (AllowUsers: ${NEW_USER})"
    else
        log ERROR "sshd -t FAILED — restoring backup"
        cp "${backup}" "${sshd_config}"
        step_fail "07" "Harden SSH" "Validation failed — backup restored"
    fi
}

# =============================================================================
#  STEP 08: HOSTNAME
# =============================================================================

step_hostname() {
    log STEP "STEP 08: CHANGE HOSTNAME → '${NEW_HOSTNAME}'"
    local before; before=$(hostname)

    if hostnamectl set-hostname "${NEW_HOSTNAME}" >> "${HARDENING_LOG}" 2>&1; then
        if grep -q "127.0.1.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t${NEW_HOSTNAME}/" /etc/hosts
        else
            echo -e "127.0.1.1\t${NEW_HOSTNAME}" >> /etc/hosts
        fi
        log_change "Hostname" "${before}" "${NEW_HOSTNAME}"
        step_ok "08" "Hostname → '${NEW_HOSTNAME}'"
    else
        step_fail "08" "Hostname" "hostnamectl failed"
    fi
}

# =============================================================================
#  STEP 09: RSYSLOG + LOGROTATE
# =============================================================================

step_rsyslog() {
    log STEP "STEP 09: RSYSLOG + LOGROTATE"
    local failed=0
    install_package "rsyslog"   || failed=1
    install_package "logrotate" || failed=1

    systemctl enable rsyslog >> "${HARDENING_LOG}" 2>&1 || true
    systemctl start  rsyslog >> "${HARDENING_LOG}" 2>&1 || true

    cat > /etc/rsyslog.d/50-hardening.conf << 'RSYSLOG_EOF'
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
daemon.*                        -/var/log/daemon.log
RSYSLOG_EOF

    cat > /etc/logrotate.d/rsyslog << LOGROTATE_EOF
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
/var/log/messages
/var/log/mail.log
/var/log/daemon.log
/var/log/user.log
{
    daily
    rotate ${LOG_ROTATE_DAYS}
    size ${SYSLOG_MAX_SIZE}
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null \
            || systemctl reload rsyslog 2>/dev/null || true
    endscript
}
LOGROTATE_EOF

    systemctl restart rsyslog >> "${HARDENING_LOG}" 2>&1 || true

    [[ ${failed} -eq 0 ]] \
        && step_ok   "09" "rsyslog + logrotate configured" \
        || step_fail "09" "rsyslog/logrotate" "Package install failed"
}

# =============================================================================
#  STEP 10: UFW — COMPLETE FIREWALL WITH CUSTOM CHAINS VIA HOOK FILES
#
#  KEY DESIGN DECISIONS:
#  ─────────────────────
#  1. iptables-persistent is REMOVED (conflicts with UFW)
#  2. Port scan detection rules → /etc/ufw/before.rules  (UFW manages them)
#  3. Traffic logging rules     → /etc/ufw/before.rules  (UFW manages them)
#  4. UFW's before.rules is loaded by UFW itself on every start/restart
#  5. No netfilter-persistent, no iptables-save needed
# =============================================================================

step_ufw() {
    log STEP "STEP 10: UFW FIREWALL + CUSTOM CHAINS (UFW-NATIVE)"

    # --- Install UFW ---
    if ! install_package "ufw"; then
        step_fail "10" "UFW" "Failed to install UFW"
        return
    fi

    # --- Ensure iptables-persistent is NOT installed ---
    if dpkg -s iptables-persistent &>/dev/null 2>&1; then
        log WARN "Removing iptables-persistent (conflicts with UFW)"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y \
            iptables-persistent netfilter-persistent \
            >> "${HARDENING_LOG}" 2>&1 || true
    fi

    # -------------------------------------------------------------------------
    # PHASE 1: Stop and fully disable UFW for clean configuration
    # -------------------------------------------------------------------------
    log INFO "Phase 1: Stopping UFW for clean configuration..."
    ufw --force disable >> "${HARDENING_LOG}" 2>&1 || true
    systemctl stop ufw  >> "${HARDENING_LOG}" 2>&1 || true

    # -------------------------------------------------------------------------
    # PHASE 2: Configure /etc/default/ufw BEFORE reset
    # -------------------------------------------------------------------------
    log INFO "Phase 2: Configuring UFW defaults..."
    local ufw_default="/etc/default/ufw"

    # Disable IPv6 in UFW (prevents ip6tables errors when IPv6 is disabled)
    sed -i 's/^IPV6=.*/IPV6=no/' "${ufw_default}"
    grep -q "^IPV6=" "${ufw_default}" || echo "IPV6=no" >> "${ufw_default}"

    # Set default forward policy to DROP
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' "${ufw_default}"

    log_change "UFW IPv6"          "(unknown)" "no"
    log_change "UFW forward policy" "(unknown)" "DROP"

    # -------------------------------------------------------------------------
    # PHASE 3: Write custom chains into UFW's before.rules
    # These rules are loaded by UFW itself — no iptables-persistent needed
    # -------------------------------------------------------------------------
    log INFO "Phase 3: Writing custom chains to /etc/ufw/before.rules..."

    # Backup existing before.rules
    local before_rules="/etc/ufw/before.rules"
    cp "${before_rules}" "${before_rules}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    cat > "${before_rules}" << BEFORE_RULES_EOF
# =============================================================================
# UFW before.rules — Generated by hardening script v3.1
# Custom chains: PORTSCAN_LOG, TRAFFIC_LOG
# These are managed by UFW — do NOT install iptables-persistent
# =============================================================================

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

# =============================================================================
# CUSTOM CHAIN: PORTSCAN_LOG
# Detects and logs TCP SYN scans and UDP probes
# Rate-limited to avoid log flooding
# =============================================================================
:PORTSCAN_LOG - [0:0]

# --- Port scan detection: log rate-limited SYN packets ---
-A PORTSCAN_LOG -p tcp --syn -m limit --limit 5/s --limit-burst 10 \
    -j LOG --log-prefix "PORTSCAN_TCP: " --log-level 4
-A PORTSCAN_LOG -p udp -m limit --limit 5/s --limit-burst 10 \
    -j LOG --log-prefix "PORTSCAN_UDP: " --log-level 4
-A PORTSCAN_LOG -j RETURN

# --- Jump to PORTSCAN_LOG from INPUT ---
-A ufw-before-input -j PORTSCAN_LOG

# =============================================================================
# CUSTOM CHAIN: TRAFFIC_LOG
# Logs all TCP/UDP/ICMP traffic for forensic purposes
# WARNING: generates large log volume
# =============================================================================
:TRAFFIC_LOG - [0:0]

-A TRAFFIC_LOG -p tcp  -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_TCP: "  --log-level 6
-A TRAFFIC_LOG -p udp  -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_UDP: "  --log-level 6
-A TRAFFIC_LOG -p icmp -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_ICMP: " --log-level 6
-A TRAFFIC_LOG -j RETURN

# --- Jump to TRAFFIC_LOG from INPUT and OUTPUT ---
-A ufw-before-input  -j TRAFFIC_LOG
-A ufw-before-output -j TRAFFIC_LOG

# =============================================================================
# STANDARD UFW before.rules (required — do not remove)
# =============================================================================

# --- Allow loopback ---
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# --- Drop invalid packets ---
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# --- Allow established/related connections ---
-A ufw-before-input  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# --- Allow ICMP (ping) ---
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# --- DHCP client ---
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

# --- UFW not-local chain ---
-A ufw-before-input -j ufw-not-local
-A ufw-not-local -m addrtype --dst-type LOCAL  -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 \
    -j LOG --log-prefix "[UFW] Non-local: " --log-level 7
-A ufw-not-local -j DROP

COMMIT
BEFORE_RULES_EOF

    log INFO "Custom chains written to ${before_rules} ✅"
    log_change "UFW before.rules" "(default)" "PORTSCAN_LOG + TRAFFIC_LOG chains added"

    # -------------------------------------------------------------------------
    # PHASE 4: Write after.rules (UFW logging hook)
    # -------------------------------------------------------------------------
    log INFO "Phase 4: Writing /etc/ufw/after.rules..."
    local after_rules="/etc/ufw/after.rules"
    cp "${after_rules}" "${after_rules}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    cat > "${after_rules}" << 'AFTER_RULES_EOF'
# =============================================================================
# UFW after.rules — Generated by hardening script v3.1
# =============================================================================

*filter
:ufw-after-input - [0:0]
:ufw-after-output - [0:0]
:ufw-after-forward - [0:0]
:ufw-after-logging-input - [0:0]
:ufw-after-logging-output - [0:0]
:ufw-after-logging-forward - [0:0]

# --- Suppress noisy UFW block logs for broadcast/multicast ---
-A ufw-after-logging-input -m limit --limit 3/min --limit-burst 10 \
    -j LOG --log-prefix "[UFW BLOCK] " --log-level 4
-A ufw-after-logging-forward -m limit --limit 3/min --limit-burst 10 \
    -j LOG --log-prefix "[UFW BLOCK] " --log-level 4

COMMIT
AFTER_RULES_EOF

    # -------------------------------------------------------------------------
    # PHASE 5: Reset UFW (clean slate) AFTER writing hook files
    # -------------------------------------------------------------------------
    log INFO "Phase 5: Resetting UFW (clean slate)..."
    ufw --force reset >> "${HARDENING_LOG}" 2>&1 || true

    # Restore our custom before.rules (reset overwrites it)
    cat > "${before_rules}" << BEFORE_RULES_RESTORE_EOF
# =============================================================================
# UFW before.rules — Generated by hardening script v3.1
# Restored after ufw --force reset
# =============================================================================

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

# Custom chain: PORTSCAN_LOG
:PORTSCAN_LOG - [0:0]
-A PORTSCAN_LOG -p tcp --syn -m limit --limit 5/s --limit-burst 10 \
    -j LOG --log-prefix "PORTSCAN_TCP: " --log-level 4
-A PORTSCAN_LOG -p udp -m limit --limit 5/s --limit-burst 10 \
    -j LOG --log-prefix "PORTSCAN_UDP: " --log-level 4
-A PORTSCAN_LOG -j RETURN
-A ufw-before-input -j PORTSCAN_LOG

# Custom chain: TRAFFIC_LOG
:TRAFFIC_LOG - [0:0]
-A TRAFFIC_LOG -p tcp  -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_TCP: "  --log-level 6
-A TRAFFIC_LOG -p udp  -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_UDP: "  --log-level 6
-A TRAFFIC_LOG -p icmp -m limit --limit 20/s --limit-burst 40 \
    -j LOG --log-prefix "TRAFFIC_ICMP: " --log-level 6
-A TRAFFIC_LOG -j RETURN
-A ufw-before-input  -j TRAFFIC_LOG
-A ufw-before-output -j TRAFFIC_LOG

# Standard UFW rules
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP
-A ufw-before-input  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT
-A ufw-before-input -j ufw-not-local
-A ufw-not-local -m addrtype --dst-type LOCAL     -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 \
    -j LOG --log-prefix "[UFW] Non-local: " --log-level 7
-A ufw-not-local -j DROP

COMMIT
BEFORE_RULES_RESTORE_EOF

    # Restore /etc/default/ufw settings (reset overwrites this too)
    sed -i 's/^IPV6=.*/IPV6=no/' "${ufw_default}"
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' "${ufw_default}"

    # -------------------------------------------------------------------------
    # PHASE 6: Set policies and rules
    # -------------------------------------------------------------------------
    log INFO "Phase 6: Setting UFW policies and rules..."

    ufw default deny incoming  >> "${HARDENING_LOG}" 2>&1
    ufw default deny outgoing  >> "${HARDENING_LOG}" 2>&1
    ufw default deny forward   >> "${HARDENING_LOG}" 2>&1

    # --- Essential outgoing (server needs these to function) ---
    ufw allow out 53/tcp  comment "DNS"         >> "${HARDENING_LOG}" 2>&1
    ufw allow out 53/udp  comment "DNS"         >> "${HARDENING_LOG}" 2>&1
    ufw allow out 80/tcp  comment "HTTP"        >> "${HARDENING_LOG}" 2>&1
    ufw allow out 443/tcp comment "HTTPS"       >> "${HARDENING_LOG}" 2>&1
    ufw allow out 123/udp comment "NTP"         >> "${HARDENING_LOG}" 2>&1
    ufw allow out 25/tcp  comment "SMTP"        >> "${HARDENING_LOG}" 2>&1
    ufw allow out 587/tcp comment "SMTP-TLS"    >> "${HARDENING_LOG}" 2>&1

    log INFO "Essential outgoing rules: DNS, HTTP, HTTPS, NTP, SMTP"

    # --- SSH whitelist: ONLY whitelisted IPs can SSH ---
    log INFO "Applying SSH whitelist rules..."
    for ip in ${SSH_ALLOWED_IPS}; do
        log INFO "  Whitelisting SSH from: ${ip}"

        # Allow SSH from this IP
        ufw allow from "${ip}" to any port "${SSH_PORT}" proto tcp \
            comment "SSH-whitelist: ${ip}" >> "${HARDENING_LOG}" 2>&1

        # Allow all traffic from this trusted IP (management access)
        ufw allow from "${ip}" to any \
            comment "Trusted-IP: ${ip}" >> "${HARDENING_LOG}" 2>&1

        # Allow outgoing back to this IP
        ufw allow out to "${ip}" \
            comment "Trusted-IP-out: ${ip}" >> "${HARDENING_LOG}" 2>&1

        log_change "UFW SSH rule" "(none)" \
            "allow from ${ip} port ${SSH_PORT}/tcp + all traffic"
    done

    # --- Enable UFW logging ---
    ufw logging full >> "${HARDENING_LOG}" 2>&1

    # -------------------------------------------------------------------------
    # PHASE 7: Enable UFW
    # -------------------------------------------------------------------------
    log INFO "Phase 7: Enabling UFW..."
    if ufw --force enable >> "${HARDENING_LOG}" 2>&1; then
        log INFO "✅ UFW enabled"
    else
        log ERROR "❌ UFW enable failed"
        step_fail "10" "UFW" "ufw --force enable failed"
        return
    fi

    # -------------------------------------------------------------------------
    # PHASE 8: Verify
    # -------------------------------------------------------------------------
    sleep 2
    if ufw status | grep -q "Status: active"; then
        log INFO "✅ UFW status: ACTIVE"
    else
        log ERROR "❌ UFW not active after enable"
        step_fail "10" "UFW" "UFW not active after enable"
        return
    fi

    # Verify custom chains are loaded
    if iptables -L PORTSCAN_LOG -n &>/dev/null 2>&1; then
        log INFO "✅ PORTSCAN_LOG chain: LOADED"
    else
        log WARN "⚠️  PORTSCAN_LOG chain not found in iptables — check before.rules"
    fi

    if iptables -L TRAFFIC_LOG -n &>/dev/null 2>&1; then
        log INFO "✅ TRAFFIC_LOG chain: LOADED"
    else
        log WARN "⚠️  TRAFFIC_LOG chain not found in iptables — check before.rules"
    fi

    log INFO "=== FINAL UFW STATUS ==="
    ufw status verbose 2>&1 | tee -a "${HARDENING_LOG}" | \
        while IFS= read -r line; do log INFO "  ${line}"; done

    log INFO "=== IPTABLES CHAINS ==="
    iptables -L -n --line-numbers 2>&1 | head -60 | tee -a "${HARDENING_LOG}" || true

    step_ok "10" "UFW active — SSH restricted to: ${SSH_ALLOWED_IPS}"
}

# =============================================================================
#  STEP 11: DISABLE IPv6 (AFTER UFW)
# =============================================================================

step_disable_ipv6() {
    log STEP "STEP 11: DISABLE IPv6 (sysctl + GRUB)"

    local before
    before=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")

    cat > /etc/sysctl.d/99-disable-ipv6.conf << 'IPV6_EOF'
net.ipv6.conf.all.disable_ipv6     = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6      = 1
IPV6_EOF

    sysctl -p /etc/sysctl.d/99-disable-ipv6.conf >> "${HARDENING_LOG}" 2>&1 || true

    local after
    after=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")
    log_change "net.ipv6.conf.all.disable_ipv6" "${before}" "${after}"

    if [[ -f /etc/default/grub ]]; then
        if ! grep -q "ipv6.disable=1" /etc/default/grub; then
            # Handle both double- and single-quoted GRUB_CMDLINE_LINUX (varies by cloud provider image)
            sed -i \
                -e 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 ipv6.disable=1"/' \
                -e "s/^GRUB_CMDLINE_LINUX='\(.*\)'/GRUB_CMDLINE_LINUX='\1 ipv6.disable=1'/" \
                /etc/default/grub

            if grep -q "ipv6.disable=1" /etc/default/grub; then
                command -v update-grub &>/dev/null \
                    && update-grub >> "${HARDENING_LOG}" 2>&1 || true
                command -v grub2-mkconfig &>/dev/null \
                    && grub2-mkconfig -o /boot/grub2/grub.cfg >> "${HARDENING_LOG}" 2>&1 || true
                log INFO "GRUB updated: ipv6.disable=1"
            else
                log WARN "Could not find/edit GRUB_CMDLINE_LINUX in /etc/default/grub — IPv6 disable via GRUB was skipped (sysctl disable still applies at runtime; edit /etc/default/grub manually if you need the boot-time flag too)"
            fi
        else
            log INFO "ipv6.disable=1 already in GRUB"
        fi
    fi

    step_ok "11" "IPv6 disabled (sysctl + GRUB)"
}

# =============================================================================
#  STEP 12: KERNEL HARDENING (SYSCTL)
# =============================================================================

step_kernel_hardening() {
    log STEP "STEP 12: KERNEL HARDENING (SYSCTL)"

    cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL_EOF'
# Kernel hardening — hardening script v3.1
kernel.randomize_va_space          = 2
kernel.kptr_restrict               = 2
kernel.dmesg_restrict              = 1
kernel.yama.ptrace_scope           = 1
kernel.panic                       = 60
kernel.panic_on_oops               = 1
kernel.sysrq                       = 0
fs.suid_dumpable                   = 0
fs.protected_hardlinks             = 1
fs.protected_symlinks              = 1
net.ipv4.tcp_syncookies            = 1
net.ipv4.conf.all.rp_filter        = 1
net.ipv4.conf.default.rp_filter    = 1
net.ipv4.ip_forward                = 0
net.ipv4.conf.all.accept_redirects     = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects     = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects       = 0
net.ipv4.conf.default.send_redirects   = 0
net.ipv4.icmp_echo_ignore_broadcasts   = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians         = 1
net.ipv4.conf.default.log_martians     = 1
net.ipv4.conf.all.accept_source_route  = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_max_syn_backlog           = 2048
net.ipv4.tcp_synack_retries            = 2
net.ipv4.tcp_syn_retries               = 5
net.ipv4.tcp_timestamps                = 1
net.ipv4.tcp_tw_reuse                  = 1
net.ipv6.conf.all.disable_ipv6         = 1
net.ipv6.conf.default.disable_ipv6     = 1
net.ipv6.conf.lo.disable_ipv6          = 1
net.ipv6.conf.all.accept_redirects     = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route  = 0
net.ipv6.conf.default.accept_source_route = 0
dev.tty.ldisc_autoload                 = 0
SYSCTL_EOF

    sysctl -p /etc/sysctl.d/99-hardening.conf >> "${HARDENING_LOG}" 2>&1 \
        && step_ok   "12" "Kernel hardening (sysctl) applied" \
        || { log WARN "sysctl -p had warnings (some params may not exist on this kernel)"
             step_ok "12" "Kernel hardening applied (with warnings — see log)"; }
}

# =============================================================================
#  STEP 13: FAIL2BAN
# =============================================================================

step_fail2ban() {
    log STEP "STEP 13: FAIL2BAN"
    local failed=0

    # Remove conflicting MTA
    if dpkg -s exim4 &>/dev/null 2>&1; then
        log WARN "Removing exim4 (conflicts with postfix)"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y \
            exim4 exim4-base exim4-config exim4-daemon-light \
            >> "${HARDENING_LOG}" 2>&1 || true
    fi

    # Pre-seed postfix
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string ${NEW_HOSTNAME}"        | debconf-set-selections

    install_package "fail2ban"         || failed=1
    install_package "python3-systemd"  || failed=1
    install_package "postfix"          || failed=1
    install_package "mailutils"        || failed=1
    install_package "ca-certificates"  || failed=1

    [[ ${failed} -eq 1 ]] && {
        step_fail "13" "Fail2Ban" "Package install failed"
        return
    }

    # Remove Debian default (causes duplicate [sshd])
    rm -f /etc/fail2ban/jail.d/defaults-debian.conf
    log INFO "Removed defaults-debian.conf (prevents duplicate [sshd])"

    # Backup jail.conf
    [[ -f /etc/fail2ban/jail.conf ]] && \
        cp /etc/fail2ban/jail.conf \
           "/etc/fail2ban/jail.conf.bak.$(date +%Y%m%d%H%M%S)"

    # Build ignoreip
    local ignoreip="127.0.0.1/8 ::1"
    for ip in ${TRUSTED_IPS}; do ignoreip="${ignoreip} ${ip}"; done

    # Detect banaction
    local banaction banaction_all
    if command -v nft &>/dev/null && nft list tables &>/dev/null 2>&1; then
        banaction="nftables-multiport"; banaction_all="nftables-allports"
        log INFO "Banaction: nftables"
    else
        banaction="iptables-multiport"; banaction_all="iptables-allports"
        log INFO "Banaction: iptables"
    fi

    # Detect SSH backend
    local backend logpath_line
    if journalctl -u ssh --since "1 minute ago" &>/dev/null 2>&1 || \
       journalctl -u sshd --since "1 minute ago" &>/dev/null 2>&1; then
        backend="systemd"
        logpath_line="# logpath not needed for systemd backend"
    elif [[ -f /var/log/auth.log ]]; then
        backend="auto"
        logpath_line="logpath = /var/log/auth.log"
    else
        backend="systemd"
        logpath_line="# logpath not needed for systemd backend"
    fi
    log INFO "Fail2Ban SSH backend: ${backend}"

    cat > /etc/fail2ban/jail.local << JAIL_EOF
# Fail2Ban jail.local — hardening script v3.1

[DEFAULT]
ignoreip           = ${ignoreip}
bantime            = 7776000
findtime           = 900
maxretry           = 5
backend            = ${backend}
banaction          = ${banaction}
banaction_allports = ${banaction_all}
logtarget          = ${FAIL2BAN_LOG}
destemail          = ${ALERT_EMAIL}
sender             = fail2ban@${NEW_HOSTNAME}
mta                = sendmail
action             = %(action_mwl)s

[sshd]
enabled            = true
port               = ${SSH_PORT}
filter             = sshd
${logpath_line}
backend            = ${backend}
maxretry           = 5
findtime           = 900
bantime            = 7776000
banaction          = ${banaction}
action             = %(action_mwl)s

[recidive]
enabled            = true
logpath            = ${FAIL2BAN_LOG}
banaction          = ${banaction_all}
bantime            = 31536000
findtime           = 86400
maxretry           = 3
action             = %(action_mwl)s

[portscan]
enabled            = true
port               = all
filter             = portscan
logpath            = /var/log/kern.log
                     /var/log/syslog
                     /var/log/portscan.log
maxretry           = 10
findtime           = 60
bantime            = 7776000
ignoreip           = ${ignoreip}
action             = %(action_mwl)s
JAIL_EOF

    # Portscan filter
    cat > /etc/fail2ban/filter.d/portscan.conf << 'FILTER_EOF'
[Definition]
failregex = ^.*PORTSCAN_TCP:.*SRC=<HOST>.*$
            ^.*PORTSCAN_UDP:.*SRC=<HOST>.*$
            ^\s*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
FILTER_EOF

    # Setup log files
    for logfile in "${FAIL2BAN_LOG}" "/var/log/portscan.log"; do
        touch "${logfile}"
        chmod 640 "${logfile}"
        chown root:adm "${logfile}" 2>/dev/null || chown root:root "${logfile}"
    done

    # Logrotate
    cat > /etc/logrotate.d/fail2ban << ROTATE_EOF
${FAIL2BAN_LOG}
/var/log/portscan.log
{
    daily
    rotate ${LOG_ROTATE_DAYS}
    size 100M
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        fail2ban-client flushlogs >/dev/null 2>&1 || true
    endscript
}
ROTATE_EOF

    # Validate
    if ! fail2ban-server -t >> "${HARDENING_LOG}" 2>&1; then
        log ERROR "fail2ban config validation FAILED"
        fail2ban-server -t 2>&1 | tee -a "${HARDENING_LOG}" || true
        failed=1
    else
        log INFO "fail2ban config: VALID ✅"
    fi

    systemctl enable  fail2ban >> "${HARDENING_LOG}" 2>&1 || true
    systemctl restart fail2ban >> "${HARDENING_LOG}" 2>&1 || true
    sleep 3

    if systemctl is-active --quiet fail2ban; then
        log INFO "✅ fail2ban: RUNNING"
        fail2ban-client status 2>&1 | tee -a "${HARDENING_LOG}" || true
    else
        log ERROR "❌ fail2ban failed to start"
        journalctl -u fail2ban --since "2 minutes ago" --no-pager 2>&1 \
            | tee -a "${HARDENING_LOG}" || true
        failed=1
    fi

    # Postfix
    if [[ -f /etc/postfix/main.cf ]]; then
        postconf -e "inet_interfaces = loopback-only" >> "${HARDENING_LOG}" 2>&1
        postconf -e "myhostname = ${NEW_HOSTNAME}"    >> "${HARDENING_LOG}" 2>&1
        postconf -e "inet_protocols = ipv4"           >> "${HARDENING_LOG}" 2>&1
        systemctl restart postfix >> "${HARDENING_LOG}" 2>&1 || true
        log INFO "Postfix: loopback-only, IPv4"
    fi

    # Rsyslog routing for portscan log
    cat > /etc/rsyslog.d/51-portscan.conf << 'RSYSLOG_EOF'
:msg, startswith, "PORTSCAN_TCP:"  -/var/log/portscan.log
:msg, startswith, "PORTSCAN_TCP:"  ~
:msg, startswith, "PORTSCAN_UDP:"  -/var/log/portscan.log
:msg, startswith, "PORTSCAN_UDP:"  ~
RSYSLOG_EOF

    # Rsyslog routing for traffic log
    cat > /etc/rsyslog.d/52-traffic.conf << RSYSLOG_TRAFFIC_EOF
:msg, startswith, "TRAFFIC_TCP:"   -${TRAFFIC_LOG}
:msg, startswith, "TRAFFIC_TCP:"   ~
:msg, startswith, "TRAFFIC_UDP:"   -${TRAFFIC_LOG}
:msg, startswith, "TRAFFIC_UDP:"   ~
:msg, startswith, "TRAFFIC_ICMP:"  -${TRAFFIC_LOG}
:msg, startswith, "TRAFFIC_ICMP:"  ~
RSYSLOG_TRAFFIC_EOF

    touch "${TRAFFIC_LOG}"
    chmod 640 "${TRAFFIC_LOG}"
    chown root:adm "${TRAFFIC_LOG}" 2>/dev/null || chown root:root "${TRAFFIC_LOG}"

    cat > /etc/logrotate.d/iptables-traffic << TRAFFIC_ROTATE_EOF
${TRAFFIC_LOG} {
    daily
    rotate ${LOG_ROTATE_DAYS}
    size 500M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
TRAFFIC_ROTATE_EOF

    systemctl restart rsyslog >> "${HARDENING_LOG}" 2>&1 || true

    [[ ${failed} -eq 0 ]] \
        && step_ok   "13" "Fail2Ban + portscan filter configured" \
        || step_fail "13" "Fail2Ban" "Config or startup failed — check log"
}

# =============================================================================
#  STEP 14: NTP (CHRONY)
# =============================================================================

step_ntp() {
    log STEP "STEP 14: NTP WITH CHRONY"
    local failed=0

    systemctl is-active --quiet systemd-timesyncd 2>/dev/null && {
        systemctl stop    systemd-timesyncd >> "${HARDENING_LOG}" 2>&1 || true
        systemctl disable systemd-timesyncd >> "${HARDENING_LOG}" 2>&1 || true
        log INFO "systemd-timesyncd disabled"
    }

    install_package "chrony" || failed=1
    [[ ${failed} -eq 1 ]] && { step_fail "14" "NTP" "chrony install failed"; return; }

    local chrony_conf="/etc/chrony/chrony.conf"
    [[ ! -f "${chrony_conf}" ]] && chrony_conf="/etc/chrony.conf"
    [[ -f "${chrony_conf}" ]] && \
        cp "${chrony_conf}" "${chrony_conf}.bak.$(date +%Y%m%d%H%M%S)"

    local server_lines=""
    for srv in ${NTP_SERVERS}; do
        server_lines="${server_lines}server ${srv} iburst\n"
    done

    cat > "${chrony_conf}" << CHRONY_EOF
# Chrony config — hardening script v3.1
$(echo -e "${server_lines}")
makestep 1.0 3
driftfile /var/lib/chrony/drift
rtcsync
log tracking measurements statistics
logdir /var/log/chrony
cmdallow 127.0.0.1
cmdport 0
minsources 2
leapsectz right/UTC
user _chrony
CHRONY_EOF

    mkdir -p /var/log/chrony
    chown _chrony:_chrony /var/log/chrony 2>/dev/null || true

    systemctl enable  chrony >> "${HARDENING_LOG}" 2>&1 || true
    systemctl restart chrony >> "${HARDENING_LOG}" 2>&1 || true
    sleep 3
    chronyc tracking >> "${HARDENING_LOG}" 2>&1 || true
    chronyc sources  >> "${HARDENING_LOG}" 2>&1 || true

    step_ok "14" "NTP with chrony configured"
}

# =============================================================================
#  STEP 15: HARDENING LOG FINALIZATION
# =============================================================================

step_log_setup() {
    log STEP "STEP 15: HARDENING LOG FINALIZATION"

    chmod 640 "${HARDENING_LOG}"
    chown root:adm "${HARDENING_LOG}" 2>/dev/null || chown root:root "${HARDENING_LOG}"

    cat > /etc/logrotate.d/hardening << HARDENING_ROTATE_EOF
${HARDENING_LOG} {
    monthly
    rotate 12
    size 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
HARDENING_ROTATE_EOF

    step_ok "15" "Hardening log finalized: ${HARDENING_LOG}"
}

# =============================================================================
#  FINAL SUMMARY
# =============================================================================

print_summary() {
    local div="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local header="
${div}
  HARDENING SCRIPT v3.1 — EXECUTION SUMMARY
  Completed : $(ts)
  Hostname  : $(hostname)
  Log file  : ${HARDENING_LOG}
${div}"

    echo -e "${CYAN}${BOLD}${header}${NC}"
    echo "${header}" >> "${HARDENING_LOG}"

    local ok=0 fail=0
    for entry in "${STEP_NAMES[@]}"; do
        local id="${entry%%:*}" name="${entry#*:}"
        local status="${STEP_STATUS[${id}]:-UNKNOWN}"
        if [[ "${status}" == "OK" ]]; then
            echo -e "  ${GREEN}✅ [OK  ]${NC} Step ${id}: ${name}"
            echo "  [OK  ] Step ${id}: ${name}" >> "${HARDENING_LOG}"
            (( ok++ ))
        else
            echo -e "  ${RED}❌ [FAIL]${NC} Step ${id}: ${name}"
            echo "  [FAIL] Step ${id}: ${name}" >> "${HARDENING_LOG}"
            (( fail++ ))
        fi
    done

    local footer="
${div}
  RESULT: ${ok} PASSED | ${fail} FAILED
${div}

  ⚠️  POST-RUN ACTIONS (DO NOT SKIP):

  1. Open a NEW terminal and verify SSH access BEFORE closing this one:
       ssh -p ${SSH_PORT} ${NEW_USER}@$(hostname -I | awk '{print $1}' 2>/dev/null || echo '<server-ip>')

  2. SSH is ONLY allowed from:
$(for ip in ${SSH_ALLOWED_IPS}; do echo "       → ${ip}"; done)

  3. REBOOT to apply IPv6 disable (GRUB) and all sysctl params:
       sudo reboot

  4. VERIFY AFTER REBOOT:
       ufw status verbose
       iptables -L PORTSCAN_LOG -n     ← must exist (loaded by UFW)
       iptables -L TRAFFIC_LOG -n      ← must exist (loaded by UFW)
       fail2ban-client status
       fail2ban-client status sshd
       chronyc tracking
       sysctl net.ipv6.conf.all.disable_ipv6

  5. NOTE: iptables-persistent was REMOVED (conflicts with UFW)
     Custom iptables chains are now managed via /etc/ufw/before.rules
     They persist across reboots because UFW loads them automatically.

  6. LOGS:
       ${HARDENING_LOG}
       ${FAIL2BAN_LOG}
       ${TRAFFIC_LOG}
       /var/log/portscan.log

${div}"

    echo -e "${CYAN}${BOLD}${footer}${NC}"
    echo "${footer}" >> "${HARDENING_LOG}"
}

# =============================================================================
#  MAIN
# =============================================================================

main() {
    set +e  # Individual steps handle their own errors

    preflight_checks

    step_timezone           # 01
    step_apt_update         # 02
    step_apt_upgrade        # 03
    step_install_tools      # 04
    step_create_user        # 05
    step_ssh_banner         # 06
    step_harden_ssh         # 07
    step_hostname           # 08
    step_rsyslog            # 09
    step_ufw                # 10 ← UFW BEFORE IPv6 disable
    step_disable_ipv6       # 11 ← IPv6 AFTER UFW
    step_kernel_hardening   # 12
    step_fail2ban           # 13 ← includes portscan filter + traffic log rsyslog
    step_ntp                # 14
    step_log_setup          # 15

    print_summary
}

main "$@"