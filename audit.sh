#!/usr/bin/env bash

set -u

# Re-exec as root if needed
if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

# Args
FAST=0
for arg in "$@"; do
    case "$arg" in
        --fast) FAST=1 ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $arg" >&2; exit 1 ;;
    esac
done

# Colors (only if stdout is a terminal)
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' DIM='' BOLD='' NC=''
fi

# Output helpers
section() {
    echo
    echo -e "${CYAN}${BOLD}═══ $1 ═══${NC}"
    [[ -n "${2:-}" ]] && echo -e "${DIM}Look for: $2${NC}"
    echo
}
show_cmd() { echo -e "${DIM}\$ $*${NC}"; }
ok()       { echo -e "${GREEN}✓ $*${NC}"; }
flag()     { echo -e "${YELLOW}⚠ $*${NC}"; }
alert()    { echo -e "${RED}✗ $*${NC}"; }
info()     { echo -e "  $*"; }

# Print command, then run it. Output passes through. Never fatal.
run() {
    show_cmd "$*"
    eval "$*" 2>&1 || true
    echo
}

# Checks

check_system_info() {
    section "System Info" "Baseline context for everything that follows"
    run 'hostname'
    run 'uname -a'
    run 'uptime'
    run 'cat /proc/device-tree/model 2>/dev/null; echo'
    run 'ip -brief addr'
}

check_login_history() {
    section "Login History" \
        "Unexpected users, unknown IPs, logins at odd hours, wtmp start date that predates your provisioning"
    run 'last -20'
    show_cmd 'lastb -10  # failed login attempts'
    lastb -10 2>/dev/null || info "(no failed-login records)"
    echo
    run 'who'
    info "wtmp birth time (if older than your provisioning date, device isn't fresh):"
    run 'stat /var/log/wtmp | grep -E "Birth|Modify"'
}

check_users() {
    section "User Accounts" \
        "UID 0 accounts besides root, service accounts with a real shell, unknown users"
    show_cmd "awk -F: '\$7 !~ /(nologin|false|sync)/' /etc/passwd"
    awk -F: '$7 !~ /(nologin|false|sync)/' /etc/passwd
    echo
    info "Accounts with UID 0 (should ONLY be root):"
    show_cmd "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
    local root_accts
    root_accts=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    echo "$root_accts"
    if [[ "$root_accts" != "root" ]]; then
        alert "More than one UID-0 account found"
    else
        ok "Only root has UID 0"
    fi
}

check_ssh() {
    section "SSH Configuration and Keys" \
        "PermitRootLogin yes, PasswordAuthentication yes, ForceCommand, unknown authorized_keys entries"
    show_cmd 'sshd -T | grep -iE "permitroot|passwordauth|allowusers|allowgroups|authorizedkeys|forcecommand|challenge"'
    sshd -T 2>/dev/null | grep -iE "permitroot|passwordauth|allowusers|allowgroups|authorizedkeys|forcecommand|challenge" \
        || info "(sshd -T unavailable)"
    echo

    show_cmd 'find / -name authorized_keys -type f 2>/dev/null'
    local akeys
    mapfile -t akeys < <(find / -name authorized_keys -type f 2>/dev/null)
    if [[ ${#akeys[@]} -eq 0 ]]; then
        ok "No authorized_keys files found"
    else
        for f in "${akeys[@]}"; do
            flag "$f"
            ls -la "$f"
            echo "  --- contents ---"
            sed 's/^/  /' "$f"
            echo
        done
        info "Confirm every key above belongs to a current team member."
    fi
}

check_auth_log() {
    section "Recent Auth Activity" \
        "Accepted logins from unexpected IPs, bursts of failed attempts, sudo by unexpected users"
    if [[ -f /var/log/auth.log ]]; then
        run 'grep -E "Accepted|Failed|sudo:" /var/log/auth.log | tail -40'
    else
        run 'journalctl _COMM=sshd --since "7 days ago" --no-pager | tail -40'
    fi
}

check_listeners() {
    section "Listening Ports" \
        "Anything bound to 0.0.0.0 that should be loopback. Services you did not install."
    run 'ss -tlnp'
    run 'ss -ulnp'
}

check_connections() {
    section "Active Network Connections" \
        "Established connections to foreign addresses you don't recognize"
    run 'ss -tnp state established'
}

check_processes() {
    section "Process Tree" \
        "Hidden/obfuscated process names, unexpected high-CPU, anything exec'd from /tmp, /dev/shm, or /home"
    run 'ps auxf'
    info "Executables running from suspicious paths:"
    show_cmd 'ls -l /proc/*/exe 2>/dev/null | grep -E "/tmp|/var/tmp|/dev/shm|/home"'
    local sus
    sus=$(ls -l /proc/*/exe 2>/dev/null | grep -E "/tmp|/var/tmp|/dev/shm|/home" || true)
    [[ -z "$sus" ]] && ok "No processes running from world-writable or user dirs" || { flag "Found:"; echo "$sus"; }
}

check_cron() {
    section "Cron Jobs and User Crontabs" \
        "Anything beyond standard Debian (sysstat, apt, logrotate, man-db, exim4, e2scrub, dpkg). Scripts that fetch or curl out."
    run 'crontab -l 2>&1'
    run 'ls -la /var/spool/cron/crontabs/ 2>/dev/null'
    run 'grep -r . /etc/cron.*/ /etc/crontab 2>/dev/null'
}

check_systemd() {
    section "Systemd Timers, Services, and Custom Units" \
        "Timers or services not from Debian/BSP packages. Recently-added unit files."
    run 'systemctl list-units --type=timer --all --no-pager'
    run 'systemctl list-unit-files --type=service --state=enabled --no-pager'
    info "Custom unit files in /etc/systemd (non-package provided):"
    run 'ls -la /etc/systemd/system/ /etc/systemd/user/ 2>/dev/null'
    info "Unit files modified in last 60 days (look for unexpected additions):"
    run 'find /etc/systemd /lib/systemd /usr/lib/systemd \( -name "*.service" -o -name "*.timer" \) -mtime -60 2>/dev/null'
}

check_init_scripts() {
    section "Legacy Init Scripts and rc.local" \
        "Any /etc/rc.local content, unfamiliar entries in /etc/init.d"
    show_cmd 'cat /etc/rc.local 2>/dev/null'
    if [[ -f /etc/rc.local ]]; then
        cat /etc/rc.local
    else
        ok "/etc/rc.local not present"
    fi
    echo
    run 'ls -la /etc/init.d/ /etc/rcS.d/ 2>/dev/null'
}

check_ld_preload() {
    section "Library Injection (LD_PRELOAD / ld.so.preload)" \
        "ANY existence of /etc/ld.so.preload is suspicious. ANY unexpected process with LD_PRELOAD set."
    show_cmd 'ls -la /etc/ld.so.preload'
    if [[ -e /etc/ld.so.preload ]]; then
        alert "/etc/ld.so.preload EXISTS — investigate immediately"
        ls -la /etc/ld.so.preload
        echo "--- contents ---"
        cat /etc/ld.so.preload
    else
        ok "/etc/ld.so.preload does not exist"
    fi
    echo

    info "Scanning process environments (numeric PIDs only; self/thread-self skipped):"
    show_cmd 'for p in /proc/[0-9]*/environ; do grep -a -l LD_PRELOAD "$p"; done'
    local found=0
    for p in /proc/[0-9]*/environ; do
        local pid; pid=$(basename "$(dirname "$p")")
        # Skip our own shell, the grep process ancestry, and kernel threads
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        if grep -a -q LD_PRELOAD "$p" 2>/dev/null; then
            flag "PID $pid has LD_PRELOAD in environ:"
            echo -n "    cmdline: "
            tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null; echo
            tr '\0' '\n' < "$p" 2>/dev/null | grep LD_PRELOAD | sed 's/^/    /'
            found=1
        fi
    done
    [[ $found -eq 0 ]] && ok "No processes have LD_PRELOAD set"
}

check_kernel_modules() {
    section "Kernel Modules" \
        "Module names that don't match real hardware on this board. Modules dropped in after initial kernel install."
    run 'lsmod'
    info "Modules newer than modules.dep (would indicate out-of-band drops):"
    show_cmd 'find /lib/modules/$(uname -r) -name "*.ko*" -newer /lib/modules/$(uname -r)/modules.dep'
    local newmods
    newmods=$(find "/lib/modules/$(uname -r)" -name "*.ko*" -newer "/lib/modules/$(uname -r)/modules.dep" 2>/dev/null || true)
    [[ -z "$newmods" ]] && ok "No modules newer than modules.dep" || { flag "Recently-added modules:"; echo "$newmods"; }
}

check_suid() {
    section "SUID/SGID Binaries" \
        "SUID binaries in /tmp, /home, /opt, /var, or any unusual path. Additions to the standard Debian set."
    run 'find / -perm -4000 -type f 2>/dev/null'
    info "SUID binaries OUTSIDE standard system paths (high-signal):"
    show_cmd 'find / -perm -4000 -type f 2>/dev/null | grep -vE "^/usr/(bin|sbin|lib|libexec)/"'
    local unusual
    unusual=$(find / -perm -4000 -type f 2>/dev/null | grep -vE "^/usr/(bin|sbin|lib|libexec)/" || true)
    [[ -z "$unusual" ]] && ok "All SUID binaries are in standard paths" || { flag "Non-standard SUID paths:"; echo "$unusual"; }
}

check_recent_changes() {
    section "Recent Filesystem Modifications" \
        "Unexpected edits to config files in /etc, new files in /usr/local or /opt, anything new in /root"
    if [[ $FAST -eq 1 ]]; then
        info "Skipped (--fast)"
        return
    fi
    run 'find /etc /usr/local /opt /root -type f -mtime -60 2>/dev/null | head -100'
}

check_temp_dirs() {
    section "World-Writable Temp Directories" \
        "ANY executable, staged payloads, hidden files that aren't normal user cache/config"
    run 'find /tmp /var/tmp /dev/shm -type f 2>/dev/null'
    info "Executables in temp dirs (classic staging indicator):"
    show_cmd 'find /tmp /var/tmp /dev/shm -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) 2>/dev/null'
    local execs
    execs=$(find /tmp /var/tmp /dev/shm -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) 2>/dev/null || true)
    [[ -z "$execs" ]] && ok "No executables in temp dirs" || { flag "Executables found:"; echo "$execs"; }
}

check_network_config() {
    section "Network Configuration" \
        "Unexpected firewall rules, extra /etc/hosts entries, DNS pointed somewhere unexpected"
    run 'iptables -L -n -v 2>/dev/null | head -80'
    run 'nft list ruleset 2>/dev/null | head -80'
    run 'ip route'
    run 'cat /etc/hosts'
    run 'cat /etc/resolv.conf'
}

check_docker() {
    section "Docker" \
        "Containers or images not from your CI pipeline. Unknown image digests."
    if command -v docker >/dev/null 2>&1; then
        run 'docker ps -a'
        run 'docker image ls'
    else
        info "Docker not installed"
    fi
}

check_debsums() {
    section "Package Integrity (debsums)" \
        "Modified BINARIES in /usr/bin, /usr/sbin, /bin, /sbin, /lib*. Missing files. Header files, locales, and BSP-patched files in /usr/include can usually be ignored."
    if [[ $FAST -eq 1 ]]; then
        info "Skipped (--fast). Omit --fast to include (can take several minutes)."
        return
    fi
    if ! command -v debsums >/dev/null 2>&1; then
        flag "debsums not installed. Install with: apt-get install debsums"
        return
    fi
    run 'debsums -ac'
}

# Main
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Device Security Audit${NC}"
echo -e "${BOLD}  Host: $(hostname)   Date: $(date -Iseconds)${NC}"
[[ $FAST -eq 1 ]] && echo -e "${YELLOW}  Mode: --fast (slow checks skipped)${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"

check_system_info
check_login_history
check_users
check_ssh
check_auth_log
check_listeners
check_connections
check_processes
check_cron
check_systemd
check_init_scripts
check_ld_preload
check_kernel_modules
check_suid
check_recent_changes
check_temp_dirs
check_network_config
check_docker
check_debsums

echo
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Audit complete.${NC}"
echo -e "${BOLD}  Review all ${YELLOW}⚠${NC}${BOLD} and ${RED}✗${NC}${BOLD} lines and any unexpected output.${NC}"
echo -e "${BOLD}  Commands are shown above each check — re-run manually to dig deeper.${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"