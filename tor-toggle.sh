#!/bin/zsh
# System-level TOR toggle for archcrypt (zsh + iptables-legacy)
# Modes: on | off | status
# Failsafe: when ON -> default DROP; only TCP + DNS via TOR allowed; IPv6 fully blocked.
# If TOR is not ready, networking stays blocked.

set -euo pipefail

# --- constants ---
TRANS_PORT=9040       # Tor TransPort  (set in /etc/tor/torrc)
DNS_PORT=5353         # Tor DNSPort    (set in /etc/tor/torrc)
TOR_UID="$(id -u tor 2>/dev/null || true)"

# State + lock live in tmpfs so we reset on reboot
STATE_DIR="/run/tor-toggle"
V4_BACKUP="$STATE_DIR/iptables.v4"
V6_BACKUP="$STATE_DIR/iptables.v6"
STATE_FILE="$STATE_DIR/state"
LOCK="$STATE_DIR/lock"
mkdir -p "$STATE_DIR"

# --- single-instance lock ---
exec {lock_fd}>"$LOCK" || exit 1
flock -n "$lock_fd" || { echo "[!] Another tor-toggle is running."; exit 1; }

# --- re-exec as root (sudo or doas), zsh-safe absolute path ---
if [[ "$EUID" -ne 0 ]]; then
  echo "[!] This action requires root. Re-running with sudo..."
  SCRIPT=${${(%):-%x}:A}        # absolute path to current script (zsh)
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "$SCRIPT" "$@"
  elif command -v doas >/dev/null 2>&1; then
    exec doas -E "$SCRIPT" "$@"
  else
    echo "[!] Neither sudo nor doas found."; exit 1
  fi
fi

# --- wrappers that use iptables wait-lock (-w) to avoid races ---
ipt()  { iptables    -w "$@"; }
iptn() { iptables -t nat -w "$@"; }
ipt6() { ip6tables   -w "$@"; }

# --- required commands check ---
require_cmds() {
  for c in systemctl iptables iptables-save iptables-restore ss; do
    command -v "$c" >/dev/null || { echo "[!] Missing command: $c"; exit 1; }
  done
  if command -v ip6tables >/dev/null; then
    HAVE_IP6=1
  else
    HAVE_IP6=0
  fi
}

# --- wait for Tor to bind ports ---
check_tor_ready() {
  for i in {1..10}; do
    if ss -ltn | grep -q ":${TRANS_PORT}\b" && ss -lun | grep -q ":${DNS_PORT}\b"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# --- backup / restore rules (to /run) ---
backup_rules() {
  iptables-save   -w >"$V4_BACKUP" 2>/dev/null || true
  if [[ $HAVE_IP6 -eq 1 ]]; then ip6tables-save -w >"$V6_BACKUP" 2>/dev/null || true; fi
}

restore_rules() {
  ipt  -F; iptn -F
  if [[ -s "$V4_BACKUP" ]]; then iptables-restore -w <"$V4_BACKUP"  || true
  else ipt -P INPUT ACCEPT; ipt -P OUTPUT ACCEPT; ipt -P FORWARD ACCEPT; fi
  if [[ $HAVE_IP6 -eq 1 ]]; then
    if [[ -s "$V6_BACKUP" ]]; then ip6tables-restore -w <"$V6_BACKUP" || true
    else ipt6 -P INPUT ACCEPT; ipt6 -P OUTPUT ACCEPT; ipt6 -P FORWARD ACCEPT; fi
  fi
  rm -f "$V4_BACKUP" "$V6_BACKUP" 2>/dev/null || true
}

# --- ON rules (IPv4 redirect; IPv6 hard block) ---
rules_on_v4() {
  # Flush and default-DROP everywhere (fail-closed)
  ipt  -F; iptn -F
  ipt  -P INPUT   DROP
  ipt  -P OUTPUT  DROP
  ipt  -P FORWARD DROP

  # Allow loopback + established
  ipt -A INPUT  -i lo -j ACCEPT
  ipt -A OUTPUT -o lo -j ACCEPT
  ipt -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
  ipt -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # NAT exceptions BEFORE redirects
  # 1) Don't touch traffic already destined to localhost
  iptn -A OUTPUT -d 127.0.0.0/8  -j RETURN
  # 2) Don't hijack explicit local DNS to 127.0.0.1:53
  iptn -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j RETURN
  # 3) Let the tor daemon itself reach the network (avoid hairpin)
  if [[ -n "${TOR_UID}" ]]; then
    iptn -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j RETURN
    ipt  -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j ACCEPT
  fi

  # Redirect all DNS to Tor DNSPort (and kill stray UDP/53 from apps)
  iptn -A OUTPUT -p udp --dport 53        -j REDIRECT --to-ports "$DNS_PORT"
  ipt  -A OUTPUT -p udp --dport 53        -j DROP

  # Redirect NEW TCP connects to Tor TransPort
  iptn -A OUTPUT -p tcp --syn              -j REDIRECT --to-ports "$TRANS_PORT"

  echo "[+] IPv4 rules applied: default DROP; TCP/DNS forced into TOR."
}

rules_on_v6_block() {
  # Hard block IPv6 to prevent leaks
  ipt6 -F
  ipt6 -P INPUT   DROP
  ipt6 -P OUTPUT  DROP
  ipt6 -P FORWARD DROP
  # Keep localhost ::1 usable for services that bind both stacks
  ipt6 -A INPUT  -i lo -j ACCEPT
  ipt6 -A OUTPUT -o lo -j ACCEPT
  ipt6 -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
  ipt6 -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "[+] IPv6 blocked (DROP)."
}

rules_on() {
  backup_rules
  rules_on_v4
  if [[ $HAVE_IP6 -eq 1 ]]; then rules_on_v6_block; fi

  # Final sanity: if NAT redirects went missing, lock down
  iptn -S | grep -q -- "--to-ports $TRANS_PORT" || { echo "[!] NAT->TransPort missing; locking down."; ipt -P OUTPUT DROP; ipt -P INPUT DROP; ipt -P FORWARD DROP; exit 1; }
  iptn -S | grep -q -- "--to-ports $DNS_PORT"   || { echo "[!] NAT->DNSPort missing;   locking down."; ipt -P OUTPUT DROP; ipt -P INPUT DROP; ipt -P FORWARD DROP; exit 1; }
}

rules_off() {
  restore_rules
  echo "[+] TOR mode DISABLED – previous firewall restored."
}

show_status() {
  local pol_out pol_in pol_fwd nat_tcp nat_dns tor_active v6_in v6_out v6_fwd
  pol_out="$(iptables -S | awk '$1=="-P" && $2=="OUTPUT"{print $3}')"
  pol_in ="$(iptables -S | awk '$1=="-P" && $2=="INPUT" {print $3}')"
  pol_fwd="$(iptables -S | awk '$1=="-P" && $2=="FORWARD"{print $3}')"
  nat_tcp="$(iptables -t nat -S | grep -E '\-A OUTPUT .* -p tcp .* --syn .* REDIRECT .* --to-ports '"$TRANS_PORT"'' || true)"
  nat_dns="$(iptables -t nat -S | grep -E '\-A OUTPUT .* -p udp .* dport 53 .* REDIRECT .* --to-ports '"$DNS_PORT"''  || true)"
  tor_active="$(systemctl is-active tor 2>/dev/null || true)"

  if [[ $HAVE_IP6 -eq 1 ]]; then
    v6_in ="$(ip6tables -S 2>/dev/null | awk '$1=="-P" && $2=="INPUT" {print $3}'  || true)"
    v6_out="$(ip6tables -S 2>/dev/null | awk '$1=="-P" && $2=="OUTPUT"{print $3}' || true)"
    v6_fwd="$(ip6tables -S 2>/dev/null | awk '$1=="-P" && $2=="FORWARD"{print $3}'|| true)"
  else
    v6_in=v6-na; v6_out=v6-na; v6_fwd=v6-na
  fi

  if [[ "$pol_out" == "DROP" && "$pol_in" == "DROP" && "$pol_fwd" == "DROP" && -n "$nat_tcp" && -n "$nat_dns" ]]; then
    echo "[STATUS] TOR MODE: ENABLED"
  else
    echo "[STATUS] TOR MODE: DISABLED"
  fi
  echo "[STATUS] tor.service: ${tor_active:-unknown}"
  echo "[STATUS] IPv4 policy: IN=$pol_in OUT=$pol_out FWD=$pol_fwd"
  echo "[STATUS] IPv6 policy: IN=$v6_in OUT=$v6_out FWD=$v6_fwd"
  ss -ltn | grep -q ":$TRANS_PORT\b" && echo "[STATUS] TOR TransPort :$TRANS_PORT listening" || echo "[STATUS] TOR TransPort :$TRANS_PORT NOT listening"
  ss -lun | grep -q ":$DNS_PORT\b"   && echo "[STATUS] TOR DNSPort  :$DNS_PORT listening"  || echo "[STATUS] TOR DNSPort  :$DNS_PORT NOT listening"
}

require_cmds

case "${1:-}" in
  on)
    if [[ -s "$STATE_FILE" && "$(cat "$STATE_FILE")" == "on" ]]; then
      echo "[!] TOR MODE ALREADY ENABLED."; show_status; exit 0
    fi
    echo "[*] Enabling TOR routing..."
    # Start tor daemon if not already active (harmless for Tor Browser; it uses its own tor)
    systemctl is-active --quiet tor || systemctl start tor

    if ! check_tor_ready; then
      echo "[!] TOR ports not ready. Refusing to open network – staying BLOCKED."
      ipt -P OUTPUT DROP || true; ipt -P INPUT DROP || true; ipt -P FORWARD DROP || true
      if [[ $HAVE_IP6 -eq 1 ]]; then ipt6 -P OUTPUT DROP || true; ipt6 -P INPUT DROP || true; ipt6 -P FORWARD DROP || true; fi
      exit 1
    fi

    rules_on
    echo on > "$STATE_FILE"
    show_status
    ;;
  off)
    if [[ -s "$STATE_FILE" && "$(cat "$STATE_FILE")" == "off" ]]; then
      echo "[!] TOR MODE ALREADY DISABLED."; show_status; exit 0
    fi
    echo "[*] Disabling TOR routing..."
    rules_off
    echo off > "$STATE_FILE"
    show_status
    ;;
  status)
    show_status
    ;;
  *)
    echo "USAGE: $0 {on|off|status}"
    exit 2
    ;;
esac
