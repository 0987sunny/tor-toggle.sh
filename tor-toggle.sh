#!/bin/zsh
# v 1.2 yuriy edition 
# System-level TOR toggle for archcrypt (zsh + iptables-legacy)
# Modes: on | off | status
# Failsafe: when ON -> default DROP; only TCP + DNS via TOR allowed; IPv6 fully blocked.
# If TOR is not ready, networking stays blocked.
# This script requires iptables-legacy.

set -euo pipefail

# --- Configuration (for your Archcrypt system) ---
# The uid and ports MUST match your /etc/tor/torrc
: ${TOR_USER:="tor"}
: ${TRANS_PORT:=9040}
: ${DNS_PORT:=5353}
: ${CONTROL_PORT:=9051}

# --- UI helpers (same as your net-toggle) ---
autoload -Uz colors && colors || true
ok()   { print -P "%F{green}[✓]%f $*"; }
warn() { print -P "%F{yellow}[!]%f $*"; }
err()  { print -P "%F{red}[✗]%f $*" >&2; }
info() { print -P "%F{cyan}[*]%f $*"; }

banner() {
  local h="$(hostname -s 2>/dev/null || echo archcrypt)"
  local d="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  print -P "%F{magenta}================================================================================%f"
  print -P "%F{yellow}                      TOR-Toggle — ${h} — ${d}%f"
  print -P "%F{magenta}================================================================================%f"
}

# --- State + Lock ---
STATE_DIR="/run/tor-toggle"
V4_BACKUP="$STATE_DIR/iptables.v4"
V6_BACKUP="$STATE_DIR/iptables.v6"
STATE_FILE="$STATE_DIR/state"
LOCK="$STATE_DIR/lock"
mkdir -p "$STATE_DIR" &>/dev/null

# --- Single-instance lock ---
exec {lock_fd}>"$LOCK" || exit 1
flock -n "$lock_fd" || { err "Another tor-toggle is running."; exit 1; }

# --- Re-exec as root (zsh-safe absolute path) ---
if [[ "$EUID" -ne 0 ]]; then
  info "This action requires root. Re-running with sudo..."
  SCRIPT=${${(%):-%x}:A}
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "$SCRIPT" "$@"
  elif command -v doas >/dev/null 2>&1; then
    exec doas -E "$SCRIPT" "$@"
  else
    err "Neither sudo nor doas found."; exit 1
  fi
fi

# --- Command Check ---
TOR_UID="$(id -u "$TOR_USER" 2>/dev/null || true)"
require_cmds() {
  for c in systemctl iptables iptables-save iptables-restore ss curl; do
    command -v "$c" &>/dev/null || { err "Missing command: $c"; exit 1; }
  done
  command -v ip6tables &>/dev/null && HAVE_IP6=1 || HAVE_IP6=0
}

# --- Iptables Wrappers ---
ipt()  { iptables -w "$@"; }
iptn() { iptables -t nat -w "$@"; }
ipt6() { ip6tables -w "$@"; }

# --- Tor Readiness Check (must bind ports) ---
check_tor_ready() {
  info "Waiting for Tor daemon to bind ports..."
  local check_trans="ss -ltn | grep -q \":${TRANS_PORT}\b\""
  local check_dns="ss -lun | grep -q \":${DNS_PORT}\b\""
  for i in {1..20}; do
    if eval "$check_trans" && eval "$check_dns"; then
      ok "Tor is ready."
      return 0
    fi
    sleep 0.5
  done
  warn "Tor ports not ready after 10 seconds."
  return 1
}

# --- Firewall Rule Management ---
backup_rules() {
  info "Backing up current firewall rules..."
  iptables-save >"$V4_BACKUP" 2>/dev/null || true
  if [[ $HAVE_IP6 -eq 1 ]]; then ip6tables-save >"$V6_BACKUP" 2>/dev/null || true; fi
}

restore_rules() {
  info "Restoring previous firewall rules..."
  if [[ -s "$V4_BACKUP" ]]; then iptables-restore <"$V4_BACKUP" || true
  else ipt -F; ipt -P INPUT ACCEPT; ipt -P OUTPUT ACCEPT; ipt -P FORWARD ACCEPT; fi
  if [[ $HAVE_IP6 -eq 1 ]]; then
    if [[ -s "$V6_BACKUP" ]]; then ip6tables-restore <"$V6_BACKUP" || true
    else ipt6 -F; ipt6 -P INPUT ACCEPT; ipt6 -P OUTPUT ACCEPT; ipt6 -P FORWARD ACCEPT; fi
  fi
  rm -f "$V4_BACKUP" "$V6_BACKUP" 2>/dev/null || true
  ok "Firewall restored."
}

# --- Tor ON Rules (strict fail-closed) ---
apply_on_rules() {
  info "Applying secure, fail-closed firewall rules..."
  # IPv4: Flush all chains and set default policy to DROP
  ipt  -F; iptn -F
  ipt  -P INPUT   DROP
  ipt  -P OUTPUT  DROP
  ipt  -P FORWARD DROP

  # Allow Loopback traffic (essential for services)
  ipt -A INPUT  -i lo -j ACCEPT
  ipt -A OUTPUT -o lo -j ACCEPT

  # Allow DNS resolution to Tor's DNSPort (UDP)
  iptn -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
  ipt  -A OUTPUT -p udp --dport 53 -j ACCEPT
  ipt  -A INPUT  -p udp --sport 53 -j ACCEPT

  # Allow established connections (to keep the Tor connection alive)
  ipt -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Do NOT touch traffic to localhost
  iptn -A OUTPUT -d 127.0.0.0/8 -j RETURN
  
  # Allow Tor daemon to connect to the internet
  if [[ -n "${TOR_UID}" ]]; then
    iptn -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j RETURN
    ipt  -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j ACCEPT
  fi
  
  # Redirect all new TCP connections to Tor's TransPort
  iptn -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TRANS_PORT"
  
  # IPv6: Hard block everything
  if [[ $HAVE_IP6 -eq 1 ]]; then
    ipt6 -F
    ipt6 -P INPUT   DROP
    ipt6 -P OUTPUT  DROP
    ipt6 -P FORWARD DROP
    ipt6 -A INPUT  -i lo -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
  fi
  ok "Firewall rules applied."
}

# --- Tor Circuit Info (requires ControlPort) ---
show_tor_circuits() {
  info "Attempting to get Tor circuit information..."
  if ! ss -ltn | grep -q ":$CONTROL_PORT\b"; then
    warn "Tor control port not listening. Cannot get circuit info."
    warn "Ensure 'ControlPort $CONTROL_PORT' is in /etc/tor/torrc and the service is restarted."
    return 1
  fi
  
  local circuits
  circuits=$(echo "GETINFO circuit-status" | nc 127.0.0.1 "$CONTROL_PORT" | grep 'CIRCUIT' || true)
  if [[ -z "$circuits" ]]; then
    warn "No active Tor circuits found."
    return 1
  fi

  echo "$circuits" | while read -r line; do
    local circid status nodes
    circid=$(echo "$line" | awk '{print $2}')
    status=$(echo "$line" | awk '{print $4}')
    nodes=$(echo "$line" | awk '{print $6}' | tr ',' ' ' | sed 's/~\(.*\)//g')
    
    [[ "$status" != "BUILT" ]] && continue
    info "Circuit ID: $circid (Status: $status)"
    
    local i=1 node_list=()
    for node in ${=nodes}; do
      node_list+=( $(echo "GETINFO ns/name/${node}" | nc 127.0.0.1 "$CONTROL_PORT" | awk '{print $NF}' | tr -d '()') )
    done

    printf "    %-10s %s\n" "Entry Node:" "${node_list[1]:-?}"
    printf "    %-10s %s\n" "Middle Node:" "${node_list[2]:-?}"
    printf "    %-10s %s\n" "Exit Node:" "${node_list[3]:-?}"
  done
  ok "Circuit info displayed."
}

# --- Tor Speed Test ---
run_tor_speedtest() {
  info "Running a Tor speed test..."
  local url="https://speed.hetzner.de/100MB.bin"
  local temp_file="/tmp/tor_speedtest.$$"
  local start_time end_time elapsed_time size speed

  if ! ss -ltn | grep -q ":$TRANS_PORT\b"; then
    warn "Tor TransPort not listening. Cannot run speed test."
    return 1
  fi
  
  start_time=$(date +%s.%N)
  if ! curl -s --socks5-hostname 127.0.0.1:"$TRANS_PORT" "$url" -o "$temp_file"; then
    err "Speed test failed."
    rm -f "$temp_file"
    return 1
  fi
  end_time=$(date +%s.%N)
  
  elapsed_time=$(echo "$end_time - $start_time" | bc)
  size=$(du -b "$temp_file" | awk '{print $1}')
  speed=$(echo "scale=2; ($size / 1048576) / $elapsed_time" | bc)

  printf "    %-12s %s MB\n" "File Size:" "$((size / 1048576))"
  printf "    %-12s %s seconds\n" "Time Taken:" "$(printf "%.1f" "$elapsed_time")"
  printf "    %-12s %s MB/s\n" "Speed:" "$(printf "%.2f" "$speed")"

  warn "Note: Tor speeds are highly variable and depend on the current circuit."
  rm -f "$temp_file"
}

# --- Main Functions ---
tor_on() {
  if [[ -s "$STATE_FILE" && "$(cat "$STATE_FILE")" == "on" ]]; then
    warn "TOR mode is already ENABLED."
    show_status
    return 0
  fi
  
  banner
  info "Enabling TOR routing."
  
  if ! systemctl is-active --quiet tor; then
    info "Tor service is not active. Starting..."
    systemctl start tor
  fi
  
  if ! check_tor_ready; then
    err "Tor daemon failed to start or bind ports."
    err "Refusing to apply rules; network remains blocked."
    # The default DROP policy handles the block, so we just exit.
    exit 1
  fi
  
  backup_rules
  apply_on_rules
  
  ok "Tor routing is now ENABLED."
  echo "on" >"$STATE_FILE"
  show_status
}

tor_off() {
  if [[ -s "$STATE_FILE" && "$(cat "$STATE_FILE")" == "off" ]]; then
    warn "TOR mode is already DISABLED."
    show_status
    return 0
  fi
  
  banner
  info "Disabling TOR routing."
  
  info "Stopping tor service..."
  systemctl stop tor &>/dev/null || warn "Tor service not running."
  
  restore_rules
  
  ok "Tor routing is now DISABLED."
  echo "off" >"$STATE_FILE"
  show_status
}

show_status() {
  banner
  print -P "%F{green}[i]%f TOR-Toggle Status -%f"
  print

  info "Service Status:"
  local tor_status=$(systemctl is-active tor 2>/dev/null || echo "not-running")
  printf "    %-18s %s\n" "tor.service" "$tor_status"
  
  info "Port Status:"
  ss -ltn | grep -q ":$TRANS_PORT\b" && ok "TransPort :$TRANS_PORT is listening" || warn "TransPort :$TRANS_PORT is NOT listening"
  ss -lun | grep -q ":$DNS_PORT\b" && ok "DNSPort  :$DNS_PORT is listening" || warn "DNSPort  :$DNS_PORT is NOT listening"
  ss -ltn | grep -q ":$CONTROL_PORT\b" && ok "ControlPort :$CONTROL_PORT is listening" || warn "ControlPort :$CONTROL_PORT is NOT listening"
  
  info "Firewall Policy (Current):"
  local pol_out pol_in pol_fwd v6_in v6_out
  pol_in="$(ipt -S | awk '$1=="-P" && $2=="INPUT"{print $3}')"
  pol_out="$(ipt -S | awk '$1=="-P" && $2=="OUTPUT"{print $3}')"
  pol_fwd="$(ipt -S | awk '$1=="-P" && $2=="FORWARD"{print $3}')"
  printf "    %-18s %-12s %-12s %-12s\n" "IPv4 policy:" "IN=$pol_in" "OUT=$pol_out" "FWD=$pol_fwd"
  if [[ $HAVE_IP6 -eq 1 ]]; then
    v6_in="$(ip6tables -S | awk '$1=="-P" && $2=="INPUT"{print $3}')"
    v6_out="$(ip6tables -S | awk '$1=="-P" && $2=="OUTPUT"{print $3}')"
    printf "    %-18s %-12s %-12s %-12s\n" "IPv6 policy:" "IN=$v6_in" "OUT=$v6_out" "FWD=DROP"
  fi
  
  local nat_trans="$(iptn -S | grep "to-ports $TRANS_PORT" || true)"
  local nat_dns="$(iptn -S | grep "to-ports $DNS_PORT" || true)"
  if [[ -n "$nat_trans" ]]; then ok "Traffic is redirected to Tor TransPort."
  else warn "Traffic is NOT redirected to Tor TransPort."; fi
  if [[ -n "$nat_dns" ]]; then ok "DNS is redirected to Tor DNSPort."
  else warn "DNS is NOT redirected to Tor DNSPort."; fi
  
  print
  show_tor_circuits
  print
  run_tor_speedtest
}

# --- Main Script Entry ---
require_cmds
case "${1:-}" in
  on)
    tor_on
    ;;
  off)
    tor_off
    ;;
  status)
    show_status
    ;;
  *)
    echo "USAGE: $0 {on|off|status}"
    exit 2
    ;;
esac
