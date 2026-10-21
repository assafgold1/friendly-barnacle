#!/bin/bash
# Axiom OTP gate — runs on the Proxmox host and installs the gate inside a Windows VM
# through the QEMU guest agent.
#
#   bash <(curl -s https://raw.githubusercontent.com/assafgold1/friendly-barnacle/main/install.sh) <vmid>              install + QR link
#   bash <(curl -s https://raw.githubusercontent.com/assafgold1/friendly-barnacle/main/install.sh) <vmid> status
#   bash <(curl -s https://raw.githubusercontent.com/assafgold1/friendly-barnacle/main/install.sh) <vmid> lockdown     close RDP except through the gate
#   bash <(curl -s https://raw.githubusercontent.com/assafgold1/friendly-barnacle/main/install.sh) <vmid> uninstall
set -euo pipefail

REPO_RAW="${AXIOM_REPO_RAW:-https://raw.githubusercontent.com/assafgold1/friendly-barnacle/main}"
QR_URL="${AXIOM_QR_URL:-http://otp.axiom.taninoni.com:9911}"
VMID="${1:-${VPSID:-}}"
ACTION="${2:-install}"
GATE_PORT="${GATE_PORT:-47123}"
REMOTE_DIR='C:\ProgramData\OtpGate'
REMOTE_SCRIPT="$REMOTE_DIR\\otp-gate.ps1"

die()  { echo "✗ $*" >&2; exit 1; }
step() { echo "→ $*"; }

[[ $EUID -eq 0 ]] || die "Run as root on the Proxmox host."
command -v qm >/dev/null || die "qm not found — this runs on the Proxmox host, not inside the VM."
[[ "$VMID" =~ ^[0-9]+$ ]] || die "Usage: bash <(curl -s $REPO_RAW/install.sh) <vmid> [install|status|lockdown|uninstall]"
qm status "$VMID" >/dev/null 2>&1 || die "VM $VMID does not exist."
qm agent "$VMID" ping >/dev/null 2>&1 \
  || die "QEMU Guest Agent is not answering in VM $VMID. Enable it in VM > Options and install it in Windows (virtio-win ISO)."

# Runs a command inside the VM, relays its output and returns its exit code
guest() {
  local json
  json=$(qm guest exec "$VMID" --timeout 180 -- "$@") || return 1
  perl -MJSON::PP -e '
    my $r = decode_json(join "", <STDIN>);
    print $r->{"out-data"} // "";
    print STDERR $r->{"err-data"} // "";
    exit($r->{"exited"} ? ($r->{"exitcode"} // 1) : 124);
  ' <<<"$json"
}

gate() { guest powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$REMOTE_SCRIPT" "$@"; }

# Writes a file inside the VM through the Proxmox API (qm has no file-write command)
put_file() { pvesh create "/nodes/$(hostname -s)/qemu/$VMID/agent/file-write" --file "$1" --content "$2" >/dev/null; }

install_gate() {
  step "Downloading the gate script"
  local ps1
  ps1=$(curl -fsS "$REPO_RAW/otp-gate.ps1") || die "Could not download $REPO_RAW/otp-gate.ps1"

  step "Copying it into VM $VMID"
  guest cmd.exe /c "if not exist $REMOTE_DIR mkdir $REMOTE_DIR" >/dev/null
  put_file "$REMOTE_SCRIPT" "$ps1"

  # The secret is created here and written straight into the VM; it never touches disk on the host
  local secret
  secret=$(head -c 20 /dev/urandom | base32 | tr -d '=\n')
  put_file "$REMOTE_DIR\\secret.txt" "$secret"

  step "Installing the gate service in Windows"
  gate -Install -Unattended -GatePort "$GATE_PORT" || die "Install failed inside the VM (see output above)."

  step "Creating the QR link"
  local label id
  label="VM${VMID}-$(hostname -s)"
  id=$(curl -fsS -X POST --data-binary "otpauth://totp/Axiom:${label}?secret=${secret}&issuer=Axiom" "$QR_URL/api/qr") \
    || die "Could not create the QR link on $QR_URL"
  unset secret

  echo
  echo "  Scan this in Google Authenticator:"
  echo
  echo "      $QR_URL/qr/$id"
  echo
  echo "  The link works once and expires in 10 minutes."
  echo

  local code
  while true; do
    read -r -p "Enter the 6-digit code Google Authenticator shows now: " code
    if gate -Verify -Code "$code" >/dev/null 2>&1; then break; fi
    echo "  Wrong code — wait for the next one and try again."
  done

  echo
  echo "✓ The gate is running on TCP $GATE_PORT in VM $VMID."
  echo "  RDP is still open to everyone. Once vps-connect from your Mac answers OK, lock it down:"
  echo
  echo "      bash <(curl -s $REPO_RAW/install.sh) $VMID lockdown"
  echo
  echo "  If the VM is behind NAT on this host, forward TCP $GATE_PORT to it like you forward RDP."
}

lockdown_gate() {
  echo "This closes RDP to everyone except IPs that sent a valid code through the gate."
  echo "Make sure vps-connect from your Mac works first. The Proxmox console keeps working regardless."
  local answer
  read -r -p "Lock down VM $VMID now? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
  gate -Lockdown -Force
}

case "$ACTION" in
  install)   install_gate ;;
  status)    gate -Status ;;
  lockdown)  lockdown_gate ;;
  uninstall) gate -Uninstall ;;
  *)         die "Unknown action '$ACTION' (install|status|lockdown|uninstall)" ;;
esac
