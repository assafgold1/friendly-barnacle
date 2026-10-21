# Axiom OTP Gate

Keeps RDP on a Windows VM closed to the internet, and opens it per IP for a few minutes
to whoever sends a valid Google Authenticator code. Pure PowerShell + bash, nothing third-party.

## Install (on the Proxmox host)

```bash
bash <(curl -s https://raw.githubusercontent.com/assafgold1/axiom-otp-gate/main/install.sh) <vmid>
```

The installer copies the gate into the VM through the QEMU guest agent, creates a new secret,
and prints a one-time link (`http://otp.axiom.taninoni.com:9911/qr/<id>`, valid for 10 minutes) with the QR code
for Google Authenticator. It then asks for a code from the app to confirm the setup.

Requires the QEMU Guest Agent running in the VM (`qm agent <vmid> ping`).

| Command | What it does |
|---|---|
| `bash <(curl -s https://raw.githubusercontent.com/assafgold1/axiom-otp-gate/main/install.sh) <vmid>` | Install and get the QR link |
| `... <vmid> status` | Service state, open IPs, recent log |
| `... <vmid> lockdown` | Close RDP to everyone except gate-opened IPs |
| `... <vmid> uninstall` | Remove everything and restore the original RDP rules |

## Connect (on your Mac)

```bash
./vps-connect          # sends the current code to the gate, RDP opens for your IP
./vps-connect setup    # optional: store the secret in Keychain so no phone is needed
```

Settings via environment: `VPS_HOST` (required, e.g. `export VPS_HOST=1.2.3.4` in `~/.zshrc`),
`VPS_GATE_PORT` (default 47123), `VPS_RDP_FILE`.

The installer downloads `otp-gate.ps1` from this repo and creates the QR link on the QR server
(`AXIOM_QR_URL`, default `http://otp.axiom.taninoni.com:9911`).

## Files

- `install.sh` — Proxmox-side installer
- `otp-gate.ps1` — the gate service inside Windows (also usable directly: `-Install`, `-Lockdown`, `-Status`, `-Uninstall`)
- `vps-connect` — Mac client

## How the gate works

- A scheduled task (SYSTEM) listens on TCP 47123 for a 6-digit code.
- A valid code adds a firewall rule allowing RDP from the sender's IP for 10 minutes; the rule stays while an RDP session from that IP is connected.
- Each code works once. 5 wrong codes from one IP, or 20 overall, within 10 minutes block further attempts.
- If the VM is behind NAT on the Proxmox host, forward TCP 47123 to it like RDP.
