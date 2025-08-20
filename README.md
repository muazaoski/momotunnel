# Momo Tunnel

Modern Windows VPN client (VLESS / VMess / Trojan) with a polished UI, production-safe defaults, and strong Windows integration.

![status](https://img.shields.io/badge/platform-windows-0078d7) ![security](https://img.shields.io/badge/security-DPAPI%20key%2C%20prod%20logging-green)

## Features
- V2Ray/Trojan support: VLESS, VMess, Trojan
- HTTP (1081) + SOCKS (1080) inbounds for system proxy routing
- Kill Switch (Windows Firewall) and DNS leak protection
- Split Tunneling via PAC (domains/IP/CIDR)
- Auto-connect, auto-reconnect, tray, quick toggles
- Start with Windows (HKCU Run)
- Production logging (INFO/WARN with redaction) + Diagnostics export

## Quick Start (Users)
1. Download the latest `Momo Tunnel.exe` from Releases (or build locally).
2. Optional (if not bundling tools): create `%APPDATA%/MomoTunnel/data/tool_hashes.json` with:
   `{ "v2ray_sha256": "<hash>", "trojan_sha256": "<hash>" }`
3. Run the EXE, import your configuration, click Connect.

## Build Locally
```bash
pip install -r requirements.txt
python npv_tunnel_pc.py  # run from source
# or build EXE
build_momo_exe.bat
```
The build script will use your icon from `Downloads/iconmomotunnel256.ico` (falls back to 48/others).

## Security & Privacy
- Configs are encrypted at rest with a **Fernet** key wrapped by **Windows DPAPI** (per-user), stored in `%APPDATA%/MomoTunnel/data/npv_tunnel.key`.
- Tool downloads require a checksum manifest (`tool_hashes.json`) unless you pre-bundle executables in `%APPDATA%/MomoTunnel/vpn_tools/`.
- Production logging is default: INFO to file, WARNING to console, and aggressive secret redaction.

## Split Tunneling
- Domains/IPs/CIDRs can bypass proxy via PAC. Configure in Advanced Settings.

## Diagnostics
- Activity Monitor → Export Diagnostics (zip saved to your Downloads).
- Fix Network button resets proxy/PAC, restores DNS, and clears stale kill switch rules.

## GitHub Release
```bash
git init
git add .
git commit -m "Momo Tunnel initial public"
git branch -M main
git remote add origin https://github.com/<you>/momo-tunnel.git
git push -u origin main
```
- Tag a release (`v1.0.0`) and upload the built EXE (or rely on the provided GitHub Action to build artifacts).

## Troubleshooting
- SmartScreen: More info → Run anyway (code signing recommended later).
- Icon not updating: rename EXE once or clear `%LocalAppData%/IconCache.db`.
- No browsing after connect: press Fix Network, verify system proxy and tool hashes.

## License
MIT (recommended). Include a `LICENSE` file.
