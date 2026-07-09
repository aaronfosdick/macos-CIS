# macOS CIS Baseline Scripts – Tahoe-os26

This repository contains two companion shell scripts for auditing and remediating macOS against a subset of **Center for Internet Security (CIS) benchmarks**. They are designed to work together: one inspects the current system state, the other applies the recommended settings.

## Files

| File | Role | Description |
|------|------|-------------|
| `macos-CIS-query-Tahoe-os26.sh` | **Audit / Query** | Read‑only scan of the current macOS configuration. Checks FileVault, Firewall, Gatekeeper, SIP, software update settings, password policy, screen saver, sharing services, Safari security, log retention, and more. Outputs a formatted compliance report. |
| `macos-CIS-apply-Tahoe-os26.sh` | **Remediation / Apply** | Interactive script that enforces the same CIS controls. Prompts the user for a few parameters (screen saver timeout, grace period, SSH preference, update installation policy), then applies terminal commands to harden the system. Provides a `check_and_apply` helper that only changes non‑compliant settings. |

## Usage

### Query (audit only)
```bash
sudo bash macos-CIS-query-Tahoe-os26.sh
```
Runs in read‑only mode and prints an audit report to the terminal.

### Apply (remediation)
```bash
sudo bash macos-CIS-apply-Tahoe-os26.sh
```
Will ask several questions and then apply the corresponding CIS controls.  
**Test on a non‑production machine first.**

## Controls Covered

- **Core CIS controls**: FileVault, Application Firewall with Stealth Mode, Gatekeeper, SIP, Guest Account, Secure Boot.
- **Software updates**: Automatic check, download, critical updates, app store updates, OS updates.
- **Password policy**: Minimum 16 characters, no complexity requirements, lockout after 5 failed attempts.
- **Screen saver / lock**: Configurable idle timeout and grace period.
- **Sharing & Bluetooth**: Disables Remote Apple Events, Internet Sharing, Bluetooth sharing, AirDrop, AirPlay.
- **Login security**: Disables auto‑login, sets login‑window banner.
- **Environment**: Sets global `umask 027`.
- **Log retention**: Enforces 24‑hour retention via unified logging, newsyslog rotation, ASL TTL, and cleanup of old logs.

## Notes

- Both scripts require `sudo` (root) to read or modify system‑level preferences.
- Some controls (e.g., SIP) can only be enabled from macOS Recovery; the apply script detects this and provides guidance.
- If the device is enrolled in an MDM (e.g., Fleet), MDM configuration profiles may override locally applied settings.
- The scripts have been tested on macOS 14 (Sonoma) and later; some commands may differ on older versions.

## License

These scripts are provided as‑is for educational and administrative purposes. Use at your own risk.

## AppleScript Migration Guidance

These scripts are written in bash and will need a more substantial conversion to be compatible with AppleScript. Use the following guidance when translating them:

- Replace bash-specific syntax such as `#!/bin/bash`, `if [ ... ]`, `[[ ... ]]`, `$(...)`, `local`, `eval`, `read -p`, and heredocs with AppleScript equivalents.
- Use double-quoted AppleScript strings. If a string must contain a literal double quote, escape it as `\"`.
- Keep shell literals inside AppleScript command strings in single quotes when possible, for example `grep -q 'assessments enabled'`.
- For dynamic values, build shell commands with `quoted form of` so values are safely escaped rather than manually inserted.
- Prefer wrapping the existing system commands in `do shell script` from AppleScript, while keeping the overall logic and prompts in AppleScript for UI and flow control.
- For read-only audit logic, return status text or result values from AppleScript rather than relying on bash-style `echo` and `printf` output.
- For remediation logic, use AppleScript dialogs or prompts for user input and then pass the resulting values into shell commands via `do shell script`.