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

## Recent Workflow Additions

- The query script now writes timestamped snapshot files to `/private/var/db/macos-cis/snapshots` after each run.
- Snapshot files are plain text and human-readable, using a simple `KEY=VALUE` format that can later be consumed by an AppleScript-based apply workflow.
- The apply script now offers two modes: apply the full CIS baseline, or restore from a previously captured snapshot.
- Snapshot selection is displayed with a human-readable date/time format (including hour and minute) to make it easier to choose the correct backup.
- Snapshot restore intentionally skips irreversible or unsafe changes such as FileVault, recovery-key escrow state, SIP, and Secure Boot.

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

## AppleScript create notes
Open the Script Editor app on your Mac (press Cmd + Space and type "Script Editor").

# This finds the internal path inside this specific app bundle
set repoPath to POSIX path of (path to me) & "Contents/Resources/myscript.sh"

# Run the embedded script with admin rights
do shell script "sudo " & quoted form of repoPath with administrator privileges




1. Save your Bash script somewhere permanent (e.g., /usr/local/bin/myscript.sh or inside your Documents folder).
2. Make sure it's executable by running chmod +x /path/to/myscript.sh in the Terminal.
3. In your AppleScript Editor, use this single line:

do shell script "'/path/to/your/myscript.sh'" with administrator privileges

# Obtain developer certificate if not present

- Download Apple's Developer ID - G2 SubCA certificate directly from Apple's site: developer.apple.com/certificationauthority/DeveloperIDG2CA.cer
- Double-click the .cer file to add it to your Keychain.

# Sign app - to get through Gatekeeper

1.  **Verify your certificate**

    ```shell
    security find-identity -v -p codesigning
    ```

2.  **Deep sign**

    ```shell
    codesign --force --deep --options runtime --sign "Developer ID Application: Your Name (TEAM_ID)" /path/to/MyScriptApp.app
    ```

3.  **Verify**

    ```shell
    codesign --verify --verbose /path/to/MyScriptApp.app
    ```

4.  **Use ditto to zip**

    ```shell
    ditto -c -k --keepParent /path/to/MyScriptApp.app /path/to/MyScriptApp.zip
    ```

5.  **Submit to notary**

    ```shell
    xcrun notarytool submit /path/to/MyScriptApp.zip --apple-id "your-apple-id@email.com" --team-id "YOUR_TEAM_ID" --wait
    ```

6.  **Staple app**

    ```shell
    xcrun stapler staple /path/to/MyScriptApp.app
