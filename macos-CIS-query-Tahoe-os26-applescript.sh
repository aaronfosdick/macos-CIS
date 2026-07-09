#!/bin/bash

# ==============================================================================
# macOS CIS Baseline Audit / Query Script (AppleScript-compatible wrapper)
# ==============================================================================
# This version preserves the audit workflow while moving the evaluation logic
# into AppleScript via osascript. It is read-only and writes a snapshot file
# alongside the original bash query script.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root (via sudo) to read system-level configurations."
  exit 1
fi

if ! command -v osascript >/dev/null 2>&1; then
  echo "[-] Error: osascript was not found. This AppleScript-compatible workflow requires macOS."
  exit 1
fi

clear
printf '==================================================================\n'
printf '          macOS CIS Compliance Configuration Audit                \n'
printf '==================================================================\n'
printf 'Timestamp: %s\n' "$(date)"
printf 'OS Version: %s\n' "$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
printf '==================================================================\n'
printf '\n'

SNAPSHOT_DIR="/private/var/db/macos-cis/snapshots"
SNAPSHOT_TS="$(date '+%Y%m%d-%H%M%S')"
SNAPSHOT_RUN_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
SNAPSHOT_FILE=""

mkdir -p "$SNAPSHOT_DIR"
SNAPSHOT_FILE="$SNAPSHOT_DIR/macos-cis-snapshot-$SNAPSHOT_TS.txt"
{
    echo "# macOS CIS Snapshot"
    echo "# Generated: $SNAPSHOT_RUN_TIME"
    echo "# Version: 1"
    echo "# Format: KEY=VALUE"
    echo "# Purpose: Human-readable restore input for a future AppleScript apply workflow"
    echo "SNAPSHOT_TIMESTAMP=$SNAPSHOT_RUN_TIME"
    echo "SNAPSHOT_FILENAME=$(basename "$SNAPSHOT_FILE")"
} > "$SNAPSHOT_FILE"

echo "[+] Snapshot export initialized: $SNAPSHOT_FILE"

echo ""

report_text=$(osascript <<'APPLESCRIPT'
set linefeed to "\n"

on joinText(listOfStrings, delimiter)
    set astid to AppleScript's text item delimiters
    set AppleScript's text item delimiters to delimiter
    set joinedString to listOfStrings as text
    set AppleScript's text item delimiters to astid
    return joinedString
end joinText

on shell(commandText)
    try
        return do shell script commandText
    on error errText
        return ""
    end try
end shell

on run
    set reportLines to {}
    set end of reportLines to "--- [0] Core CIS Controls ---"

    set fvStatus to shell("fdesetup status 2>/dev/null")
    if fvStatus contains "FileVault is On." then
        set end of reportLines to "CIS 2.3.1 - FileVault (Full Disk Encryption): On"
    else
        set end of reportLines to "CIS 2.3.1 - FileVault (Full Disk Encryption): Off"
    end if

    set personalRecovery to shell("fdesetup haspersonalrecoverykey 2>/dev/null")
    if personalRecovery contains "true" then
        set end of reportLines to "CIS 2.3.2 - FileVault Personal Recovery Key: Present"
    else
        set end of reportLines to "CIS 2.3.2 - FileVault Personal Recovery Key: Not Present"
    end if

    set institutionalRecovery to shell("fdesetup hasinstitutionalrecoverykey 2>/dev/null")
    if institutionalRecovery contains "true" then
        set end of reportLines to "CIS 2.3.2 - FileVault Institutional Recovery Key: Present"
    else
        set end of reportLines to "CIS 2.3.2 - FileVault Institutional Recovery Key: Not Present"
    end if

    set fwState to shell("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}'")
    set end of reportLines to "CIS 2.4.1 - Application Firewall: " & fwState

    set fwStealth to shell("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | awk '{print $NF}'")
    set end of reportLines to "CIS 2.4.2 - Firewall Stealth Mode: " & fwStealth

    set gatekeeperStatus to shell("spctl --status 2>/dev/null")
    if gatekeeperStatus contains "assessments enabled" then
        set end of reportLines to "CIS 2.4.3 - Gatekeeper: Enabled"
    else
        set end of reportLines to "CIS 2.4.3 - Gatekeeper: Disabled"
    end if

    set autoCheck to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null")
    if autoCheck is "" then set autoCheck to "0 (Disabled)"
    set end of reportLines to "CIS 1.1 - Automatic Update Check Enabled: " & autoCheck

    set autoDownload to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null")
    if autoDownload is "" then set autoDownload to "0 (Disabled)"
    set end of reportLines to "CIS 1.2 - Automatic Download Enabled: " & autoDownload

    set criticalUpdate to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null")
    if criticalUpdate is "" then set criticalUpdate to "0 (Disabled)"
    set end of reportLines to "CIS 1.5 - Install System Data & Security Files: " & criticalUpdate

    set appUpdate to shell("defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null")
    if appUpdate is "" then set appUpdate to "0 (Disabled)"
    set end of reportLines to "CIS 1.4 - Automatic App Store Updates: " & appUpdate

    set macosUpdate to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null")
    if macosUpdate is "" then set macosUpdate to "0 (Disabled)"
    set end of reportLines to "CIS 1.3 - Automatic OS Updates Enabled: " & macosUpdate

    set sipStatus to shell("csrutil status 2>/dev/null")
    if sipStatus contains "enabled" then
        set end of reportLines to "CIS 5.1.1 - System Integrity Protection (SIP): Enabled"
    else
        set end of reportLines to "CIS 5.1.1 - System Integrity Protection (SIP): Disabled (see note)"
    end if

    set guestStatus to shell("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
    if guestStatus is "1" or guestStatus is "true" then
        set end of reportLines to "CIS 6.1 - Guest Account: Enabled"
    else
        set end of reportLines to "CIS 6.1 - Guest Account: Disabled"
    end if

    set secureBootStatus to shell("system_profiler SPiBridgeDataType 2>/dev/null")
    if secureBootStatus contains "Secure Boot: Enabled" then
        set end of reportLines to "CIS 6.5 - Secure Boot (Intel T2): Enabled"
    else if shell("sysctl -n hw.optional.arm64 2>/dev/null") is "1" then
        set end of reportLines to "CIS 6.5 - Secure Boot (Apple Silicon): Always Enabled"
    else
        set end of reportLines to "CIS 6.5 - Secure Boot: Unable to determine / Not applicable"
    end if

    set autologinStatus to shell("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null")
    if autologinStatus is "" then set autologinStatus to "None (Secure)"
    set end of reportLines to "CIS 5.7 - Automatic UI Login User: " & autologinStatus

    set end of reportLines to ""
    set end of reportLines to "--- [1] System Preferences & Access Control ---"

    set ssTimeout to shell("defaults read com.apple.screensaver idleTime 2>/dev/null")
    if ssTimeout is "" then set ssTimeout to "Not Configured"
    set end of reportLines to "CIS 2.2.1 - Screen Saver Timeout (Seconds): " & ssTimeout

    set ssPwd to shell("defaults read com.apple.screensaver askForPassword 2>/dev/null")
    if ssPwd is "" then set ssPwd to "Not Configured"
    set end of reportLines to "CIS 2.2.2 - Require Password After Screen Saver: " & ssPwd

    set ssDelay to shell("defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null")
    if ssDelay is "" then set ssDelay to "Not Configured"
    set end of reportLines to "CIS 2.2.2 - Screen Saver Password Grace Period: " & ssDelay

    set aeStatus to shell("launchctl list 2>/dev/null | grep com.apple.AEServer")
    if aeStatus is "" then
        set end of reportLines to "CIS 3.3 - Remote Apple Events: Disabled"
    else
        set end of reportLines to "CIS 3.3 - Remote Apple Events: Enabled"
    end if

    return joinText(reportLines, linefeed)
end run

run
APPLESCRIPT
)

printf '%s
' "$report_text"

# Append a lightweight snapshot payload for downstream workflows.
{
    printf 'CIS_2_3_1_FILEVAULT_STATUS=%s\n' "$(printf '%s' "$report_text" | grep 'CIS 2.3.1' | cut -d: -f2- | xargs)"
    printf 'CIS_2_4_1_APPLICATION_FIREWALL=%s\n' "$(printf '%s' "$report_text" | grep 'CIS 2.4.1' | cut -d: -f2- | xargs)"
    printf 'CIS_2_4_3_GATEKEEPER_STATUS=%s\n' "$(printf '%s' "$report_text" | grep 'Gatekeeper:' | cut -d: -f2- | xargs)"
    printf 'CIS_5_7_AUTOMATIC_UI_LOGIN_USER=%s\n' "$(printf '%s' "$report_text" | grep 'CIS 5.7 - Automatic UI Login User' | cut -d: -f2- | xargs)"
    printf 'CIS_1_1_AUTOMATIC_UPDATE_CHECK=%s\n' "$(printf '%s' "$report_text" | grep 'CIS 1.1' | cut -d: -f2- | xargs)"
    printf 'CIS_2_2_1_SCREEN_SAVER_TIMEOUT=%s\n' "$(printf '%s' "$report_text" | grep 'CIS 2.2.1' | cut -d: -f2- | xargs)"
} >> "$SNAPSHOT_FILE"
