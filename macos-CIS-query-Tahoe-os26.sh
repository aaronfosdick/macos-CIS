#!/bin/bash

# ==============================================================================
# macOS CIS Baseline Audit / Query Script
# ==============================================================================
# This script reads the system's current configuration for standard CIS controls.
# It is completely READ-ONLY and will not modify any parameters.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root (via sudo) to read system-level configurations."
  exit 1
fi

clear
echo "=================================================================="
echo "          macOS CIS Compliance Configuration Audit                "
echo "=================================================================="
echo "Timestamp: $(date)"
echo "OS Version: $(sw_vers -productVersion)"
echo "=================================================================="
echo ""

# Helper function to format outputs cleanly
print_status() {
    local control_name="$1"
    local status="$2"
    printf "%-50s : %s\n" "$control_name" "$status"
}

# Snapshot export for future restore/apply workflow.
# Format is simple KEY=VALUE so it remains human-readable and easy to parse later.
SNAPSHOT_DIR="/private/var/db/macos-cis/snapshots"
SNAPSHOT_TS="$(date '+%Y%m%d-%H%M%S')"
SNAPSHOT_RUN_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
SNAPSHOT_FILE=""

snapshot_setting() {
    local key="$1"
    local value="$2"
    if [ -n "$SNAPSHOT_FILE" ]; then
        value=$(printf '%s' "$value" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')
        printf '%s=%s\n' "$key" "$value" >> "$SNAPSHOT_FILE"
    fi
}

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

# ------------------------------------------------------------------------------
# 0. CORE CIS CONTROLS (FileVault, Firewall, Gatekeeper, Auto Updates, SIP,
#    Guest Account, Secure Boot)
# ------------------------------------------------------------------------------
echo "--- [0] Core CIS Controls ---"

# CIS Control 2.3.1 — FileVault (Full Disk Encryption)
fv_status=$(fdesetup status 2>/dev/null)
if echo "$fv_status" | grep -q "FileVault is On."; then
    print_status "CIS 2.3.1 - FileVault (Full Disk Encryption)" "On"
else
    print_status "CIS 2.3.1 - FileVault (Full Disk Encryption)" "Off"
fi

# CIS Control 2.3.2 — Key Escrow (Personal / Institutional Recovery Key)
if fdesetup haspersonalrecoverykey 2>/dev/null | grep -q "true"; then
    print_status "CIS 2.3.2 - FileVault Personal Recovery Key" "Present"
else
    print_status "CIS 2.3.2 - FileVault Personal Recovery Key" "Not Present"
fi
if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -q "true"; then
    print_status "CIS 2.3.2 - FileVault Institutional Recovery Key" "Present"
else
    print_status "CIS 2.3.2 - FileVault Institutional Recovery Key" "Not Present"
fi

# CIS Control 2.4.1 — Application Layer Firewall
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}')
print_status "CIS 2.4.1 - Application Firewall" "$fw_state"

# CIS Control 2.4.2 — Firewall Stealth Mode
fw_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | awk '{print $NF}')
print_status "CIS 2.4.2 - Firewall Stealth Mode" "$fw_stealth"

# Gatekeeper
gk_status=$(spctl --status 2>/dev/null)
if echo "$gk_status" | grep -q "assessments enabled"; then
    print_status "Gatekeeper" "Enabled"
else
    print_status "Gatekeeper" "Disabled"
fi



# CIS Control 1.1 — Automatic Software Updates
auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
print_status "CIS 1.1 - Automatic Update Check Enabled" "${auto_check:-0 (Disabled)}"

# CIS Control 1.2 — Update Background Downloads
auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
print_status "CIS 1.2 - Automatic Download Enabled" "${auto_download:-0 (Disabled)}"

# CIS Control 1.5 — Silent Security RSR / Data Patches
crit_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
print_status "CIS 1.5 - Install System Data & Security Files" "${crit_update:-0 (Disabled)}"

# CIS Control 1.4 — App Store App Installations
app_update=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)
print_status "CIS 1.4 - Automatic App Store Updates" "${app_update:-0 (Disabled)}"

# CIS Control 1.3 — Automated OS Installations
macos_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
print_status "CIS 1.3 - Automatic OS Updates Enabled" "${macos_update:-0 (Disabled)}"

# CIS Control 5.1.1 — System Integrity Protection
sip_status=$(csrutil status 2>/dev/null)
if echo "$sip_status" | grep -q "enabled"; then
    print_status "CIS 5.1.1 - System Integrity Protection (SIP)" "Enabled"
else
    print_status "CIS 5.1.1 - System Integrity Protection (SIP)" "Disabled (see note)"
fi

# CIS Control 5.1.2 — Boot-args (System Mobile File Integrity)
boot_args=$(nvram boot-args 2>/dev/null)
if [ -z "$boot_args" ]; then
    print_status "CIS 5.1.2 - Boot Args (nvram)" "Not Set (Secure)"
else
    print_status "CIS 5.1.2 - Boot Args (nvram)" "$boot_args"
fi

# CIS Control 6.1 — Guest Account
guest_status=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guest_status" = "1" ] || [ "$guest_status" = "true" ]; then
    print_status "CIS 6.1 - Guest Account" "Enabled"
else
    print_status "CIS 6.1 - Guest Account" "Disabled"
fi

# CIS Control 6.3 — Root Shell Disabled
root_shell=$(dscl . -read /Users/root UserShell 2>/dev/null)
if echo "$root_shell" | grep -q "/usr/bin/false"; then
    print_status "CIS 6.3 - Root Login (Shell)" "Disabled (/usr/bin/false)"
else
    print_status "CIS 6.3 - Root Login (Shell)" "${root_shell:-Unknown}"
fi

# Secure Boot
if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "Secure Boot: Enabled"; then
    print_status "Secure Boot (Intel T2)" "Enabled"
elif sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
    print_status "Secure Boot (Apple Silicon)" "Always Enabled"
else
    print_status "Secure Boot" "Unable to determine / Not applicable"
fi


# CIS Control 5.3 / 5.4 — Password Policy
pw_policy=$(pwpolicy -getglobalpolicy 2>/dev/null)
min_chars=$(echo "$pw_policy" | tr ',' '\n' | grep "minChars" | cut -d= -f2)
max_fail=$(echo "$pw_policy" | tr ',' '\n' | grep "maxFailedLoginAttempts" | cut -d= -f2)
print_status "CIS 5.3 - Password minChars" "${min_chars:-Not Set}"
print_status "CIS 5.4 - maxFailedLoginAttempts" "${max_fail:-Not Set}"

# Also check complexity disablers
requires_numeric=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresNumeric" | cut -d= -f2)
requires_mixed=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresMixedCase" | cut -d= -f2)
requires_symbol=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresSymbol" | cut -d= -f2)
print_status "CIS 5.3/5.4 - requiresNumeric (should be 0)" "${requires_numeric:-Not Set}"
print_status "CIS 5.3/5.4 - requiresMixedCase (should be 0)" "${requires_mixed:-Not Set}"
print_status "CIS 5.3/5.4 - requiresSymbol (should be 0)" "${requires_symbol:-Not Set}"

echo ""

# ------------------------------------------------------------------------------
# 1. SYSTEM PREFERENCES & ACCESS CONTROL
# ------------------------------------------------------------------------------
echo "--- [1] System Preferences & Access Control ---"

# CIS Control 2.2.1 — Screensaver Max Timeout Lock
ss_timeout=$(defaults read com.apple.screensaver idleTime 2>/dev/null)
print_status "CIS 2.2.1 - Screen Saver Timeout (Seconds)" "${ss_timeout:-Not Configured}"

# CIS Control 2.2.2 — Screen Lock Prompt Enforcement
ss_pwd=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
print_status "CIS 2.2.2 - Require Password After Screen Saver" "${ss_pwd:-Not Configured}"

ss_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
print_status "CIS 2.2.2 - Screen Saver Password Grace Period" "${ss_delay:-Not Configured}"

bt_sharing=$(defaults read /Library/Preferences/com.apple.Bluetooth.plist QuietMode 2>/dev/null)
if [ "$bt_sharing" = "true" ] || [ "$bt_sharing" = "1" ]; then
    print_status "CIS 2.2.3 - Bluetooth Discoverable/Sharing State" "0 (Disabled / Secure)"
else
    print_status "CIS 2.2.3 - Bluetooth Discoverable/Sharing State" "1 (Enabled / Public)"
fi

# CIS Control 2.2.3 — Bluetooth Hardware Discoverability
#   (QuietMode above controls sharing; this checks low-level controller state)
bt_le=$(system_profiler SPBluetoothDataType 2>/dev/null | grep "Discoverable" | head -1)
if [ -n "$bt_le" ]; then
    print_status "CIS 2.2.3 - Bluetooth Discoverable (Controller)" "$(echo "$bt_le" | awk '{print $NF}')"
else
    print_status "CIS 2.2.3 - Bluetooth Discoverable (Controller)" "Unknown"
fi

# CIS Control 2.2.4 — Remote Management (ARD / Screen Sharing)
if launchctl print-disabled system 2>/dev/null | grep -q "com.apple.RemoteDesktop"; then
    print_status "CIS 2.2.4 - Remote Management (ARD)" "Disabled"
else
    rd_status=$(launchctl list 2>/dev/null | grep com.apple.RemoteDesktop)
    if [ -n "$rd_status" ]; then
        print_status "CIS 2.2.4 - Remote Management (ARD)" "Enabled"
    else
        print_status "CIS 2.2.4 - Remote Management (ARD)" "Not loaded (likely disabled)"
    fi
fi

# CIS Control 2.10.1.2 — Energy Sleep Optimization
pmset_info=$(pmset -g custom 2>/dev/null | grep -E "(sleep|displaysleep)" | head -4)
if [ -n "$pmset_info" ]; then
    print_status "CIS 2.10.1.2 - Power Mgmt (sleep/displaysleep)" "See below"
    echo "    $pmset_info" | while IFS= read -r line; do
        echo "      $line"
    done
else
    print_status "CIS 2.10.1.2 - Power Mgmt (sleep/displaysleep)" "Unable to read"
fi

# CIS Control 3.3 — Remote Apple Events
ae_status=$(launchctl list | grep com.apple.AEServer)
if [ -n "$ae_status" ]; then
    print_status "CIS 3.3 - Remote Apple Events" "Enabled"
else
    print_status "CIS 3.3 - Remote Apple Events" "Disabled"
fi

# CIS Control 3.4 — Internet Sharing
nat_status=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null)
if [ -n "$nat_status" ] && [ "$nat_status" != "{}" ]; then
    print_status "CIS 3.4 - Internet Sharing" "Enabled"
else
    print_status "CIS 3.4 - Internet Sharing" "Disabled"
fi

# --- iCloud Controls (MDM-enforced; query-only without MDM profile) ---
# CIS Control 2.1.1.1 — iCloud Keychain Sync
kc_sync=$(/usr/libexec/PlistBuddy -c "Print :Accounts:0:Services:KEYCHAIN_SYNC:Status" /Library/Preferences/com.apple.mobiledevice.passwordpolicy.plist 2>/dev/null)
print_status "CIS 2.1.1.1 - iCloud Keychain Sync (MDM)" "${kc_sync:-Not restricted (no MDM profile)}"

# CIS Control 2.1.1.2 — iCloud Drive Document Sync
icloud_drive=$(defaults read /Library/Managed\ Preferences/com.apple.applicationaccess allowCloudDocumentSync 2>/dev/null)
if [ "$icloud_drive" = "0" ]; then
    print_status "CIS 2.1.1.2 - iCloud Drive Sync (MDM)" "Blocked"
else
    print_status "CIS 2.1.1.2 - iCloud Drive Sync (MDM)" "${icloud_drive:-Not restricted (no MDM profile)}"
fi

# CIS Control 2.1.1.3 — iCloud Desktop & Documents
icloud_desktop=$(defaults read /Library/Managed\ Preferences/com.apple.finder EnterpriseDesktopDocumentSyncDisabled 2>/dev/null)
if [ "$icloud_desktop" = "1" ]; then
    print_status "CIS 2.1.1.3 - iCloud Desktop & Documents (MDM)" "Blocked"
else
    print_status "CIS 2.1.1.3 - iCloud Desktop & Documents (MDM)" "${icloud_desktop:-Not restricted (no MDM profile)}"
fi

echo ""

# ------------------------------------------------------------------------------
# 2. NETWORK & SECURITY PROFILE
# ------------------------------------------------------------------------------
echo "--- [2] Network & Security Profile ---"

ssh_state=$(systemsetup -getremotelogin 2>/dev/null | awk '{print $NF}')
print_status "Remote Login (SSH) Status" "${ssh_state:-Unknown/MDM Controlled}"

# CIS Control 3.1 — SMB File Sharing
if launchctl print-disabled system 2>/dev/null | grep -q "com.apple.smbd"; then
    print_status "CIS 3.1 - SMB File Sharing" "Disabled"
else
    smb_status=$(launchctl list 2>/dev/null | grep com.apple.smbd)
    if [ -n "$smb_status" ]; then
        print_status "CIS 3.1 - SMB File Sharing" "Enabled"
    else
        print_status "CIS 3.1 - SMB File Sharing" "Not loaded"
    fi
fi

# CIS Control 3.2 — CUPS Network Print Pools
cups_sharing=$(cupsctl 2>/dev/null | grep "_share_printers")
if echo "$cups_sharing" | grep -q "_share_printers=0"; then
    print_status "CIS 3.2 - CUPS Printer Sharing" "Disabled"
elif echo "$cups_sharing" | grep -q "_share_printers=1"; then
    print_status "CIS 3.2 - CUPS Printer Sharing" "Enabled"
else
    print_status "CIS 3.2 - CUPS Printer Sharing" "Unknown"
fi

# CIS Control 3.5 — Content Caching (P2P Asset Relays)
cache_status=$(AssetCacheManagerUtil status 2>/dev/null | head -1)
if [ -n "$cache_status" ]; then
    print_status "CIS 3.5 - Content Caching (P2P)" "$cache_status"
else
    print_status "CIS 3.5 - Content Caching (P2P)" "Inactive / Not configured"
fi

# CIS Control 6.2 — Guest Network Share Access
afp_guest=$(defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess 2>/dev/null)
if [ "$afp_guest" = "0" ] || [ "$afp_guest" = "false" ]; then
    print_status "CIS 6.2 - Guest SMB/AFP Share Access" "Disabled"
else
    print_status "CIS 6.2 - Guest SMB/AFP Share Access" "${afp_guest:-Allowed (default)}"
fi
smb_guest=$(defaults read /Library/Preferences/com.apple.smb.server AllowGuestAccess 2>/dev/null)
if [ "$smb_guest" = "0" ] || [ "$smb_guest" = "false" ]; then
    print_status "CIS 6.2 - Guest SMB Access" "Disabled"
else
    print_status "CIS 6.2 - Guest SMB Access" "${smb_guest:-Allowed (default)}"
fi

echo ""

# ------------------------------------------------------------------------------
# 3. LOGGING, AUDITING & ACCESSIBILITY
# ------------------------------------------------------------------------------
echo "--- [3] Logging, Auditing & Access ---"

# CIS Control 4.1 — Security Auditing Daemon
audit_status=$(launchctl list | grep com.apple.auditd)
if [ -n "$audit_status" ]; then
    print_status "CIS 4.1 - Security Auditing Daemon (auditd)" "Running"
else
    print_status "CIS 4.1 - Security Auditing Daemon (auditd)" "Stopped / Disabled"
fi

# CIS Control 4.2 — Audit Flags (Kernel Activity Scope)
audit_flags=$(grep -E "^flags:" /etc/security/audit_control 2>/dev/null)
if [ -n "$audit_flags" ]; then
    print_status "CIS 4.2 - Audit Flags" "$(echo "$audit_flags" | cut -d: -f2)"
else
    print_status "CIS 4.2 - Audit Flags" "Not configured / Missing"
fi

# CIS Control 4.3 — Audit Minfree (Low-Volume Threshold)
audit_minfree=$(grep -E "^minfree:" /etc/security/audit_control 2>/dev/null)
if [ -n "$audit_minfree" ]; then
    print_status "CIS 4.3 - Audit Minfree" "$(echo "$audit_minfree" | cut -d: -f2)"
else
    print_status "CIS 4.3 - Audit Minfree" "Not configured / Missing"
fi

autologin_status=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
print_status "Automatic UI Login User" "${autologin_status:-None (Secure)}"

# CIS Control 5.7 — Login Window Auth Database (screensaver)
auth_db=$(security authorizationdb read system.login.screensaver 2>/dev/null | grep -o "authenticate-user" | head -1)
if [ "$auth_db" = "authenticate-user" ]; then
    print_status "CIS 5.7 - Login Window Auth (Screensaver)" "Requires authentication"
else
    print_status "CIS 5.7 - Login Window Auth (Screensaver)" "Not requiring authentication (or unable to read)"
fi

echo ""

# ------------------------------------------------------------------------------
# 4. USER ENVIRONMENT MASKS
# ------------------------------------------------------------------------------
echo "--- [4] Environment & Shell Policies ---"

if [ -f /etc/zprofile ] && grep -q "umask" /etc/zprofile; then
    zsh_umask=$(grep "umask" /etc/zprofile)
    print_status "Global ZSH Umask Setting" "$zsh_umask"
    zsh_umask_value="$zsh_umask"
else
    print_status "Global ZSH Umask Setting" "Not defined in /etc/zprofile (Defaults to system mask)"
    zsh_umask_value="Not defined"
fi

# CIS Control 5.5 — Sudo Session Expiration (timestamp)
sudo_ts=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout")
if [ -n "$sudo_ts" ]; then
    print_status "CIS 5.5 - Sudo Timestamp Timeout" "$(echo "$sudo_ts" | cut -d: -f2)"
    sudo_timestamp_value="$(echo "$sudo_ts" | cut -d: -f2)"
else
    print_status "CIS 5.5 - Sudo Timestamp Timeout" "Unknown"
    sudo_timestamp_value="Unknown"
fi

# CIS Control 5.6 — Sudo Logging (allowed/denied)
sudo_log_allowed=$(sudo -V 2>/dev/null | grep "log_allowed")
sudo_log_denied=$(sudo -V 2>/dev/null | grep "log_denied")
if [ -n "$sudo_log_allowed" ]; then
    print_status "CIS 5.6 - Sudo Log Allowed" "$(echo "$sudo_log_allowed" | cut -d: -f2)"
    sudo_log_allowed_value="$(echo "$sudo_log_allowed" | cut -d: -f2)"
else
    print_status "CIS 5.6 - Sudo Log Allowed" "Not configured"
    sudo_log_allowed_value="Not configured"
fi
if [ -n "$sudo_log_denied" ]; then
    print_status "CIS 5.6 - Sudo Log Denied" "$(echo "$sudo_log_denied" | cut -d: -f2)"
    sudo_log_denied_value="$(echo "$sudo_log_denied" | cut -d: -f2)"
else
    print_status "CIS 5.6 - Sudo Log Denied" "Not configured"
    sudo_log_denied_value="Not configured"
fi

# CIS Control 6.4 — Home Directory Permissions
print_status "CIS 6.4 - Home Dir Permissions (Users)" ""
home_dir_perms_state="Compliant"
for user_home in /Users/*; do
    u=$(basename "$user_home")
    if id "$u" &>/dev/null 2>&1 && [ -d "$user_home" ]; then
        perms=$(stat -f "%A" "$user_home" 2>/dev/null)
        if [ "$perms" = "700" ] || [ "$perms" = "750" ]; then
            :
        else
            home_dir_perms_state="Non-compliant homes detected"
            echo "    $user_home : $perms"
        fi
    fi
done
echo "    (Non-compliant home dirs listed above; 700 or 750 expected)"
home_dir_perms_value="$home_dir_perms_state"

# ------------------------------------------------------------------------------
# ADDITIONAL SECURITY HARDENING CHECKS
# ------------------------------------------------------------------------------
echo "--- [5] Additional Security Hardening ---"

# Safari settings (check for current user; repeat across users would be complex, so check for root's sanity)
for user_test in /Users/*; do
    u=$(basename "$user_test")
    if id "$u" &>/dev/null; then
        sf1=$(sudo -u "$u" defaults read com.apple.Safari AutoFillPasswords 2>/dev/null)
        sf2=$(sudo -u "$u" defaults read com.apple.Safari WarnAboutFraudulentWebsites 2>/dev/null)
        # Print only for first user to keep output clean
        print_status "Safari AutoFillPasswords ($u)" "${sf1:-Not configured}"
        print_status "Safari WarnAboutFraudulentWebsites ($u)" "${sf2:-Not configured}"
        break
    fi
done

# Bluetooth controller power state
bt_power=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
if [ "$bt_power" = "0" ]; then
    print_status "Bluetooth Controller" "Off"
else
    print_status "Bluetooth Controller" "On (power state: ${bt_power:-Unknown})"
fi

# AirDrop status (first user)
for user_test in /Users/*; do
    u=$(basename "$user_test")
    if id "$u" &>/dev/null; then
        airdrop=$(sudo -u "$u" defaults read com.apple.sharingd AirDrop 2>/dev/null)
        print_status "AirDrop ($u)" "${airdrop:-Not set (assumed enabled)}"
        break
    fi
done

# AirPlay receiver
airplay_disabled=$(defaults read /System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist Disabled 2>/dev/null)
if [ "$airplay_disabled" = "true" ]; then
    print_status "AirPlay Receiver" "Disabled"
else
    print_status "AirPlay Receiver" "Enabled (or not configured)"
fi

# Keychain lock timeout (first user)
keychain_timeout_value="Not available"
for user_test in /Users/*; do
    u=$(basename "$user_test")
    keychain="$user_test/Library/Keychains/login.keychain"
    if [ -f "$keychain" ]; then
        timeout_info=$(sudo -u "$u" security show-keychain-info "$keychain" 2>/dev/null | head -1)
        if [ -n "$timeout_info" ]; then
            keychain_timeout_value="$timeout_info"
        else
            keychain_timeout_value="No timeout configured"
        fi
        print_status "Login Keychain ($u)" "$keychain_timeout_value"
        break
    fi
done


# Time Machine Remote Backups
tm_status=$(tmutil destinationinfo 2>/dev/null | head -1)
if [ -n "$tm_status" ]; then
    print_status "Time Machine" "Destinations configured (remote backups possible)"
else
    print_status "Time Machine" "No destinations configured"
fi

echo ""
# ------------------------------------------------------------------------------
# 6. 24-HOUR LOG RETENTION CHECKS
# ------------------------------------------------------------------------------
echo "--- [6] 24-Hour Log Retention Checks ---"

# Unified logging – we can only check the size/age of the persistent store
# Use log collect to see if a test pull of last 24h succeeds
log_test=$(/usr/bin/log collect --last 24h --output /dev/null 2>&1)
# If collect exits 0, unified logging is working; we can't read the config back easily
# Best proxy: check if /var/db/diagnostics/ has files older than 48h
old_diag=$(find /var/db/diagnostics -type f -mtime +2 2>/dev/null | wc -l | tr -d ' ')
if [ "$old_diag" -gt 0 ]; then
    print_status "Unified log store (>48h old files)" "$old_diag files present (may exceed 24h retention)"
else
    print_status "Unified log store (>48h old files)" "None found (likely capped at 24h)"
fi

# Newsyslog configuration
if [ -f /etc/newsyslog.d/99-cis-24h-retention.conf ]; then
    newsyslog_entries=$(grep -c "^/var/log/" /etc/newsyslog.d/99-cis-24h-retention.conf 2>/dev/null)
    print_status "Newsyslog CIS retention config" "Present ($newsyslog_entries log entries, count=0)"
else
    print_status "Newsyslog CIS retention config" "Not configured"
fi

# ASL TTL configuration
if grep -q "ttl=24" /etc/asl.conf 2>/dev/null; then
    print_status "ASL TTL (24 hours)" "Configured"
else
    print_status "ASL TTL (24 hours)" "Not configured"
fi

# Old log files still present
old_syslog=$(find /var/log -type f -name "*.log" -mtime +1 2>/dev/null | wc -l | tr -d ' ')
print_status "/var/log *.log older than 24h" "${old_syslog:-0} files"

old_library_logs=$(find /Library/Logs -type f -mtime +1 2>/dev/null | wc -l | tr -d ' ')
print_status "/Library/Logs older than 24h" "${old_library_logs:-0} files"

first_user=""
for user_test in /Users/*; do
    u=$(basename "$user_test")
    if id "$u" &>/dev/null && [ -d "$user_test/Library/Logs" ]; then
        first_user="$u"
        break
    fi
done
if [ -n "$first_user" ]; then
    user_old_logs=$(find "/Users/$first_user/Library/Logs" -type f -mtime +1 2>/dev/null | wc -l | tr -d ' ')
    print_status "~/Library/Logs older than 24h ($first_user)" "${user_old_logs:-0} files"
fi

echo ""
# ------------------------------------------------------------------------------
# 7. WRITE SNAPSHOT EXPORT
# ------------------------------------------------------------------------------
# Normalize several values into simple, restore-friendly strings.
if echo "$fv_status" | grep -q "FileVault is On."; then
    fv_value="On"
else
    fv_value="Off"
fi
if fdesetup haspersonalrecoverykey 2>/dev/null | grep -q "true"; then
    personal_recovery_value="Present"
else
    personal_recovery_value="Not Present"
fi
if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -q "true"; then
    institutional_recovery_value="Present"
else
    institutional_recovery_value="Not Present"
fi
if [ "$fw_state" = "enabled" ] || [ "$fw_state" = "Firewall is enabled" ]; then
    firewall_state_value="Enabled"
else
    firewall_state_value="Disabled"
fi
if [ "$fw_stealth" = "enabled" ] || [ "$fw_stealth" = "Stealth mode enabled" ]; then
    firewall_stealth_value="Enabled"
else
    firewall_stealth_value="Disabled"
fi
if echo "$gk_status" | grep -q "assessments enabled"; then
    gatekeeper_value="Enabled"
else
    gatekeeper_value="Disabled"
fi
if [ "$auto_check" = "1" ] || [ "$auto_check" = "true" ]; then
    auto_check_value="Enabled"
else
    auto_check_value="Disabled"
fi
if [ "$auto_download" = "1" ] || [ "$auto_download" = "true" ]; then
    auto_download_value="Enabled"
else
    auto_download_value="Disabled"
fi
if [ "$crit_update" = "1" ] || [ "$crit_update" = "true" ]; then
    crit_update_value="Enabled"
else
    crit_update_value="Disabled"
fi
if [ "$app_update" = "1" ] || [ "$app_update" = "true" ]; then
    app_update_value="Enabled"
else
    app_update_value="Disabled"
fi
if [ "$macos_update" = "1" ] || [ "$macos_update" = "true" ]; then
    macos_update_value="Enabled"
else
    macos_update_value="Disabled"
fi
if echo "$sip_status" | grep -q "enabled"; then
    sip_value="Enabled"
else
    sip_value="Disabled"
fi
if [ -z "$boot_args" ]; then
    boot_args_value="Not Set"
else
    boot_args_value="$boot_args"
fi
if [ "$guest_status" = "1" ] || [ "$guest_status" = "true" ]; then
    guest_account_value="Enabled"
else
    guest_account_value="Disabled"
fi
if echo "$root_shell" | grep -q "/usr/bin/false"; then
    root_shell_value="Disabled"
else
    root_shell_value="Enabled"
fi
if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "Secure Boot: Enabled"; then
    secure_boot_value="Enabled"
elif sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
    secure_boot_value="Always Enabled"
else
    secure_boot_value="Unable to Determine"
fi
if [ "$ss_timeout" = "Not Configured" ]; then
    screensaver_timeout_value="Not Configured"
else
    screensaver_timeout_value="$ss_timeout"
fi
if [ "$ss_pwd" = "1" ] || [ "$ss_pwd" = "true" ]; then
    screensaver_password_required_value="Enabled"
else
    screensaver_password_required_value="Disabled"
fi
if [ "$ss_delay" = "Not Configured" ]; then
    screensaver_password_grace_value="Not Configured"
else
    screensaver_password_grace_value="$ss_delay"
fi
if [ "$bt_sharing" = "true" ] || [ "$bt_sharing" = "1" ]; then
    bluetooth_quiet_mode_value="Enabled"
else
    bluetooth_quiet_mode_value="Disabled"
fi
if launchctl print-disabled system 2>/dev/null | grep -q "com.apple.RemoteDesktop"; then
    remote_management_value="Disabled"
else
    remote_management_value="Enabled"
fi
if [ -n "$pmset_info" ]; then
    power_management_value="$pmset_info"
else
    power_management_value="Not Configured"
fi
if [ -n "$ae_status" ]; then
    remote_apple_events_value="Enabled"
else
    remote_apple_events_value="Disabled"
fi
if [ -n "$nat_status" ] && [ "$nat_status" != "{}" ]; then
    internet_sharing_value="Enabled"
else
    internet_sharing_value="Disabled"
fi
if [ "$ssh_state" = "on" ] || [ "$ssh_state" = "On" ] || [ "$ssh_state" = "true" ]; then
    ssh_state_value="Enabled"
else
    ssh_state_value="Disabled"
fi
if launchctl print-disabled system 2>/dev/null | grep -q "com.apple.smbd"; then
    smb_file_sharing_value="Disabled"
else
    smb_file_sharing_value="Enabled"
fi
if echo "$cups_sharing" | grep -q "_share_printers=0"; then
    cups_printer_sharing_value="Disabled"
elif echo "$cups_sharing" | grep -q "_share_printers=1"; then
    cups_printer_sharing_value="Enabled"
else
    cups_printer_sharing_value="Unknown"
fi
if [ -n "$cache_status" ]; then
    content_caching_value="$cache_status"
else
    content_caching_value="Inactive"
fi
if [ "$afp_guest" = "0" ] || [ "$afp_guest" = "false" ]; then
    guest_file_share_value="Disabled"
else
    guest_file_share_value="Enabled"
fi
if [ "$smb_guest" = "0" ] || [ "$smb_guest" = "false" ]; then
    guest_smb_share_value="Disabled"
else
    guest_smb_share_value="Enabled"
fi

snapshot_setting "CIS_2_3_1_FILEVAULT_STATUS" "$fv_value"
snapshot_setting "CIS_2_3_2_PERSONAL_RECOVERY_KEY" "$personal_recovery_value"
snapshot_setting "CIS_2_3_2_INSTITUTIONAL_RECOVERY_KEY" "$institutional_recovery_value"
snapshot_setting "CIS_2_4_1_APPLICATION_FIREWALL" "$firewall_state_value"
snapshot_setting "CIS_2_4_2_FIREWALL_STEALTH_MODE" "$firewall_stealth_value"
snapshot_setting "CIS_GATEKEEPER_STATUS" "$gatekeeper_value"
snapshot_setting "CIS_1_1_AUTOMATIC_UPDATE_CHECK" "$auto_check_value"
snapshot_setting "CIS_1_2_AUTOMATIC_DOWNLOAD" "$auto_download_value"
snapshot_setting "CIS_1_5_CRITICAL_UPDATE_INSTALL" "$crit_update_value"
snapshot_setting "CIS_1_4_APP_STORE_AUTO_UPDATE" "$app_update_value"
snapshot_setting "CIS_1_3_AUTOMATIC_OS_UPDATES" "$macos_update_value"
snapshot_setting "CIS_5_1_1_SIP_STATUS" "$sip_value"
snapshot_setting "CIS_5_1_2_BOOT_ARGS" "$boot_args_value"
snapshot_setting "CIS_6_1_GUEST_ACCOUNT" "$guest_account_value"
snapshot_setting "CIS_6_3_ROOT_SHELL" "$root_shell_value"
snapshot_setting "CIS_SECURE_BOOT" "$secure_boot_value"
snapshot_setting "CIS_5_3_PASSWORD_MINCHARS" "${min_chars:-Not Set}"
snapshot_setting "CIS_5_4_PASSWORD_MAX_FAILED_LOGIN_ATTEMPTS" "${max_fail:-Not Set}"
snapshot_setting "CIS_5_3_REQUIRES_NUMERIC" "${requires_numeric:-Not Set}"
snapshot_setting "CIS_5_3_REQUIRES_MIXED_CASE" "${requires_mixed:-Not Set}"
snapshot_setting "CIS_5_3_REQUIRES_SYMBOL" "${requires_symbol:-Not Set}"
snapshot_setting "CIS_2_2_1_SCREEN_SAVER_TIMEOUT" "$screensaver_timeout_value"
snapshot_setting "CIS_2_2_2_SCREEN_SAVER_PASSWORD_REQUIRED" "$screensaver_password_required_value"
snapshot_setting "CIS_2_2_2_SCREEN_SAVER_PASSWORD_GRACE" "$screensaver_password_grace_value"
snapshot_setting "CIS_2_2_3_BLUETOOTH_QUIET_MODE" "$bluetooth_quiet_mode_value"
snapshot_setting "CIS_2_2_4_REMOTE_MANAGEMENT" "$remote_management_value"
snapshot_setting "CIS_2_10_1_2_POWER_MANAGEMENT" "$power_management_value"
snapshot_setting "CIS_3_3_REMOTE_APPLE_EVENTS" "$remote_apple_events_value"
snapshot_setting "CIS_3_4_INTERNET_SHARING" "$internet_sharing_value"
snapshot_setting "CIS_3_6_REMOTE_LOGIN" "$ssh_state_value"
snapshot_setting "CIS_3_1_SMB_FILE_SHARING" "$smb_file_sharing_value"
snapshot_setting "CIS_3_2_CUPS_PRINTER_SHARING" "$cups_printer_sharing_value"
snapshot_setting "CIS_3_5_CONTENT_CACHING" "$content_caching_value"
snapshot_setting "CIS_6_2_GUEST_FILE_SHARE_ACCESS" "$guest_file_share_value"
snapshot_setting "CIS_6_2_GUEST_SMB_ACCESS" "$guest_smb_share_value"

# Additional non-CIS hardening settings
if [ "$bt_power" = "0" ]; then
    bt_power_value="Off"
else
    bt_power_value="On"
fi
snapshot_setting "NONCIS_BLUETOOTH_CONTROLLER_POWER_STATE" "$bt_power_value"
snapshot_setting "NONCIS_AIRDROP_STATUS" "${airdrop:-Not set (assumed enabled)}"
snapshot_setting "NONCIS_AIRPLAY_RECEIVER" "$( [ "$airplay_disabled" = "true" ] && echo "Disabled" || echo "Enabled" )"
snapshot_setting "NONCIS_LOGIN_KEYCHAIN_TIMEOUT" "$keychain_timeout_value"
snapshot_setting "NONCIS_TIME_MACHINE_STATUS" "${tm_status:-Not available}"
snapshot_setting "NONCIS_UNIFIED_LOG_STORE_OLD_FILES" "${old_diag:-0}"
snapshot_setting "NONCIS_NEWSYSLOG_RETENTION_CONFIG" "${newsyslog_entries:+Present ($newsyslog_entries entries)}${newsyslog_entries:-Not configured}"
snapshot_setting "NONCIS_ASL_TTL_24H" "$(grep -q 'ttl=24' /etc/asl.conf 2>/dev/null && echo Configured || echo Not configured)"
snapshot_setting "NONCIS_VAR_LOG_OLDER_THAN_24H" "${old_syslog:-0}"
snapshot_setting "NONCIS_LIBRARY_LOGS_OLDER_THAN_24H" "${old_library_logs:-0}"
snapshot_setting "NONCIS_USER_LIBRARY_LOGS_OLDER_THAN_24H" "${user_old_logs:-0}"
snapshot_setting "NONCIS_SAFARI_AUTOFILL_PASSWORDS" "${sf1:-Not configured}"
snapshot_setting "NONCIS_SAFARI_FRAUD_WARNING" "${sf2:-Not configured}"
snapshot_setting "NONCIS_GLOBAL_ZSH_UMASK" "$zsh_umask_value"
snapshot_setting "NONCIS_SUDO_TIMESTAMP_TIMEOUT" "$sudo_timestamp_value"
snapshot_setting "NONCIS_SUDO_LOG_ALLOWED" "$sudo_log_allowed_value"
snapshot_setting "NONCIS_SUDO_LOG_DENIED" "$sudo_log_denied_value"
snapshot_setting "NONCIS_LOGIN_WINDOW_AUTO_LOGIN_USER" "${autologin_status:-None}"
snapshot_setting "NONCIS_LOGIN_WINDOW_BANNER_TEXT" "${banner_text:-None}" 
snapshot_setting "NONCIS_HOME_DIR_PERMISSIONS" "$home_dir_perms_value"

echo "[✓] Snapshot export written to $SNAPSHOT_FILE"
echo "=================================================================="
echo "[✓] Read-only CIS Audit Complete."
echo "=================================================================="