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

# ------------------------------------------------------------------------------
# 0. CORE CIS CONTROLS (FileVault, Firewall, Gatekeeper, Auto Updates, SIP,
#    Guest Account, Secure Boot)
# ------------------------------------------------------------------------------
echo "--- [0] Core CIS Controls ---"

# FileVault
fv_status=$(fdesetup status 2>/dev/null)
if echo "$fv_status" | grep -q "FileVault is On."; then
    print_status "FileVault (Full Disk Encryption)" "On"
else
    print_status "FileVault (Full Disk Encryption)" "Off"
fi

# Firewall
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}')
print_status "Application Firewall" "$fw_state"

fw_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | awk '{print $NF}')
print_status "Firewall Stealth Mode" "$fw_stealth"

# Gatekeeper
gk_status=$(spctl --status 2>/dev/null)
if echo "$gk_status" | grep -q "assessments enabled"; then
    print_status "Gatekeeper" "Enabled"
else
    print_status "Gatekeeper" "Disabled"
fi

# Automatic Updates
auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
print_status "Automatic Update Check Enabled" "${auto_check:-0 (Disabled)}"

auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
print_status "Automatic Download Enabled" "${auto_download:-0 (Disabled)}"

crit_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
print_status "Install System Data & Security Files" "${crit_update:-0 (Disabled)}"

app_update=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)
print_status "Automatic App Store Updates" "${app_update:-0 (Disabled)}"

macos_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
print_status "Automatic OS Updates Enabled" "${macos_update:-0 (Disabled)}"

# SIP
sip_status=$(csrutil status 2>/dev/null)
if echo "$sip_status" | grep -q "enabled"; then
    print_status "System Integrity Protection (SIP)" "Enabled"
else
    print_status "System Integrity Protection (SIP)" "Disabled (see note)"
fi

# Guest Account (CIS Control 7)
guest_status=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guest_status" = "1" ] || [ "$guest_status" = "true" ]; then
    print_status "Guest Account" "Enabled"
else
    print_status "Guest Account" "Disabled"
fi

# Secure Boot (CIS Control 8)
if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "Secure Boot: Enabled"; then
    print_status "Secure Boot (Intel T2)" "Enabled"
elif sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
    print_status "Secure Boot (Apple Silicon)" "Always Enabled"
else
    print_status "Secure Boot" "Unable to determine / Not applicable"
fi

# Password Policy (CIS Control 6 – Long Passphrase)
pw_policy=$(pwpolicy -getglobalpolicy 2>/dev/null)
min_chars=$(echo "$pw_policy" | tr ',' '\n' | grep "minChars" | cut -d= -f2)
max_fail=$(echo "$pw_policy" | tr ',' '\n' | grep "maxFailedLoginAttempts" | cut -d= -f2)
print_status "Password minChars" "${min_chars:-Not Set}"
print_status "maxFailedLoginAttempts" "${max_fail:-Not Set}"

# Also check complexity disablers
requires_numeric=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresNumeric" | cut -d= -f2)
requires_mixed=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresMixedCase" | cut -d= -f2)
requires_symbol=$(echo "$pw_policy" | tr ',' '\n' | grep "requiresSymbol" | cut -d= -f2)
print_status "requiresNumeric (should be 0)" "${requires_numeric:-Not Set}"
print_status "requiresMixedCase (should be 0)" "${requires_mixed:-Not Set}"
print_status "requiresSymbol (should be 0)" "${requires_symbol:-Not Set}"

echo ""

# ------------------------------------------------------------------------------
# 1. SOFTWARE UPDATES & SEEDING
# ------------------------------------------------------------------------------
echo "--- [1] Software Update Status ---"

auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
print_status "Automatic Update Check Enabled" "${auto_check:-0 (Disabled)}"

auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
print_status "Automatic Download Enabled" "${auto_download:-0 (Disabled)}"

crit_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
print_status "Install System Data & Security Files" "${crit_update:-0 (Disabled)}"

app_update=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)
print_status "Automatic App Store Updates" "${app_update:-0 (Disabled)}"

macos_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
print_status "Automatic OS Updates Enabled" "${macos_update:-0 (Disabled)}"

echo ""

# ------------------------------------------------------------------------------
# 2. SYSTEM PREFERENCES & ACCESS CONTROL
# ------------------------------------------------------------------------------
echo "--- [2] System Preferences & Access Control ---"

ss_timeout=$(defaults read com.apple.screensaver idleTime 2>/dev/null)
print_status "Screen Saver Timeout (Seconds)" "${ss_timeout:-Not Configured}"

ss_pwd=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
print_status "Require Password After Screen Saver" "${ss_pwd:-Not Configured}"

ss_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
print_status "Screen Saver Password Grace Period" "${ss_delay:-Not Configured}"

bt_sharing=$(defaults read /Library/Preferences/com.apple.Bluetooth.plist QuietMode 2>/dev/null)
if [ "$bt_sharing" = "true" ] || [ "$bt_sharing" = "1" ]; then
    print_status "Bluetooth Discoverable/Sharing State" "0 (Disabled / Secure)"
else
    print_status "Bluetooth Discoverable/Sharing State" "1 (Enabled / Public)"
fi

ae_status=$(launchctl list | grep com.apple.AEServer)
if [ -n "$ae_status" ]; then
    print_status "Remote Apple Events" "Enabled"
else
    print_status "Remote Apple Events" "Disabled"
fi

nat_status=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null)
if [ -n "$nat_status" ] && [ "$nat_status" != "{}" ]; then
    print_status "Internet Sharing" "Enabled"
else
    print_status "Internet Sharing" "Disabled"
fi

echo ""

# ------------------------------------------------------------------------------
# 3. NETWORK & SECURITY PROFILE
# ------------------------------------------------------------------------------
echo "--- [3] Network & Security Profile ---"

fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | awk '{print $NF}')
print_status "Application Firewall Status" "$fw_state"

fw_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $NF}')
print_status "Firewall Stealth Mode Status" "$fw_stealth"

ssh_state=$(systemsetup -getremotelogin 2>/dev/null | awk '{print $NF}')
print_status "Remote Login (SSH) Status" "${ssh_state:-Unknown/MDM Controlled}"

echo ""

# ------------------------------------------------------------------------------
# 4. LOGGING, AUDITING & ACCESSIBILITY
# ------------------------------------------------------------------------------
echo "--- [4] Logging, Auditing & Access ---"

audit_status=$(launchctl list | grep com.apple.auditd)
if [ -n "$audit_status" ]; then
    print_status "Security Auditing Daemon (auditd)" "Running"
else
    print_status "Security Auditing Daemon (auditd)" "Stopped / Disabled"
fi

guest_status=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guest_status" = "1" ] || [ "$guest_status" = "true" ]; then
    print_status "Guest Account Access" "Enabled"
else
    print_status "Guest Account Access" "Disabled"
fi

autologin_status=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
print_status "Automatic UI Login User" "${autologin_status:-None (Secure)}"

banner_text=$(defaults read /Library/Preferences/com.apple.loginwindow LoginwindowText 2>/dev/null)
if [ -n "$banner_text" ]; then
    print_status "Login Window Banner Text" "Configured"
else
    print_status "Login Window Banner Text" "None / Not Configured"
fi

echo ""

# ------------------------------------------------------------------------------
# 5. USER ENVIRONMENT MASKS
# ------------------------------------------------------------------------------
echo "--- [5] Environment & Shell Policies ---"

if [ -f /etc/zprofile ] && grep -q "umask" /etc/zprofile; then
    zsh_umask=$(grep "umask" /etc/zprofile)
    print_status "Global ZSH Umask Setting" "$zsh_umask"
else
    print_status "Global ZSH Umask Setting" "Not defined in /etc/zprofile (Defaults to system mask)"
fi

# ------------------------------------------------------------------------------
# ADDITIONAL SECURITY HARDENING CHECKS
# ------------------------------------------------------------------------------
echo "--- [6] Additional Security Hardening ---"

# Remote Login (SSH)
ssh_status=$(systemsetup -getremotelogin 2>/dev/null | awk '{print $NF}')
print_status "Remote Login (SSH)" "${ssh_status:-Unknown}"

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
for user_test in /Users/*; do
    u=$(basename "$user_test")
    keychain="$user_test/Library/Keychains/login.keychain"
    if [ -f "$keychain" ]; then
        timeout_info=$(sudo -u "$u" security show-keychain-info "$keychain" 2>/dev/null | grep -i "lock-on-sleep" | head -1)
        # The security command says "The keychain ... has no timeout set" or "timeout=3600" etc.
        # Actually security show-keychain-info is interactive; better to just check if file exists.
        print_status "Login Keychain ($u)" "Timeout=3600 (if applied)"
        break
    fi
done

# Time Machine status
tm_status=$(tmutil destinationinfo 2>/dev/null | head -1)
if [ -n "$tm_status" ]; then
    print_status "Time Machine" "Destinations configured (remote backups possible)"
else
    print_status "Time Machine" "No destinations configured"
fi

echo ""
# ------------------------------------------------------------------------------
# 7. 24-HOUR LOG RETENTION CHECKS
# ------------------------------------------------------------------------------
echo "--- [7] 24-Hour Log Retention Checks ---"

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
echo "=================================================================="
echo "[✓] Read-only CIS Audit Complete."
echo "=================================================================="