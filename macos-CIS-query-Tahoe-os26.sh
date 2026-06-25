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

echo "=================================================================="
echo "[✓] Read-only CIS Audit Complete."
echo "=================================================================="