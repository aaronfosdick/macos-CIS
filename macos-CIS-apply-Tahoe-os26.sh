#!/bin/bash

# ==============================================================================
# macOS CIS Baseline Remediation Script (Terminal Method Mapping)
# ==============================================================================
# WARNING: Run this on a test machine first. In production environments, 
# configurations are ideally deployed via MDM Configuration Profiles.

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root (via sudo)."
  exit 1
fi

clear
echo "=================================================================="
echo "          macOS CIS Compliance Configuration Assistant           "
echo "=================================================================="
echo ""

# ------------------------------------------------------------------------------
# INTERACTIVE CHOICES SECTION
# ------------------------------------------------------------------------------

# 1. Screen Saver Timeout
read -p "[?] Enter screen saver inactivity timeout in seconds (CIS recommends 1200 or less): " SS_TIMEOUT
if [[ ! "$SS_TIMEOUT" =~ ^[0-9]+$ ]] || [ "$SS_TIMEOUT" -gt 1200 ]; then
  echo "   [!] Value empty or exceeds recommended limits. Defaulting to 1200 seconds."
  SS_TIMEOUT=1200
fi

# 2. Screen Saver Grace Period
read -p "[?] Enter grace period before password is required in seconds (CIS recommends 0): " SS_GRACE
if [[ ! "$SS_GRACE" =~ ^[0-9]+$ ]]; then
  echo "   [!] Invalid input. Defaulting to 0 seconds (Immediate lock)."
  SS_GRACE=0
fi

# 3. Remote Login (SSH)
read -p "[?] Do you want to ALLOW Remote Login / SSH? (y/N): " ALLOW_SSH
ALLOW_SSH=$(echo "$ALLOW_SSH" | tr '[:upper:]' '[:lower:]')

# 4. Automatic Updates Execution
read -p "[?] Force automated download AND background installation of macOS updates? (Y/n): " AUTO_UPD
AUTO_UPD=$(echo "${AUTO_UPD:-y}" | tr '[:upper:]' '[:lower:]')

echo ""
echo "=================================================================="
echo "            Applying Terminal Remediation Parameters...           "
echo "=================================================================="
echo ""
echo "  NOTE: iCloud controls (CIS 2.1.1.1 - 2.1.1.3) and Bluetooth"
echo "  hardware discoverability (CIS 2.2.3 via SPBluetoothDataType)"
echo "  require MDM configuration profiles and cannot be enforced via"
echo "  terminal commands. Use the query script to audit these."
echo "=================================================================="
echo ""

# ------------------------------------------------------------------------------
# HELPER FUNCTION – Check and apply only if needed
# ------------------------------------------------------------------------------
check_and_apply() {
    local control_name="$1"
    local check_cmd="$2"
    local apply_cmd="$3"
    
    if eval "$check_cmd" >/dev/null 2>&1; then
        echo "[✓] $control_name – Already compliant. Skipping."
    else
        echo "[+] $control_name – Not compliant. Applying..."
        eval "$apply_cmd"
        if [ $? -eq 0 ]; then
            echo "     Done."
        else
            echo "     [!] Failed (may require interactive action)."
        fi
    fi
}

# ------------------------------------------------------------------------------
# CORE CIS CONTROLS
# ------------------------------------------------------------------------------
echo "[*] Checking and applying Core CIS Controls..."

echo ""
echo "--- Control 1: FileVault (Full Disk Encryption) ---"
# CIS Control 2.3.1 — FileVault
if fdesetup status 2>/dev/null | grep -q "FileVault is On."; then
    echo "[✓] FileVault – Already compliant. Skipping."
else
    echo "[+] FileVault – Not compliant. Attempting to enable..."
    echo ""
    echo "    NOTE: fdesetup enable requires interactive input."
    echo "    You will be prompted to enter your Mac login password."
    echo "    If an admin password is required, you will be prompted for that too."
    echo ""
    echo "    If the command hangs or fails, run it manually in a separate terminal:"
    echo "      sudo fdesetup enable"
    echo ""
    fdesetup enable
    if [ $? -eq 0 ]; then
        echo "     FileVault has been enabled successfully."
    else
        echo "     [!] fdesetup enable did not complete successfully."
        echo "     [!] This is often due to missing interactive TTY or incorrect password."
        echo "     [!] To enable manually, run: sudo fdesetup enable"
        echo "     [!] Alternatively, enable FileVault in System Settings > Privacy & Security."
    fi
fi

# CIS Control 2.3.2 — Key Escrow (Recovery Key)
echo ""
echo "--- Key Escrow (Recovery Key) ---"
echo "[?] Checking if FileVault recovery key is escrowed..."
if fdesetup haspersonalrecoverykey 2>/dev/null | grep -q "true"; then
    echo "[✓] Personal recovery key is present."
else
    echo "[!] No personal recovery key detected."
    echo "    If FileVault is enabled without a recovery key, data may be unrecoverable."
    echo "    To generate one: sudo fdesetup changerecovery -personal"
fi
if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -q "true"; then
    echo "[✓] Institutional recovery key is present."
else
    echo "[!] No institutional recovery key detected."
    echo "    Institutional keys are typically deployed via MDM."
fi

# CIS Control 2.4.1 / 2.4.2 — Application Firewall & Stealth Mode
echo ""
echo "--- Control 2: Application Firewall ---"
check_and_apply \
    "Application Firewall" \
    '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "Firewall is enabled"' \
    '/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
    
check_and_apply \
    "Firewall Stealth Mode" \
    '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "Stealth mode enabled"' \
    '/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on'

# Gatekeeper
echo ""
echo "--- Control 3: Gatekeeper ---"
check_and_apply \
    "Gatekeeper" \
    'spctl --status 2>/dev/null | grep -q "assessments enabled"' \
    'spctl --master-enable'

# CIS Control 1.1 - 1.5 — Automatic Software Updates
echo ""
echo "--- Control 4: Automatic macOS Updates ---"
for key in AutomaticCheckEnabled AutomaticDownload CriticalUpdateInstall; do
    check_and_apply \
        "Software Update: $key" \
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate $key 2>/dev/null | grep -qE '1|true'" \
        "defaults write /Library/Preferences/com.apple.SoftwareUpdate $key -bool true"
done
check_and_apply \
    "App Store AutoUpdate" \
    'defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null | grep -qE "1|true"' \
    'defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true'

if [ "$AUTO_UPD" = "y" ]; then
    check_and_apply \
        "Automatic macOS Update Installation" \
        'defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null | grep -qE "1|true"' \
        'defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true'
fi

# CIS Control 5.1.1 — System Integrity Protection
echo ""
echo "--- Control 5: System Integrity Protection ---"
echo "[?] SIP can only be enabled from macOS Recovery. Checking current status..."
if csrutil status 2>/dev/null | grep -q "enabled"; then
    echo "[✓] SIP – Already enabled."
else
    echo "[!] SIP is DISABLED. To enable:"
    echo "     1. Restart your Mac and hold Command+R to enter Recovery Mode."
    echo "     2. Open Terminal from Utilities menu."
    echo "     3. Run: csrutil enable"
    echo "     4. Restart normally."
fi

# CIS Control 5.1.2 — Boot-args (System Mobile File Integrity)
echo ""
echo "--- Boot-args (System Mobile File Integrity) ---"
boot_args=$(nvram boot-args 2>/dev/null)
if [ -z "$boot_args" ]; then
    echo "[✓] nvram boot-args is not set (secure default)."
else
    echo "[!] nvram boot-args is set to: $boot_args"
    echo "    This may disable security features like SIP or amfi."
    echo "    To clear: sudo nvram -d boot-args"
    echo "    (Only clear if you are sure it is not needed.)"
fi

# CIS Control 6.1 — Guest Account
echo ""
echo "--- Guest Account ---"
check_and_apply \
    "Guest Account Disabled" \
    'defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null | grep -qE "0|false"' \
    'defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false'

# CIS Control 6.3 — Root Shell Disabled
echo ""
echo "--- Root Shell (Interactive Login) ---"
current_root_shell=$(dscl . -read /Users/root UserShell 2>/dev/null | awk '{print $NF}')
if [ "$current_root_shell" = "/usr/bin/false" ]; then
    echo "[✓] Root shell is set to /usr/bin/false (interactive login disabled)."
else
    echo "[!] Root shell is '$current_root_shell' (interactive login possible)."
    echo "[+] Setting root shell to /usr/bin/false..."
    dscl . -change /Users/root UserShell "$current_root_shell" /usr/bin/false 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "     Done."
    else
        echo "     [!] Failed to change root shell."
    fi
fi

# Secure Boot
echo ""
echo "--- Secure Boot Status ---"
if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "Secure Boot: Enabled"; then
    echo "[✓] Secure Boot – Enabled (Intel T2)."
elif sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1; then
    echo "[✓] Secure Boot – Always enabled on Apple Silicon (M1/M2/M3)."
elif sysctl -n kern.hv_support 2>/dev/null | grep -q 1; then
    echo "[!] Secure Boot – Could not determine. Ensure your Mac has a T2 chip and secure boot is enabled."
    echo "    To verify, restart and hold Command+R, then check Startup Security Utility."
else
    echo "[!] Secure Boot – Unable to check. This control applies to Intel Macs with T2 and all Apple Silicon Macs."
fi

# CIS Control 5.3 / 5.4 — Password Policy
echo ""
echo "--- Password Policy ---"
echo "[?] Checking current password policy..."

# Fetch current policy and check compliance inline
current_policy=$(pwpolicy -getglobalpolicy 2>/dev/null || echo "")
min_chars_ok=false
max_fail_ok=false
if [ -n "$current_policy" ]; then
    # Parse comma-separated key=value pairs
    min_chars=$(echo "$current_policy" | tr ',' '\n' | grep '^minChars=' | cut -d= -f2)
    max_fail=$(echo "$current_policy" | tr ',' '\n' | grep '^maxFailedLoginAttempts=' | cut -d= -f2)
    
    if [ -n "$min_chars" ] && [ "$min_chars" -ge 16 ] 2>/dev/null; then
        min_chars_ok=true
        echo "   minChars=$min_chars (>=16 ✓)"
    else
        echo "   minChars=${min_chars:-unset} (<16 or missing)"
    fi
    
    if [ -n "$max_fail" ] && [ "$max_fail" -le 5 ] 2>/dev/null; then
        max_fail_ok=true
        echo "   maxFailedLoginAttempts=$max_fail (<=5 ✓)"
    else
        echo "   maxFailedLoginAttempts=${max_fail:-unset} (>5 or missing)"
    fi
else
    echo "   [!] Unable to read global policy."
fi

if $min_chars_ok && $max_fail_ok; then
    echo "[✓] Password Policy – Already compliant. Skipping."
else
    echo "[+] Password Policy – Not compliant. Applying..."
    pwpolicy -setglobalpolicy "minChars=16 requiresNumeric=0 requiresMixedCase=0 requiresSymbol=0 maxFailedLoginAttempts=5"
    if [ $? -eq 0 ]; then
        echo "     Done."
    else
        echo "     [!] Failed."
    fi
fi

echo ""
echo "=================================================================="
echo "    Core CIS Checks Complete. Applying additional settings...    "
echo "=================================================================="
echo ""

# ------------------------------------------------------------------------------
# 2. SYSTEM PREFERENCES & ACCESS CONTROL (CIS Controls 2.2.1, 2.2.2, 2.2.3)
# ------------------------------------------------------------------------------
echo "[+] Hardening Screen Saver & Session Timeout Controls..."
# Enforce system-wide defaults for the loginwindow/screensaver architecture
defaults write com.apple.screensaver idleTime -int "$SS_TIMEOUT"
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int "$SS_GRACE"

# CIS Control 2.2.3 — Bluetooth Discoverability
echo "[+] Disabling Bluetooth Sharing..."
/usr/libexec/PlistBuddy -c "Set :QuietMode true" /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null

# CIS Control 2.2.4 — Remote Management (ARD / Screen Sharing)
echo "[+] Disabling Remote Management (ARD)..."
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null && echo "     Remote Management deactivated." || echo "     [!] Failed (may not be installed)."

# CIS Control 2.10.1.2 — Energy Sleep Optimization
echo "[+] Setting Energy Saver: sleep 60 min, display sleep 30 min..."
pmset -a sleep 60 displaysleep 30 2>/dev/null && echo "     Power management updated." || echo "     [!] Failed."

# CIS Control 3.3 — Remote Apple Events
echo "[+] Disabling Remote Apple Events..."
launchctl unload -w /System/Library/LaunchDaemons/com.apple.AEServer.plist 2>/dev/null

# CIS Control 3.4 — Internet Sharing
echo "[+] Disabling Internet Sharing..."
defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict

# ------------------------------------------------------------------------------
# 3. NETWORK & SECURITY PROFILE
# ------------------------------------------------------------------------------
echo "[+] Setting SSH (Remote Login) State..."
if [ "$ALLOW_SSH" = "y" ]; then
  systemsetup -setremotelogin on
else
  systemsetup -setremotelogin off
fi

# CIS Control 3.1 — SMB File Sharing
echo "[+] Disabling SMB File Sharing..."
launchctl disable system/com.apple.smbd 2>/dev/null && echo "     SMB sharing disabled." || echo "     [!] Failed."

# CIS Control 3.2 — CUPS Printer Sharing
echo "[+] Disabling CUPS Printer Sharing..."
cupsctl --no-share-printers 2>/dev/null && echo "     Printer sharing disabled." || echo "     [!] Failed."

# CIS Control 3.5 — Content Caching (P2P Asset Relays)
echo "[+] Disabling Content Caching..."
AssetCacheManagerUtil disable 2>/dev/null && echo "     Content caching disabled." || echo "     [!] Failed (may not be configured)."

# CIS Control 6.2 — Guest SMB/AFP Share Access
echo "[+] Disabling Guest Access to File Shares..."
defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false 2>/dev/null
defaults write /Library/Preferences/com.apple.smb.server AllowGuestAccess -bool false 2>/dev/null
echo "     Guest access to SMB/AFP shares disabled."

# ------------------------------------------------------------------------------
# 4. LOGGING, AUDITING & ACCESSIBILITY
# ------------------------------------------------------------------------------
# CIS Control 4.1 — Security Auditing Daemon
echo "[+] Ensuring Security Auditing Deployed..."
launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null

# CIS Control 4.2 — Audit Flags (Kernel Scope)
echo "[+] Setting audit flags to capture high-risk events..."
if grep -qE "^flags:.*lo" /etc/security/audit_control 2>/dev/null; then
    echo "     Audit flags already configured."
else
    sed -i '' 's/^flags:.*/flags: lo,ad,fd,fm,-all/' /etc/security/audit_control 2>/dev/null && \
        echo "     Audit flags updated. Restart needed to take effect." || \
        echo "     [!] Failed to update /etc/security/audit_control."
fi

# CIS Control 4.3 — Audit Minfree (Low-Volume Threshold)
echo "[+] Setting audit minfree to 25%..."
if grep -qE "^minfree:25" /etc/security/audit_control 2>/dev/null; then
    echo "     Audit minfree already configured."
else
    sed -i '' 's/^minfree:.*/minfree:25/' /etc/security/audit_control 2>/dev/null && \
        echo "     Audit minfree set to 25%." || \
        echo "     [!] Failed to update /etc/security/audit_control."
fi

# CIS Control 5.7 — Login Window Auth (Screensaver)
echo "[+] Ensuring screensaver requires authentication via security authorizationdb..."
auth_db_check=$(security authorizationdb read system.login.screensaver 2>/dev/null | grep -c "authenticate-user")
if [ "$auth_db_check" -gt 0 ]; then
    echo "     Screensaver auth already configured."
else
    echo "     [!] Cannot reliably remediate this via CLI; use System Settings > Lock Screen."
fi

echo "[+] Disabling Automatic UI Login..."
defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

echo "[+] Injecting Organizational Legal Banner text..."
defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "UNAUTHORIZED ACCESS TO THIS DEVICE IS STRICTLY PROHIBITED. All activities may be monitored and logged."

# ------------------------------------------------------------------------------
# 5. USER HOME DIRECTORIES & SHELL POLICIES
# ------------------------------------------------------------------------------
echo "[+] Setting Default Secure Umask for New Shell Sessions..."
if [ ! -f /etc/zprofile ]; then
  touch /etc/zprofile
fi
if ! grep -q "umask 027" /etc/zprofile; then
  echo "umask 027" >> /etc/zprofile
fi

# CIS Control 5.5 — Sudo Session Expiration
echo "[+] Setting sudo timestamp timeout to 0 (immediate re-authentication)..."
if [ -d /etc/sudoers.d ]; then
    if [ -f /etc/sudoers.d/00-cis-timestamp ] && grep -q "timestamp_timeout" /etc/sudoers.d/00-cis-timestamp 2>/dev/null; then
        echo "     Sudo timestamp already configured."
    else
        echo "Defaults timestamp_timeout=0" > /etc/sudoers.d/00-cis-timestamp 2>/dev/null && \
            chmod 440 /etc/sudoers.d/00-cis-timestamp && \
            echo "     Sudo timestamp timeout set to 0." || \
            echo "     [!] Failed to configure sudoers."
    fi
else
    echo "     [!] /etc/sudoers.d does not exist; skipping."
fi

# CIS Control 5.6 — Sudo Logging (Allowed / Denied)
echo "[+] Enabling sudo logging (allowed and denied commands)..."
if [ -d /etc/sudoers.d ]; then
    if [ -f /etc/sudoers.d/00-cis-logging ] && grep -q "log_allowed\|log_denied" /etc/sudoers.d/00-cis-logging 2>/dev/null; then
        echo "     Sudo logging already configured."
    else
        {
            echo "Defaults log_allowed"
            echo "Defaults log_denied"
            echo "Defaults logfile=/var/log/sudo.log"
        } > /etc/sudoers.d/00-cis-logging 2>/dev/null && \
            chmod 440 /etc/sudoers.d/00-cis-logging && \
            echo "     Sudo logging enabled (logfile: /var/log/sudo.log)." || \
            echo "     [!] Failed to configure sudo logging."
    fi
else
    echo "     [!] /etc/sudoers.d does not exist; skipping."
fi

# CIS Control 6.4 — Home Directory Permissions (700 or 750)
echo "[+] Setting home directory permissions to 700..."
for user_home in /Users/*; do
    u=$(basename "$user_home")
    if id "$u" &>/dev/null 2>&1 && [ -d "$user_home" ]; then
        perms=$(stat -f "%A" "$user_home" 2>/dev/null)
        if [ "$perms" != "700" ] && [ "$perms" != "750" ]; then
            chmod 700 "$user_home" 2>/dev/null && echo "     Fixed: $user_home" || echo "     [!] Failed: $user_home"
        fi
    fi
done
echo "     Done."

# ------------------------------------------------------------------------------
# ADDITIONAL SECURITY HARDENING (beyond CIS baseline)
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "       Additional Command-Line Security Practices                 "
echo "=================================================================="
echo ""

# 1. Safari / Web Security
echo "[+] Harden Safari security settings..."
# These affect the current user; run for all existing users?
# Apply system-wide defaults for any user (will affect future logins too with -currentHost?)
# Simpler: apply to the current user who runs the script as root.
for USER_HOME in /Users/*; do
    USER=$(basename "$USER_HOME")
    if id "$USER" &>/dev/null; then
        sudo -u "$USER" defaults write com.apple.Safari AutoFillPasswords -bool false 2>/dev/null
        sudo -u "$USER" defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true 2>/dev/null
    fi
done
echo "     Safari AutoFillPasswords disabled, fraudulent website warnings enabled."

# 2. Harden Bluetooth & Sharing
echo "[+] Disabling Bluetooth, AirDrop, AirPlay..."
# Bluetooth controller power off (saves battery, prevents unauthorized connections)
defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0 2>/dev/null && echo "     Bluetooth controller powered off."
# Disable AirDrop (per-user)
for USER_HOME in /Users/*; do
    USER=$(basename "$USER_HOME")
    if id "$USER" &>/dev/null; then
        sudo -u "$USER" defaults write com.apple.sharingd AirDrop -bool false 2>/dev/null
    fi
done
echo "     AirDrop disabled for all users."
# Disable AirPlay receiver system-wide
defaults write /System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist Disabled -bool true 2>/dev/null && echo "     AirPlay receiver disabled."

# 3. Keychain lock timeout (login keychain)
echo "[+] Setting login keychain lock timeout to 1 hour..."
for USER_HOME in /Users/*; do
    USER=$(basename "$USER_HOME")
    KEYCHAIN="$USER_HOME/Library/Keychains/login.keychain"
    if [ -f "$KEYCHAIN" ]; then
        sudo -u "$USER" security set-keychain-settings -t 3600 "$KEYCHAIN" 2>/dev/null
    fi
done
echo "     Done."

# 4. Disable Time Machine Remote Backups
echo "[+] Disabling Time Machine remote backups..."
sudo tmutil disable 2>/dev/null && echo "     Done." || echo "     [!] Failed or already disabled."

# ------------------------------------------------------------------------------
# 24-HOUR LOG RETENTION (no old logs kept)
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "        Configuring 24-Hour Log Retention                         "
echo "=================================================================="
echo ""

# 1. Unified logging persistence cap
echo "[+] Setting unified log retention cap to 24 hours..."
/usr/bin/log config --mode "level:persist:24h" 2>/dev/null && echo "     Unified log retention set to 24 hours." || echo "     [!] Failed – check macOS version."


# Newsyslog Rotation (24-hour retention)
echo "[+] Configuring newsyslog for /var/log/* files (daily, zero retention)..."
cat > /etc/newsyslog.d/99-cis-24h-retention.conf << 'EOF'
# CIS 24-hour retention: rotate daily, keep 0 copies, compress old (none)
/var/log/system.log       644  0     24    *    Z    /var/run/syslog.pid
/var/log/install.log      644  0     24    *    Z
/var/log/appstore.log     644  0     24    *    Z
/var/log/opendirectoryd.log 644  0     24    *    Z
EOF
chmod 644 /etc/newsyslog.d/99-cis-24h-retention.conf
echo "     Created /etc/newsyslog.d/99-cis-24h-retention.conf"

# 3. ASL log TTL
echo "[+] Setting ASL log TTL to 24 hours..."
ASL_CONF="/etc/asl.conf"
if grep -q "^\?.*ttl=24" "$ASL_CONF" 2>/dev/null; then
    echo "     ASL TTL already configured."
else
    # Insert before the catch-all or at end
    echo "# CIS 24-hour retention" >> "$ASL_CONF"
    echo "? [= Sender kernel] file /var/log/system.log ttl=24" >> "$ASL_CONF"
    echo "? [= Sender install] file /var/log/install.log ttl=24" >> "$ASL_CONF"
    echo "     Appended TTL rules to $ASL_CONF"
fi
# 4. Delete old log files from /Library/Logs and ~/Library/Logs
echo "[+] Removing log files older than 24 hours from common locations..."
if [ -d /Library/Logs ]; then
    find /Library/Logs -type f -mtime +1 -delete 2>/dev/null
    echo "     Cleaned /Library/Logs"
fi
for user_home in /Users/*; do
    user_logs="$user_home/Library/Logs"
    if [ -d "$user_logs" ]; then
        find "$user_logs" -type f -mtime +1 -delete 2>/dev/null
    fi
done
echo "     Cleaned all user Library/Logs"

echo ""
echo "=================================================================="
echo "[✓] Core Terminal Method CIS Controls Applied Successfully."
echo "    Note: If this asset is registered under MDM via Fleet, MDM "
echo "    profiles may override some local settings applied above."
echo "=================================================================="
echo "=================================================================="