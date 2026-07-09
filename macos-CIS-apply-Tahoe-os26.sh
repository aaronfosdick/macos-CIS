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

is_mdm_managed() {
  if command -v profiles >/dev/null 2>&1; then
    if profiles status -type enrollment 2>/dev/null | grep -Eiq 'enrolled: yes|user approved mdm: yes'; then
      return 0
    fi

    if profiles -P -o stdout 2>/dev/null | grep -Eiq 'managed|enrolled'; then
      return 0
    fi
  fi

  if [ -d /var/db/ConfigurationProfiles/Store ]; then
    if find /var/db/ConfigurationProfiles/Store -type f 2>/dev/null | grep -q .; then
      return 0
    fi
  fi

  return 1
}

MANAGEMENT_STATE="unmanaged"
if is_mdm_managed; then
  MANAGEMENT_STATE="managed"
fi

clear
echo "=================================================================="
echo "          macOS CIS Compliance Configuration Assistant           "
echo "=================================================================="
echo ""

echo "[*] Management state: $MANAGEMENT_STATE"
if [ "$MANAGEMENT_STATE" = "managed" ]; then
  echo "    [*] MDM profile detected. CIS 2.1.1.1, 2.1.1.2, and 2.3.2 are expected to be managed via MDM."
else
  echo "    [!] No MDM profile detected. Skipping CIS 2.1.1.1, 2.1.1.2, and 2.3.2 on this unmanaged personal Mac."
fi

# ------------------------------------------------------------------------------
# SNAPSHOT RESTORE HELPERS
# ------------------------------------------------------------------------------
MODE="apply"
SNAPSHOT_DIR="/private/var/db/macos-cis/snapshots"

list_snapshots() {
  if [ -d "$SNAPSHOT_DIR" ]; then
    find "$SNAPSHOT_DIR" -maxdepth 1 -type f -name 'macos-cis-snapshot-*.txt' 2>/dev/null | sort
  fi
}

snapshot_label() {
  local snapshot_path="$1"
  local base_name
  base_name=$(basename "$snapshot_path")
  local stamp="${base_name#macos-cis-snapshot-}"
  stamp="${stamp%.txt}"
  if [[ "$stamp" =~ ^([0-9]{8})-([0-9]{6})$ ]]; then
    local date_part="${BASH_REMATCH[1]}"
    local time_part="${BASH_REMATCH[2]}"
    printf '%s-%s-%s %s:%s:%s' \
      "${date_part:0:4}" "${date_part:4:2}" "${date_part:6:2}" \
      "${time_part:0:2}" "${time_part:2:2}" "${time_part:4:2}"
  else
    printf '%s' "$base_name"
  fi
}

choose_snapshot() {
  local -a snapshots=()
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && snapshots+=("$line")
  done < <(list_snapshots)

  if [ ${#snapshots[@]} -eq 0 ]; then
    echo "   [!] No snapshots found in $SNAPSHOT_DIR"
    return 1
  fi

  echo ""
  echo "Available snapshots:"
  local i
  for ((i=0; i<${#snapshots[@]}; i++)); do
    echo "   [$((i+1))] $(snapshot_label "${snapshots[$i]}")"
  done

  read -p "[?] Select snapshot to restore [1-${#snapshots[@]}]: " SNAPSHOT_CHOICE
  if [[ ! "$SNAPSHOT_CHOICE" =~ ^[0-9]+$ ]] || [ "$SNAPSHOT_CHOICE" -lt 1 ] || [ "$SNAPSHOT_CHOICE" -gt ${#snapshots[@]} ]; then
    echo "   [!] Invalid selection. Aborting."
    return 1
  fi

  echo "${snapshots[$((SNAPSHOT_CHOICE-1))]}"
}

restore_from_snapshot() {
  local snapshot_file="$1"
  echo ""
  echo "[*] Restoring settings from $(basename "$snapshot_file")"
  echo "    Immutable or unsafe settings will be skipped."

  while IFS= read -r entry; do
    entry=$(printf '%s' "$entry" | tr -d '\r')
    case "$entry" in
      \#*|'')
        continue
        ;;
      *=*)
        local key="${entry%%=*}"
        local value="${entry#*=}"
        ;;
      *)
        continue
        ;;
    esac

    case "$key" in
      CIS_2_3_1_FILEVAULT_STATUS)
        echo "   [!] Skipping FileVault restore; disabling FileVault is not safe."
        ;;
      CIS_2_3_2_PERSONAL_RECOVERY_KEY|CIS_2_3_2_INSTITUTIONAL_RECOVERY_KEY)
        echo "   [!] Skipping recovery-key restore; this state is not safely reversible."
        ;;
      CIS_5_1_1_SIP_STATUS)
        echo "   [!] Skipping SIP restore; SIP changes should be handled from Recovery."
        ;;
      CIS_SECURE_BOOT)
        echo "   [!] Skipping Secure Boot restore; this is not safely changed from the CLI."
        ;;
      CIS_2_4_1_APPLICATION_FIREWALL)
        if [ "$value" = "Enabled" ]; then
          /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null
        elif [ "$value" = "Disabled" ]; then
          /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off 2>/dev/null
        fi
        ;;
      CIS_2_4_2_FIREWALL_STEALTH_MODE)
        if [ "$value" = "Enabled" ]; then
          /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null
        elif [ "$value" = "Disabled" ]; then
          /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off 2>/dev/null
        fi
        ;;
      CIS_GATEKEEPER_STATUS)
        if [ "$value" = "Enabled" ]; then
          spctl --master-enable 2>/dev/null
        elif [ "$value" = "Disabled" ]; then
          spctl --master-disable 2>/dev/null
        fi
        ;;
      CIS_1_1_AUTOMATIC_UPDATE_CHECK|CIS_1_2_AUTOMATIC_DOWNLOAD|CIS_1_5_CRITICAL_UPDATE_INSTALL|CIS_1_4_APP_STORE_AUTO_UPDATE|CIS_1_3_AUTOMATIC_OS_UPDATES)
        case "$key" in
          CIS_1_1_AUTOMATIC_UPDATE_CHECK)
            defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true 2>/dev/null
            ;;
          CIS_1_2_AUTOMATIC_DOWNLOAD)
            defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true 2>/dev/null
            ;;
          CIS_1_5_CRITICAL_UPDATE_INSTALL)
            defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true 2>/dev/null
            ;;
          CIS_1_4_APP_STORE_AUTO_UPDATE)
            defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true 2>/dev/null
            ;;
          CIS_1_3_AUTOMATIC_OS_UPDATES)
            defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true 2>/dev/null
            ;;
        esac
        ;;
      CIS_6_1_GUEST_ACCOUNT)
        if [ "$value" = "Enabled" ]; then
          defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true 2>/dev/null
        else
          defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false 2>/dev/null
        fi
        ;;
      CIS_2_2_1_SCREEN_SAVER_TIMEOUT)
        if [[ "$value" =~ ^[0-9]+$ ]]; then
          defaults write com.apple.screensaver idleTime -int "$value" 2>/dev/null
        fi
        ;;
      CIS_2_2_2_SCREEN_SAVER_PASSWORD_REQUIRED)
        if [ "$value" = "Enabled" ]; then
          defaults write com.apple.screensaver askForPassword -int 1 2>/dev/null
        else
          defaults write com.apple.screensaver askForPassword -int 0 2>/dev/null
        fi
        ;;
      CIS_2_2_2_SCREEN_SAVER_PASSWORD_GRACE)
        if [[ "$value" =~ ^[0-9]+$ ]]; then
          defaults write com.apple.screensaver askForPasswordDelay -int "$value" 2>/dev/null
        fi
        ;;
      CIS_2_2_3_BLUETOOTH_QUIET_MODE)
        if [ "$value" = "Enabled" ]; then
          /usr/libexec/PlistBuddy -c "Set :QuietMode true" /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null
        else
          /usr/libexec/PlistBuddy -c "Set :QuietMode false" /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null
        fi
        ;;
      CIS_3_6_REMOTE_LOGIN)
        if [ "$value" = "Enabled" ]; then
          systemsetup -setremotelogin on 2>/dev/null
        else
          systemsetup -setremotelogin off 2>/dev/null
        fi
        ;;
      CIS_3_1_SMB_FILE_SHARING)
        if [ "$value" = "Enabled" ]; then
          launchctl enable system/com.apple.smbd 2>/dev/null
        else
          launchctl disable system/com.apple.smbd 2>/dev/null
        fi
        ;;
      CIS_3_2_CUPS_PRINTER_SHARING)
        if [ "$value" = "Enabled" ]; then
          cupsctl --share-printers 2>/dev/null
        else
          cupsctl --no-share-printers 2>/dev/null
        fi
        ;;
      CIS_6_2_GUEST_FILE_SHARE_ACCESS)
        if [ "$value" = "Enabled" ]; then
          defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool true 2>/dev/null
        else
          defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false 2>/dev/null
        fi
        ;;
      CIS_6_2_GUEST_SMB_ACCESS)
        if [ "$value" = "Enabled" ]; then
          defaults write /Library/Preferences/com.apple.smb.server AllowGuestAccess -bool true 2>/dev/null
        else
          defaults write /Library/Preferences/com.apple.smb.server AllowGuestAccess -bool false 2>/dev/null
        fi
        ;;
    esac
  done < "$snapshot_file"

  echo "[✓] Snapshot restore completed."
}

# ------------------------------------------------------------------------------
# INTERACTIVE CHOICES SECTION
# ------------------------------------------------------------------------------

echo "[?] CIS 2.3.1/2.3.2 Choose an operation:"
echo "    1) CIS 2.3.1 Apply all CIS changes"
echo "    2) CIS 2.3.2 Revert to a snapshot"
read -p "[?] Selection [1/2]: " OPERATION_SELECTION
case "$OPERATION_SELECTION" in
  2)
    MODE="revert"
    ;;
  *)
    MODE="apply"
    ;;
esac

if [ "$MODE" = "revert" ]; then
  SELECTED_SNAPSHOT="$(choose_snapshot)" || exit 1
  restore_from_snapshot "$SELECTED_SNAPSHOT"
  exit 0
fi

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
echo "  are MDM-dependent. On unmanaged personal Macs, CIS 2.1.1.1,"
echo "  2.1.1.2, and 2.3.2 are skipped. Use the query script to audit them."
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
echo "[*] CIS 2.3.1 Checking and applying Core CIS Controls..."

echo ""
echo "--- CIS 2.3.1 FileVault (Full Disk Encryption) ---"
# CIS Control 2.3.1 — FileVault
if fdesetup status 2>/dev/null | grep -q "FileVault is On."; then
    echo "[✓] FileVault – Already compliant. Skipping."
else
    echo "[+] CIS 2.3.1 FileVault – Not compliant. Attempting to enable..."
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

# CIS Control 2.1.1.1 / 2.1.1.2 — iCloud Sync Controls
echo ""
echo "--- CIS 2.1.1.1/2.1.1.2 iCloud Sync Controls ---"
if [ "$MANAGEMENT_STATE" = "unmanaged" ]; then
    echo "[!] Unmanaged personal Mac detected. Skipping CIS 2.1.1.1 and 2.1.1.2."
else
    echo "[*] Managed Mac detected. CIS 2.1.1.1 and 2.1.1.2 are expected to be enforced via MDM profiles."
fi

# CIS Control 2.3.2 — Key Escrow (Recovery Key)
echo ""
echo "--- CIS 2.3.2 Key Escrow (Recovery Key) ---"
if [ "$MANAGEMENT_STATE" = "unmanaged" ]; then
    echo "[!] Unmanaged Mac detected. Skipping CIS 2.3.2 recovery-key escrow checks."
else
    echo "[?] CIS 2.3.2 Checking if FileVault recovery key is escrowed..."
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
fi

# CIS Control 2.4.1 / 2.4.2 — Application Firewall & Stealth Mode
echo ""
echo "--- CIS 2.4.1/2.4.2 Application Firewall ---"
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
echo "--- CIS 2.4.3 Gatekeeper ---"
check_and_apply \
    "Gatekeeper" \
    'spctl --status 2>/dev/null | grep -q "assessments enabled"' \
    'spctl --master-enable'

# CIS Control 1.1 - 1.5 — Automatic Software Updates
echo ""
echo "--- CIS 1.1/1.2/1.3/1.4/1.5 Automatic macOS Updates ---"
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
echo "--- CIS 5.1.1 System Integrity Protection ---"
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
echo "--- CIS 6.1 Guest Account ---"
check_and_apply \
    "Guest Account Disabled" \
    'defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null | grep -qE "0|false"' \
    'defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false'

# CIS Control 6.3 — Root Shell Disabled
echo ""
echo "--- CIS 6.3 Root Shell (Interactive Login) ---"
current_root_shell=$(dscl . -read /Users/root UserShell 2>/dev/null | awk '{print $NF}')
if [ "$current_root_shell" = "/usr/bin/false" ]; then
    echo "[✓] Root shell is set to /usr/bin/false (interactive login disabled)."
else
    echo "[!] Root shell is '$current_root_shell' (interactive login possible)."
    echo "[+] CIS 6.3 Setting root shell to /usr/bin/false..."
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
echo "--- CIS 5.3/5.4 Password Policy ---"
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
    echo "[+] CIS 5.3/5.4 Password Policy – Not compliant. Applying..."
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
echo "[+] CIS 2.2.1/2.2.2 Hardening Screen Saver & Session Timeout Controls..."
# Enforce system-wide defaults for the loginwindow/screensaver architecture
defaults write com.apple.screensaver idleTime -int "$SS_TIMEOUT"
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int "$SS_GRACE"

# CIS Control 2.2.3 — Bluetooth Discoverability
echo "[+] CIS 2.2.3 Disabling Bluetooth Sharing..."
/usr/libexec/PlistBuddy -c "Set :QuietMode true" /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null

# CIS Control 2.2.4 — Remote Management (ARD / Screen Sharing)
echo "[+] CIS 2.2.4 Disabling Remote Management (ARD)..."
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null && echo "     Remote Management deactivated." || echo "     [!] Failed (may not be installed)."

# CIS Control 2.10.1.2 — Energy Sleep Optimization
echo "[+] CIS 2.10.1.2 Setting Energy Saver: sleep 60 min, display sleep 30 min..."
pmset -a sleep 60 displaysleep 30 2>/dev/null && echo "     Power management updated." || echo "     [!] Failed."

# CIS Control 3.3 — Remote Apple Events
echo "[+] CIS 3.3 Disabling Remote Apple Events..."
launchctl unload -w /System/Library/LaunchDaemons/com.apple.AEServer.plist 2>/dev/null

# CIS Control 3.4 — Internet Sharing
echo "[+] CIS 3.4 Disabling Internet Sharing..."
defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict

# ------------------------------------------------------------------------------
# 3. NETWORK & SECURITY PROFILE
# ------------------------------------------------------------------------------
echo "[+] CIS 3.6 Setting SSH (Remote Login) State..."
if [ "$ALLOW_SSH" = "y" ]; then
  systemsetup -setremotelogin on
else
  systemsetup -setremotelogin off
fi

# CIS Control 3.1 — SMB File Sharing
echo "[+] CIS 3.1 Disabling SMB File Sharing..."
launchctl disable system/com.apple.smbd 2>/dev/null && echo "     SMB sharing disabled." || echo "     [!] Failed."

# CIS Control 3.2 — CUPS Printer Sharing
echo "[+] CIS 3.2 Disabling CUPS Printer Sharing..."
cupsctl --no-share-printers 2>/dev/null && echo "     Printer sharing disabled." || echo "     [!] Failed."

# CIS Control 3.5 — Content Caching (P2P Asset Relays)
echo "[+] CIS 3.5 Disabling Content Caching..."
AssetCacheManagerUtil disable 2>/dev/null && echo "     Content caching disabled." || echo "     [!] Failed (may not be configured)."

# CIS Control 6.2 — Guest SMB/AFP Share Access
echo "[+] CIS 6.2 Disabling Guest Access to File Shares..."
defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false 2>/dev/null
defaults write /Library/Preferences/com.apple.smb.server AllowGuestAccess -bool false 2>/dev/null
echo "     Guest access to SMB/AFP shares disabled."

# ------------------------------------------------------------------------------
# 4. LOGGING, AUDITING & ACCESSIBILITY
# ------------------------------------------------------------------------------
# CIS Control 4.1 — Security Auditing Daemon
echo "[+] CIS 4.1 Ensuring Security Auditing Deployed..."
launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null

# CIS Control 4.2 — Audit Flags (Kernel Scope)
echo "[+] CIS 4.2 Setting audit flags to capture high-risk events..."
if grep -qE "^flags:.*lo" /etc/security/audit_control 2>/dev/null; then
    echo "     Audit flags already configured."
else
    sed -i '' 's/^flags:.*/flags: lo,ad,fd,fm,-all/' /etc/security/audit_control 2>/dev/null && \
        echo "     Audit flags updated. Restart needed to take effect." || \
        echo "     [!] Failed to update /etc/security/audit_control."
fi

# CIS Control 4.3 — Audit Minfree (Low-Volume Threshold)
echo "[+] CIS 4.3 Setting audit minfree to 25%..."
if grep -qE "^minfree:25" /etc/security/audit_control 2>/dev/null; then
    echo "     Audit minfree already configured."
else
    sed -i '' 's/^minfree:.*/minfree:25/' /etc/security/audit_control 2>/dev/null && \
        echo "     Audit minfree set to 25%." || \
        echo "     [!] Failed to update /etc/security/audit_control."
fi

# CIS Control 5.7 — Login Window Auth (Screensaver)
echo "[+] CIS 5.7 Ensuring screensaver requires authentication via security authorizationdb..."
auth_db_check=$(security authorizationdb read system.login.screensaver 2>/dev/null | grep -c "authenticate-user")
if [ "$auth_db_check" -gt 0 ]; then
    echo "     Screensaver auth already configured."
else
    echo "     [!] Cannot reliably remediate this via CLI; use System Settings > Lock Screen."
fi

echo "[+] CIS 5.7 Disabling Automatic UI Login..."
defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

echo "[+] CIS 5.7 Injecting Organizational Legal Banner text..."
defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "UNAUTHORIZED ACCESS TO THIS DEVICE IS STRICTLY PROHIBITED. All activities may be monitored and logged."

# ------------------------------------------------------------------------------
# 5. USER HOME DIRECTORIES & SHELL POLICIES
# ------------------------------------------------------------------------------
echo "[+] CIS 5.5 Setting Default Secure Umask for New Shell Sessions..."
if [ ! -f /etc/zprofile ]; then
  touch /etc/zprofile
fi
if ! grep -q "umask 027" /etc/zprofile; then
  echo "umask 027" >> /etc/zprofile
fi

# CIS Control 5.5 — Sudo Session Expiration
echo "[+] CIS 5.5 Setting sudo timestamp timeout to 0 (immediate re-authentication)..."
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
echo "[+] CIS 5.6 Enabling sudo logging (allowed and denied commands)..."
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
echo "[+] CIS 6.4 Setting home directory permissions to 700..."
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
echo "[+] CIS 2.2.4 Harden Safari security settings..."
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
echo "[+] CIS 2.2.3/3.4 Disabling Bluetooth, AirDrop, AirPlay..."
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
echo "[+] CIS 2.2.3 Setting login keychain lock timeout to 1 hour..."
for USER_HOME in /Users/*; do
    USER=$(basename "$USER_HOME")
    KEYCHAIN="$USER_HOME/Library/Keychains/login.keychain"
    if [ -f "$KEYCHAIN" ]; then
        sudo -u "$USER" security set-keychain-settings -t 3600 "$KEYCHAIN" 2>/dev/null
    fi
done
echo "     Done."

# 4. Disable Time Machine Remote Backups
echo "[+] CIS 2.10.1.2 Disabling Time Machine remote backups..."
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
echo "[+] CIS 4.4 Setting unified log retention cap to 24 hours..."
/usr/bin/log config --mode "level:persist:24h" 2>/dev/null && echo "     Unified log retention set to 24 hours." || echo "     [!] Failed – check macOS version."


# Newsyslog Rotation (24-hour retention)
echo "[+] CIS 4.4 Configuring newsyslog for /var/log/* files (daily, zero retention)..."
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
echo "[+] CIS 4.4 Setting ASL log TTL to 24 hours..."
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
echo "[+] CIS 4.4 Removing log files older than 24 hours from common locations..."
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