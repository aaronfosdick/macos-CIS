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

# ------------------------------------------------------------------------------
# 1. SOFTWARE UPDATES & SEEDING (CIS Section 1)
# ------------------------------------------------------------------------------
echo "[+] Configuring Apple Software Updates..."
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true

if [ "$AUTO_UPD" = "y" ]; then
  defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
fi

# ------------------------------------------------------------------------------
# 2. SYSTEM PREFERENCES & ACCESS CONTROL (CIS Section 2)
# ------------------------------------------------------------------------------
echo "[+] Hardening Screen Saver & Session Timeout Controls..."
# Enforce system-wide defaults for the loginwindow/screensaver architecture
defaults write com.apple.screensaver idleTime -int "$SS_TIMEOUT"
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int "$SS_GRACE"

echo "[+] Disabling Bluetooth Sharing..."
/usr/libexec/PlistBuddy -c "Set :QuietMode true" /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null

echo "[+] Disabling Remote Apple Events..."
launchctl unload -w /System/Library/LaunchDaemons/com.apple.AEServer.plist 2>/dev/null

echo "[+] Disabling Internet Sharing..."
defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict

# ------------------------------------------------------------------------------
# 3. NETWORK & SECURITY PROFILE (CIS Section 3)
# ------------------------------------------------------------------------------
echo "[+] Enforcing Application Firewall & Stealth Mode..."
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

echo "[+] Setting SSH (Remote Login) State..."
if [ "$ALLOW_SSH" = "y" ]; then
  systemsetup -setremotelogin on
else
  systemsetup -setremotelogin off
fi

# ------------------------------------------------------------------------------
# 4. LOGGING, AUDITING & ACCESSIBILITY (CIS Section 4 / 5)
# ------------------------------------------------------------------------------
echo "[+] Ensuring Security Auditing Deployed..."
launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null

echo "[+] Enforcing Guest Account Deactivation..."
defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false

echo "[+] Disabling Automatic UI Login..."
defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

echo "[+] Injecting Organizational Legal Banner text..."
defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "UNAUTHORIZED ACCESS TO THIS DEVICE IS STRICTLY PROHIBITED. All activities may be monitored and logged."

# ------------------------------------------------------------------------------
# 5. USER HOME DIRECTORIES & MASKS (CIS Section 6)
# ------------------------------------------------------------------------------
echo "[+] Setting Default Secure Umask for New Shell Sessions..."
if [ ! -f /etc/zprofile ]; then
  touch /etc/zprofile
fi
if ! grep -q "umask 027" /etc/zprofile; then
  echo "umask 027" >> /etc/zprofile
fi

echo ""
echo "=================================================================="
echo "[✓] Core Terminal Method CIS Controls Applied Successfully."
echo "    Note: If this asset is registered under MDM via Fleet, MDM "
echo "    profiles may override some local settings applied above."
echo "=================================================================="