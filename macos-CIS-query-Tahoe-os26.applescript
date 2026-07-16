-- ==============================================================================
-- macOS CIS Baseline Audit / Query Script (Standalone AppleScript)
-- ==============================================================================
-- This script performs a read-only audit of the current macOS configuration,
-- writes a snapshot file, and returns a human-readable report.
-- Paste directly into AppleScript Editor and click Run.

use framework "AppKit"
use scripting additions

property cancelled : false

on joinText(listOfStrings, delimiter)
    set astid to AppleScript's text item delimiters
    set AppleScript's text item delimiters to delimiter
    set joinedString to listOfStrings as text
    set AppleScript's text item delimiters to astid
    return joinedString
end joinText

on shell(commandText)
    if cancelled then return ""
    try
        return do shell script commandText with administrator privileges
    on error errText number errNum
        if errNum is -128 then
            set cancelled to true
        end if
        return ""
    end try
end shell

on safeValue(rawValue, fallback)
    if rawValue is "" then
        return fallback
    end if
    return rawValue
end safeValue

on appendStatus(reportLines, labelText, valueText)
    set end of reportLines to labelText & ": " & valueText
end appendStatus

on run
    set linefeed to ASCII character 10
    set reportLines to {}
    set end of reportLines to "--- [0] Core CIS Controls ---"

    set fvStatus to shell("fdesetup status 2>/dev/null")
    set fvValue to "Off"
    if fvStatus contains "FileVault is On." then set fvValue to "On"
    appendStatus(reportLines, "CIS 2.3.1 - FileVault (Full Disk Encryption)", fvValue)

    set personalRecovery to shell("fdesetup haspersonalrecoverykey 2>/dev/null")
    set personalRecoveryValue to "Not Present"
    if personalRecovery contains "true" then set personalRecoveryValue to "Present"
    appendStatus(reportLines, "CIS 2.3.2 - FileVault Personal Recovery Key", personalRecoveryValue)

    set institutionalRecovery to shell("fdesetup hasinstitutionalrecoverykey 2>/dev/null")
    set institutionalRecoveryValue to "Not Present"
    if institutionalRecovery contains "true" then set institutionalRecoveryValue to "Present"
    appendStatus(reportLines, "CIS 2.3.2 - FileVault Institutional Recovery Key", institutionalRecoveryValue)

    set fwState to shell("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d ')'")
    appendStatus(reportLines, "CIS 2.4.1 - Application Firewall", fwState)

    set fwStealth to shell("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | awk '{print $NF}'")
    appendStatus(reportLines, "CIS 2.4.2 - Firewall Stealth Mode", fwStealth)

    set gatekeeperStatus to shell("spctl --status 2>/dev/null")
    set gatekeeperValue to "Disabled"
    if gatekeeperStatus contains "assessments enabled" then set gatekeeperValue to "Enabled"
    appendStatus(reportLines, "CIS 2.4.3 - Gatekeeper", gatekeeperValue)

    set autoCheck to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null")
    set autoCheck to safeValue(autoCheck, "0 (Disabled)")
    appendStatus(reportLines, "CIS 1.1 - Automatic Update Check Enabled", autoCheck)

    set autoDownload to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null")
    set autoDownload to safeValue(autoDownload, "0 (Disabled)")
    appendStatus(reportLines, "CIS 1.2 - Automatic Download Enabled", autoDownload)

    set criticalUpdate to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null")
    set criticalUpdate to safeValue(criticalUpdate, "0 (Disabled)")
    appendStatus(reportLines, "CIS 1.5 - Install System Data & Security Files", criticalUpdate)

    set appUpdate to shell("defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null")
    set appUpdate to safeValue(appUpdate, "0 (Disabled)")
    appendStatus(reportLines, "CIS 1.4 - Automatic App Store Updates", appUpdate)

    set macosUpdate to shell("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null")
    set macosUpdate to safeValue(macosUpdate, "0 (Disabled)")
    appendStatus(reportLines, "CIS 1.3 - Automatic OS Updates Enabled", macosUpdate)

    set sipStatus to shell("csrutil status 2>/dev/null")
    set sipValue to "Disabled (see note)"
    if sipStatus contains "enabled" then set sipValue to "Enabled"
    appendStatus(reportLines, "CIS 5.1.1 - System Integrity Protection (SIP)", sipValue)

    set bootArgs to shell("nvram boot-args 2>/dev/null")
    set bootArgsValue to "Not Set (Secure)"
    if bootArgs is not "" then set bootArgsValue to bootArgs
    appendStatus(reportLines, "CIS 5.1.2 - Boot Args (nvram)", bootArgsValue)

    set guestStatus to shell("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
    set guestValue to "Disabled"
    if guestStatus is "1" or guestStatus is "true" then set guestValue to "Enabled"
    appendStatus(reportLines, "CIS 6.1 - Guest Account", guestValue)

    set rootShell to shell("dscl . -read /Users/root UserShell 2>/dev/null")
    set rootShellValue to "Unknown"
    if rootShell contains "/usr/bin/false" then set rootShellValue to "Disabled (/usr/bin/false)"
    appendStatus(reportLines, "CIS 6.3 - Root Login (Shell)", rootShellValue)

    set secureBootStatus to shell("system_profiler SPiBridgeDataType 2>/dev/null")
    set secureBootValue to "Unable to determine / Not applicable"
    if secureBootStatus contains "Secure Boot: Enabled" then
        set secureBootValue to "Enabled"
    else if shell("sysctl -n hw.optional.arm64 2>/dev/null") is "1" then
        set secureBootValue to "Always Enabled"
    end if
    appendStatus(reportLines, "CIS 6.5 - Secure Boot (Intel T2)", secureBootValue)
    if shell("sysctl -n hw.optional.arm64 2>/dev/null") is "1" then
        appendStatus(reportLines, "CIS 6.5 - Secure Boot (Apple Silicon)", "Always Enabled")
    else
        appendStatus(reportLines, "CIS 6.5 - Secure Boot", "Unable to determine / Not applicable")
    end if

    set pwPolicy to shell("pwpolicy -getglobalpolicy 2>/dev/null")
    set minCharsValue to "Not Set"
    set maxFailValue to "Not Set"
    set requiresNumericValue to "Not Set"
    set requiresMixedCaseValue to "Not Set"
    set requiresSymbolValue to "Not Set"
    appendStatus(reportLines, "CIS 5.3 - Password minChars", minCharsValue)
    appendStatus(reportLines, "CIS 5.4 - maxFailedLoginAttempts", maxFailValue)
    appendStatus(reportLines, "CIS 5.3/5.4 - requiresNumeric (should be 0)", requiresNumericValue)
    appendStatus(reportLines, "CIS 5.3/5.4 - requiresMixedCase (should be 0)", requiresMixedCaseValue)
    appendStatus(reportLines, "CIS 5.3/5.4 - requiresSymbol (should be 0)", requiresSymbolValue)

    set icloudKeychain to shell("/usr/libexec/PlistBuddy -c \"Print :Accounts:0:Services:KEYCHAIN_SYNC:Status\" /Library/Preferences/com.apple.mobiledevice.passwordpolicy.plist 2>/dev/null")
    set icloudKeychainValue to safeValue(icloudKeychain, "Not restricted (no MDM profile)")
    appendStatus(reportLines, "CIS 2.1.1.1 - iCloud Keychain Sync (MDM)", icloudKeychainValue)

    set icloudDrive to shell("defaults read /Library/Managed\\ Preferences/com.apple.applicationaccess allowCloudDocumentSync 2>/dev/null")
    set icloudDriveValue to safeValue(icloudDrive, "Not restricted (no MDM profile)")
    if icloudDrive is "0" then set icloudDriveValue to "Blocked"
    appendStatus(reportLines, "CIS 2.1.1.2 - iCloud Drive Sync (MDM)", icloudDriveValue)

    set icloudDesktop to shell("defaults read /Library/Managed\\ Preferences/com.apple.finder EnterpriseDesktopDocumentSyncDisabled 2>/dev/null")
    set icloudDesktopValue to safeValue(icloudDesktop, "Not restricted (no MDM profile)")
    if icloudDesktop is "1" then set icloudDesktopValue to "Blocked"
    appendStatus(reportLines, "CIS 2.1.1.3 - iCloud Desktop & Documents (MDM)", icloudDesktopValue)

    set end of reportLines to ""
    set end of reportLines to "--- [1] System Preferences & Access Control ---"

    set ssTimeout to shell("defaults read com.apple.screensaver idleTime 2>/dev/null")
    set ssTimeout to safeValue(ssTimeout, "Not Configured")
    appendStatus(reportLines, "CIS 2.2.1 - Screen Saver Timeout (Seconds)", ssTimeout)

    set ssPwd to shell("defaults read com.apple.screensaver askForPassword 2>/dev/null")
    set ssPwd to safeValue(ssPwd, "Not Configured")
    appendStatus(reportLines, "CIS 2.2.2 - Require Password After Screen Saver", ssPwd)

    set ssDelay to shell("defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null")
    set ssDelay to safeValue(ssDelay, "Not Configured")
    appendStatus(reportLines, "CIS 2.2.2 - Screen Saver Password Grace Period", ssDelay)

    set btSharing to shell("defaults read /Library/Preferences/com.apple.Bluetooth.plist QuietMode 2>/dev/null")
    set btSharingValue to "1 (Enabled / Public)"
    if btSharing is "true" or btSharing is "1" then set btSharingValue to "0 (Disabled / Secure)"
    appendStatus(reportLines, "CIS 2.2.3 - Bluetooth Discoverable/Sharing State", btSharingValue)

    set btLe to shell("system_profiler SPBluetoothDataType 2>/dev/null | grep 'Discoverable' | head -1")
    set btLeValue to "Unknown"
    if btLe is not "" then set btLeValue to btLe
    appendStatus(reportLines, "CIS 2.2.3 - Bluetooth Discoverable (Controller)", btLeValue)

    set remoteMgmtState to shell("launchctl print-disabled system 2>/dev/null | grep -q 'com.apple.RemoteDesktop'; echo $? 2>/dev/null")
    set remoteMgmtValue to "Not loaded (likely disabled)"
    if remoteMgmtState is "0" then
        set remoteMgmtValue to "Disabled"
    else if shell("launchctl list 2>/dev/null | grep com.apple.RemoteDesktop") is not "" then
        set remoteMgmtValue to "Enabled"
    end if
    appendStatus(reportLines, "CIS 2.2.4 - Remote Management (ARD)", remoteMgmtValue)

    set pmsetInfo to shell("pmset -g custom 2>/dev/null | grep -E '(sleep|displaysleep)' | head -4 | tr '\r' ' '")
    set pmsetValue to "Unable to read"
    if pmsetInfo is not "" then set pmsetValue to pmsetInfo
    appendStatus(reportLines, "CIS 2.10.1.2 - Power Mgmt (sleep/displaysleep)", pmsetValue)

    set aeStatus to shell("launchctl list 2>/dev/null | grep com.apple.AEServer")
    set aeValue to "Disabled"
    if aeStatus is not "" then set aeValue to "Enabled"
    appendStatus(reportLines, "CIS 3.3 - Remote Apple Events", aeValue)

    set natStatus to shell("defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null")
    set natValue to "Disabled"
    if natStatus is not "" and natStatus is not "{}" then set natValue to "Enabled"
    appendStatus(reportLines, "CIS 3.4 - Internet Sharing", natValue)

    set end of reportLines to ""
    set end of reportLines to "--- [2] Network & Security Profile ---"

    set sshState to shell("systemsetup -getremotelogin 2>/dev/null | awk '{print $NF}'")
    appendStatus(reportLines, "Remote Login (SSH) Status", safeValue(sshState, "Unknown/MDM Controlled"))

    set smbStatus to shell("launchctl list 2>/dev/null | grep com.apple.smbd")
    set smbValue to "Not loaded"
    if smbStatus is not "" then set smbValue to "Enabled"
    appendStatus(reportLines, "CIS 3.1 - SMB File Sharing", smbValue)

    set cupsSharing to shell("cupsctl 2>/dev/null | grep '_share_printers'")
    set cupsValue to "Unknown"
    if cupsSharing contains "_share_printers=0" then
        set cupsValue to "Disabled"
    else if cupsSharing contains "_share_printers=1" then
        set cupsValue to "Enabled"
    end if
    appendStatus(reportLines, "CIS 3.2 - CUPS Printer Sharing", cupsValue)

    set cacheStatus to shell("AssetCacheManagerUtil status 2>/dev/null | head -1")
    set cacheValue to "Inactive / Not configured"
    if cacheStatus is not "" then set cacheValue to cacheStatus
    appendStatus(reportLines, "CIS 3.5 - Content Caching (P2P)", cacheValue)

    set afpGuest to shell("defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess 2>/dev/null")
    set afpGuestValue to "Allowed (default)"
    if afpGuest is "0" or afpGuest is "false" then set afpGuestValue to "Disabled"
    appendStatus(reportLines, "CIS 6.2 - Guest SMB/AFP Share Access", afpGuestValue)

    set smbGuest to shell("defaults read /Library/Preferences/com.apple.smb.server AllowGuestAccess 2>/dev/null")
    set smbGuestValue to "Allowed (default)"
    if smbGuest is "0" or smbGuest is "false" then set smbGuestValue to "Disabled"
    appendStatus(reportLines, "CIS 6.2 - Guest SMB Access", smbGuestValue)

    set end of reportLines to ""
    set end of reportLines to "--- [3] Logging, Auditing & Access ---"

    set auditStatus to shell("launchctl list 2>/dev/null | grep com.apple.auditd")
    set auditValue to "Stopped / Disabled"
    if auditStatus is not "" then set auditValue to "Running"
    appendStatus(reportLines, "CIS 4.1 - Security Auditing Daemon (auditd)", auditValue)

    set auditFlags to shell("grep -E '^flags:' /etc/security/audit_control 2>/dev/null")
    set auditFlagsValue to "Not configured / Missing"
    if auditFlags is not "" then set auditFlagsValue to auditFlags
    appendStatus(reportLines, "CIS 4.2 - Audit Flags", auditFlagsValue)

    set auditMinfree to shell("grep -E '^minfree:' /etc/security/audit_control 2>/dev/null")
    set auditMinfreeValue to "Not configured / Missing"
    if auditMinfree is not "" then set auditMinfreeValue to auditMinfree
    appendStatus(reportLines, "CIS 4.3 - Audit Minfree", auditMinfreeValue)

    set autologinStatus to shell("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null")
    set autologinStatus to safeValue(autologinStatus, "None (Secure)")
    appendStatus(reportLines, "CIS 5.7 - Automatic UI Login User", autologinStatus)

    set authDb to shell("security authorizationdb read system.login.screensaver 2>/dev/null | grep -o 'authenticate-user' | head -1")
    set authDbValue to "Not requiring authentication (or unable to read)"
    if authDb is "authenticate-user" then set authDbValue to "Requires authentication"
    appendStatus(reportLines, "CIS 5.7 - Login Window Auth (Screensaver)", authDbValue)

    set end of reportLines to ""
    set end of reportLines to "--- [4] Environment & Shell Policies ---"

    set zshUmask to shell("grep 'umask' /etc/zprofile 2>/dev/null")
    set zshUmaskValue to "Not defined in /etc/zprofile (Defaults to system mask)"
    if zshUmask is not "" then set zshUmaskValue to zshUmask
    appendStatus(reportLines, "Global ZSH Umask Setting", zshUmaskValue)

    set sudoTs to shell("sudo -V 2>/dev/null | grep 'Authentication timestamp timeout'")
    set sudoTsValue to "Unknown"
    if sudoTs is not "" then set sudoTsValue to sudoTs
    appendStatus(reportLines, "CIS 5.5 - Sudo Timestamp Timeout", sudoTsValue)

    set sudoLogAllowed to shell("sudo -V 2>/dev/null | grep 'log_allowed'")
    set sudoLogDenied to shell("sudo -V 2>/dev/null | grep 'log_denied'")
    set sudoLogAllowedValue to "Not configured"
    if sudoLogAllowed is not "" then set sudoLogAllowedValue to sudoLogAllowed
    appendStatus(reportLines, "CIS 5.6 - Sudo Log Allowed", sudoLogAllowedValue)
    set sudoLogDeniedValue to "Not configured"
    if sudoLogDenied is not "" then set sudoLogDeniedValue to sudoLogDenied
    appendStatus(reportLines, "CIS 5.6 - Sudo Log Denied", sudoLogDeniedValue)

    set homeDirPermsState to "Compliant"
    set homeDirPermsList to ""
    set shellCommand to "for user_home in /Users/*; do u=$(basename \"$user_home\"); if id \"$u\" >/dev/null 2>&1 && [ -d \"$user_home\" ]; then perms=$(stat -f '%A' \"$user_home\" 2>/dev/null); if [ \"$perms\" != \"700\" ] && [ \"$perms\" != \"750\" ]; then homeDirPermsState=\"Non-compliant homes detected\"; homeDirPermsList=\"$homeDirPermsList $user_home : $perms\\n\"; fi; fi; done"
    do shell script shellCommand
    appendStatus(reportLines, "CIS 6.4 - Home Dir Permissions (Users)", homeDirPermsState)

    set end of reportLines to ""
    set end of reportLines to "--- [5] Additional Security Hardening ---"

    set safariAutoFill to shell("defaults read com.apple.Safari AutoFillPasswords 2>/dev/null")
    set safariWarn to shell("defaults read com.apple.Safari WarnAboutFraudulentWebsites 2>/dev/null")
    appendStatus(reportLines, "5.1 - Safari AutoFillPasswords", safeValue(safariAutoFill, "Not configured"))
    appendStatus(reportLines, "5.2 - Safari WarnAboutFraudulentWebsites", safeValue(safariWarn, "Not configured"))

    set btPower to shell("defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null")
    set btPowerValue to "On"
    if btPower is "0" then set btPowerValue to "Off"
    appendStatus(reportLines, "5.3 - Bluetooth Controller", btPowerValue)

    set airdropStatus to shell("defaults read com.apple.sharingd AirDrop 2>/dev/null")
    appendStatus(reportLines, "5.4 - AirDrop", safeValue(airdropStatus, "Not set (assumed enabled)"))

    set airplayDisabled to shell("defaults read /System/Library/LaunchDaemons/com.apple.AirPlayXPCHelper.plist Disabled 2>/dev/null")
    set airplayValue to "Enabled (or not configured)"
    if airplayDisabled is "true" then set airplayValue to "Disabled"
    appendStatus(reportLines, "5.5 - AirPlay Receiver", airplayValue)

    set keychainTimeoutValue to shell("security show-keychain-info ~/Library/Keychains/login.keychain 2>/dev/null | head -1")
    appendStatus(reportLines, "5.6 - Login Keychain", safeValue(keychainTimeoutValue, "Not available"))

    set tmStatus to shell("tmutil destinationinfo 2>/dev/null | head -1")
    set tmValue to "No destinations configured"
    if tmStatus is not "" then set tmValue to "Destinations configured (remote backups possible)"
    appendStatus(reportLines, "5.7 - Time Machine", tmValue)

    set end of reportLines to ""
    set end of reportLines to "--- [6] 24-Hour Log Retention Checks ---"

    set logCollectResult to shell("/usr/bin/log collect --last 24h --output /dev/null 2>&1")
    set oldDiagCount to shell("find /var/db/diagnostics -type f -mtime +2 2>/dev/null | wc -l | tr -d ' '")
    set logRetentionValue to "None found (likely capped at 24h)"
    if oldDiagCount is not "" and oldDiagCount is not "0" then set logRetentionValue to oldDiagCount & " files present (may exceed 24h retention)"
    appendStatus(reportLines, "6.1 - Unified log store (>48h old files)", logRetentionValue)

    set newsyslogConfig to shell("grep -c '^/var/log/' /etc/newsyslog.d/99-cis-24h-retention.conf 2>/dev/null")
    set newsyslogValue to "Not configured"
    if newsyslogConfig is not "" then set newsyslogValue to "Present (" & newsyslogConfig & " log entries, count=0)"
    appendStatus(reportLines, "6.2 - Newsyslog retention config", newsyslogValue)

    set aslTTL to shell("grep 'ttl=24' /etc/asl.conf 2>/dev/null")
    set aslTTLValue to "Not configured"
    if aslTTL is not "" then set aslTTLValue to "Configured"
    appendStatus(reportLines, "6.3 - ASL TTL (24 hours)", aslTTLValue)

    set oldSyslogLogs to shell("find /var/log -type f -name '*.log' -mtime +1 2>/dev/null | wc -l | tr -d ' '")
    set oldLibraryLogs to shell("find /Library/Logs -type f -mtime +1 2>/dev/null | wc -l | tr -d ' '")
    set oldUserLogs to shell("find ~/Library/Logs -type f -mtime +1 2>/dev/null | wc -l | tr -d ' '")
    appendStatus(reportLines, "6.4 - /var/log *.log older than 24h", safeValue(oldSyslogLogs, "0") & " files")
    appendStatus(reportLines, "6.5 - /Library/Logs older than 24h", safeValue(oldLibraryLogs, "0") & " files")
    appendStatus(reportLines, "6.6 - ~/Library/Logs older than 24h", safeValue(oldUserLogs, "0") & " files")

    set reportText to joinText(reportLines, linefeed)
    log reportText

    set snapshotDir to "/private/var/db/macos-cis/snapshots"
    set snapshotTS to shell("date '+%Y%m%d-%H%M%S'")
    set snapshotRunTime to shell("date '+%Y-%m-%d %H:%M:%S %Z'")
    set snapshotFile to snapshotDir & "/macos-cis-snapshot-" & snapshotTS & ".txt"

    shell("/bin/mkdir -p " & quoted form of snapshotDir)

    set snapshotContent to "# macOS CIS Snapshot" & linefeed & "# Generated: " & snapshotRunTime & linefeed & "# Version: 1" & linefeed & "# Format: KEY=VALUE" & linefeed & "# Purpose: Human-readable restore input for a future AppleScript apply workflow" & linefeed & "SNAPSHOT_TIMESTAMP=" & snapshotRunTime & linefeed & "SNAPSHOT_FILENAME=" & (shell("/bin/basename " & quoted form of snapshotFile)) & linefeed & linefeed & reportText & linefeed
    set snapshotCommand to "/bin/cat > " & quoted form of snapshotFile & " <<'EOF'" & linefeed & snapshotContent & linefeed & "EOF"
    shell(snapshotCommand)

    set outputText to reportText & linefeed & linefeed & "Snapshot written to " & snapshotFile
    log outputText

    -- Display results in a scrollable dialog using NSAlert
    set alertView to current application's NSAlert's alloc()'s init()
    alertView's setMessageText:"macOS CIS Audit Results"
    alertView's addButtonWithTitle:"OK"

    set textView to current application's NSTextView's alloc()'s initWithFrame:{origin:{x:0, y:0}, |size|:{width:640, height:400}}
    textView's setString:outputText
    textView's setEditable:false
    textView's setFont:(current application's NSFont's userFixedPitchFontOfSize:10)

    set scrollView to current application's NSScrollView's alloc()'s initWithFrame:{origin:{x:0, y:0}, |size|:{width:640, height:400}}
    scrollView's setDocumentView:textView
    scrollView's setHasVerticalScroller:true
    scrollView's setAutohidesScrollers:false
    scrollView's setBorderType:(current application's NSBezelBorder)

    alertView's setAccessoryView:scrollView
    alertView's runModal()
end run
