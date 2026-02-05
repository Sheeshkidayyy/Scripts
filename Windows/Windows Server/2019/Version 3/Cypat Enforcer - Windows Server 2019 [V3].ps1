# CYPat Enforcer - Windows Server 2019 Full Security & All-Audit Policies [V3] BIG BOY
# Made by Sheeshkidayyy github.com/sheeshkidayyy Also know as Sheesh
$Apply = $true
$AutoYes = $true
$VerbosePreference = "Continue"

function Check-Admin {
    $isAdmin = ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
    if (-not $isAdmin -and $Apply) {
        Write-Error "This script must be run as Administrator to apply changes. Re-run in elevated session."
        exit 1
    }
}

function Force-Action {
    param($Description, [scriptblock]$Action)
    Write-Host "[APPLY ] $Description" -ForegroundColor Green
    if ($Apply) {
        Try { & $Action; Write-Host "Success: $Description" -ForegroundColor Green } 
        Catch { Write-Warning "Failed to apply $Description : $_" }
    }
}

Check-Admin
Write-Host "CYPat Enforcer - APPLY mode active on Windows Server 2019"

# --- 1) Account Lockout Policy ---
Force-Action "Configure Account Lockout Policy" {
    net accounts /lockoutduration:60 /lockoutwindow:60 /lockoutthreshold:10
}

# --- 2) Password Policy ---
Force-Action "Set minimum password length = 10" {
    net accounts /minpwlen:10
}

Force-Action "Set minimum password age = 5, maximum = 30, enforce history = 20" {
    net accounts /minpwage:5 /maxpwage:30 /uniquepw:20
}

Force-Action "Disable storing passwords using reversible encryption (local only)" {
    $inf = @"
[Unicode]
Unicode=yes
[System Access]
ClearTextPassword = 0
"@

    $infPath    = Join-Path -Path $env:TEMP -ChildPath "cypat_password_cleartext.inf"
    $dbPath     = Join-Path -Path $env:TEMP -ChildPath "cypat_secedit.sdb"
    $exportPath = Join-Path -Path $env:TEMP -ChildPath "cypat_secpol_export.inf"

    try {
        $inf | Out-File -FilePath $infPath -Encoding ASCII -Force

        # Apply the INF to the local security policy
        secedit /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY | Out-Null

        Start-Sleep -Seconds 2

        # Export the effective local policy and verify ClearTextPassword
        secedit /export /cfg $exportPath 2>$null

        $match = Select-String -Path $exportPath -Pattern "ClearTextPassword" -SimpleMatch -ErrorAction SilentlyContinue
        if ($match -and $match.Line -match "ClearTextPassword\s*=\s*0") {
            Write-Host "Verified: 'Store passwords using reversible encryption' is DISABLED (ClearTextPassword = 0)." -ForegroundColor Green
        } else {
            Write-Warning "Verification: 'ClearTextPassword' is not 0 in exported local policy. A Group Policy may be overriding this setting."
            Write-Host "Exported policy saved at: $exportPath"
        }
    } catch {
        Write-Warning "Failed to apply/verify reversible password setting: $_"
    }
}

# --- 3) Require password expiration for all local users ---
Force-Action "Set all local users to require password expiration" {
    Get-LocalUser | ForEach-Object { Try { Set-LocalUser -Name $_.Name -PasswordExpires $true } Catch {} }
}

# --- 4) Disable anonymous enumeration of SAM accounts ---
Force-Action "Disable anonymous enumeration of SAM accounts" {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -PropertyType DWord -Value 1 -Force | Out-Null
}




# --- 5) Disable Autorun for USB drives ---
Force-Action "Disable Autorun for USB drives" {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWord -Force | Out-Null
}


# --- 6) Windows Update service (handled in section 11) ---

# --- 7) ADVANCED AUDIT POLICY: dynamic enumeration + apply Success & Failure ---
Write-Host "Capturing existing advanced audit settings (before)..." -ForegroundColor Cyan
$beforeFile = Join-Path $env:TEMP "cypat_audit_before.txt"
& auditpol /get /subcategory:* > $beforeFile 2>&1

Write-Host "Detecting available advanced audit subcategories..." -ForegroundColor Cyan
$rawList = (& auditpol /list /subcategory:* ) 2>&1

# --- 8) Trim and filter likely empty/header lines; we'll attempt to set each trimmed line and ignore failures.
# Filter out category-level items (which cause 0x57 errors) — only keep true subcategories
$categories = @("Account Logon", "Account Management", "Category/Subcategory", "Detailed Tracking", "DS Access", "Logon/Logoff", "Object Access", "Policy Change", "Privilege Use", "System")
$subcategories = $rawList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -ne " ") -and ($categories -notcontains $_) } | Sort-Object -Unique

Write-Host "Found $($subcategories.Count) entries to attempt." -ForegroundColor Cyan

foreach ($subcategory in $subcategories) {
    try {
        Write-Host "Enabling advanced audit on: $subcategory (Success & Failure)"
        # Some lines may not be valid subcategory names; auditpol will error — catch suppresses that.
        auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
    }
    catch {
        Write-Warning "Error applying advanced audit policy to: $subcategory — $_"
    }
}

Write-Host "Capturing advanced audit settings (after)..." -ForegroundColor Cyan
$afterFile = Join-Path $env:TEMP "cypat_audit_after.txt"
& auditpol /get /subcategory:* > $afterFile 2>&1

# --- 9) Save gpresult to help identify GPO overrides
Write-Host "Capturing Group Policy result (gpresult)..." -ForegroundColor Cyan
$gpFile = Join-Path $env:TEMP "cypat_gpresult.txt"
Try {
    gpresult /r > $gpFile 2>&1
} Catch {
    Write-Warning "Failed to run gpresult: $_"
}

Write-Host "Advanced audit apply step completed. Before/After saved to:" -ForegroundColor Green
Write-Host "  $beforeFile"
Write-Host "  $afterFile"
Write-Host "  $gpFile"

# --- 9.1) Verification: report subcategories still set to No Auditing and show gpresult ---
$reportFile = Join-Path $env:TEMP "cypat_audit_verify.txt"
Add-Content -Path $reportFile -Value ("Audit verification report - {0}" -f (Get-Date -Format o))

# --- 9.2) Show any subcategories still No Auditing
Add-Content -Path $reportFile -Value "== Subcategories with 'No Auditing' =="
$auditNo = Get-Content -Path $afterFile | Select-String -Pattern "No Auditing" -Context 1,0
if ($auditNo) {
    # write the matched lines and the preceding name line to report
    $auditNo | ForEach-Object {
        Add-Content -Path $reportFile -Value ($_.Context.PreContext + $_.Line)
        Add-Content -Path $reportFile -Value "----"
    }
    Write-Host "Some subcategories remain set to 'No Auditing'. See $reportFile" -ForegroundColor Yellow
} else {
    Add-Content -Path $reportFile -Value "All available subcategories show auditing configured (no 'No Auditing' matches)."
    Write-Host "All available advanced subcategories appear configured." -ForegroundColor Green
}

# --- 9.3) Save a small summary of gpresult (look for GPOs configuring Advanced Audit Policy)
Add-Content -Path $reportFile -Value "`n== Group Policy Summary (gpresult excerpt) =="
try {
    # show only lines mentioning Advanced Audit Policy or Security Settings to keep summary short
    Select-String -Path $gpFile -Pattern "Advanced Audit Policy|Security Settings|Audit" -SimpleMatch -Context 0,1 | ForEach-Object {
        Add-Content -Path $reportFile -Value ($_.Line)
    }
    Add-Content -Path $reportFile -Value "`nFull gpresult saved at: $gpFile"
} catch {
    Add-Content -Path $reportFile -Value "Failed to process gpresult: $_"
}

# --- 9.4) Optional: open the report automatically if running interactively
if (-not $DryRun) {
    Write-Host "Audit verification saved to: $reportFile"
    # Uncomment the following line to auto-open the report in Notepad (interactive sessions only)
    # Start-Process notepad.exe -ArgumentList $reportFile
}

# --- 10) Enable Windows Defender Real-time Protection ---
Force-Action "Enable Windows Defender Virus & Threat Protection" {
    Try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "Success: Windows Defender real-time protection enabled."
    } Catch {
        Write-Warning "Failed to enable Windows Defender real-time protection: $_"
    }
}

# --- 11) Automatic Windows Updates ---
Force-Action "Enable Automatic Windows Updates" {
    Try {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop

        $AUKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        If (-Not (Test-Path $AUKey)) { New-Item -Path $AUKey -Force | Out-Null }
        Set-ItemProperty -Path $AUKey -Name "AUOptions" -Value 4 -Force
        # Trigger an immediate scan/install attempt (best-effort)
        Try {
            Start-Process "wuauclt.exe" -ArgumentList "/detectnow" -NoNewWindow -Wait -ErrorAction Stop
            Start-Process "wuauclt.exe" -ArgumentList "/updatenow" -NoNewWindow -Wait -ErrorAction Stop
        } Catch {
            Write-Warning "Failed to trigger Windows Update via wuauclt: $_"
        }

        Write-Host "Automatic Windows Updates enabled and configured." -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to enable/configure automatic updates: $_"
    }
}

# --- 12) Disable Microsoft FTP Server Service ---
Force-Action "Disable Microsoft FTP Server Service" {
    Try {
        $ftpService = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
        if ($ftpService -and $ftpService.Status -ne 'Stopped') {
            Stop-Service -Name FTPSVC -Force -ErrorAction Stop
            Write-Host "Microsoft FTP Server service stopped." -ForegroundColor Green
        }

        if ($ftpService) {
            Set-Service -Name FTPSVC -StartupType Disabled -ErrorAction Stop
            Write-Host "Microsoft FTP Server service disabled." -ForegroundColor Green
        } else {
            Write-Host "Microsoft FTP Server service not installed, nothing to disable." -ForegroundColor Yellow
        }
    } Catch {
        Write-Warning "Failed to stop/disable Microsoft FTP Server service: $_"
    }
}

# --- 13) Disable & Stop Simple Mail Transfer Protocol (SMTP) Service ---
Force-Action "Disable Simple Mail Transfer Protocol (SMTP) Service" {
    Try {
        # Common SMTP service name for the built-in IIS SMTP service
        $smtpService = Get-Service -Name SMTPSVC -ErrorAction SilentlyContinue

        if ($smtpService) {
            if ($smtpService.Status -ne 'Stopped') {
                Stop-Service -Name SMTPSVC -Force -ErrorAction Stop
                Write-Host "SMTP service stopped." -ForegroundColor Green
            }
            Set-Service -Name SMTPSVC -StartupType Disabled -ErrorAction Stop
            Write-Host "SMTP service disabled." -ForegroundColor Green
        } else {
            Write-Host "SMTP service (SMTPSVC) not installed on this server." -ForegroundColor Yellow
        }

        # Optional: remove the Windows feature if present (Server Manager)
        $smtpFeature = Get-WindowsFeature -Name SMTP-Server -ErrorAction SilentlyContinue
        if ($smtpFeature -and $smtpFeature.Installed) {
            Uninstall-WindowsFeature -Name SMTP-Server -ErrorAction Stop
            Write-Host "SMTP Server Windows feature removed." -ForegroundColor Green
        }
    } Catch {
        Write-Warning "Failed to stop/disable/remove SMTP service/feature: $_"
    }
}

# --- 14) Limit local use of blank passwords to console only ---
Force-Action "Limit local use of blank passwords to console only" {
    Try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Configured: LimitBlankPasswordUse = 1" -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to set LimitBlankPasswordUse: $_"
    }
}

# --- 14.5) Require Ctrl+Alt+Delete for login (Secure Attention Sequence) ---
Force-Action "Enable Ctrl+Alt+Delete requirement for login" {
    Try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host "Configured: Ctrl+Alt+Delete logon requirement ENABLED (SAS protected)" -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to enable Ctrl+Alt+Delete requirement: $_"
    }
}

# --- 15) Enable 'Microsoft network server: Digitally sign communications (always)' ---
Force-Action "Enable Microsoft network server: Digitally sign communications (always)" {
    Try {
        # Enable SMB signing on the server (enforce signing)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Configured: RequireSecuritySignature = 1 and EnableSecuritySignature = 1" -ForegroundColor Green

        # Try to restart the Server service to apply immediately (may disrupt SMB sessions)
        Try {
            Restart-Service -Name LanmanServer -Force -ErrorAction Stop
            Write-Host "Server service restarted to apply SMB signing settings." -ForegroundColor Green
        } Catch {
            Write-Warning "Could not restart LanmanServer service automatically: $_. A reboot may be required to apply the setting."
        }
    } Catch {
        Write-Warning "Failed to enable SMB server signing: $_"
    }
}

# --- 16) Disable SMB v1 (legacy insecure protocol) ---
Force-Action "Disable SMB v1 protocol" {
    Try {
        # Disable SMB v1 via registry (applies to both server and client)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host "Configured: SMB v1 disabled (SMB1 = 0)" -ForegroundColor Green

        # Optional: remove the SMB 1.0/CIFS feature on Server 2019 (if installed)
        $smbv1Feature = Get-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue
        if ($smbv1Feature -and $smbv1Feature.Installed) {
            Try {
                Uninstall-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
                Write-Host "SMB 1.0/CIFS Windows feature removed." -ForegroundColor Green
            } Catch {
                Write-Warning "Could not uninstall FS-SMB1 feature: $_"
            }
        } else {
            Write-Host "SMB 1.0/CIFS feature not installed (nothing to remove)." -ForegroundColor Yellow
        }
    } Catch {
        Write-Warning "Failed to disable SMB v1: $_"
    }
}

# --- 17) Browser Security (Firefox & Chrome) ---
Force-Action "Harden Browsers (Disable Password Saving)" {
    # 1. Firefox Hardening via Registry
    $ffPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
    if (-not (Test-Path $ffPath)) { New-Item -Path $ffPath -Force | Out-Null }
    
    # Disable Password Manager and the 'Offer to Save' prompt
    New-ItemProperty -Path $ffPath -Name "PasswordManagerEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ffPath -Name "OfferToSaveLogins" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ffPath -Name "OfferToSaveLoginsDefault" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "Firefox: Password Manager DISABLED." -ForegroundColor Green

    # 19.5. Chrome Hardening (Just in case they switch browsers)
    $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $chromePath)) { New-Item -Path $chromePath -Force | Out-Null }
    New-ItemProperty -Path $chromePath -Name "PasswordManagerEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "Chrome: Password Manager DISABLED." -ForegroundColor Green
}

# --- 17.5) Browser Extension Audit (Firefox & Chrome) ---
Write-Host "`n--- BROWSER EXTENSION AUDIT ---" -ForegroundColor Cyan
$extensionReport = Join-Path $env:TEMP "cypat_browser_extensions.txt"
Add-Content -Path $extensionReport -Value ("Browser Extension Audit Report - {0}" -f (Get-Date -Format o))

# Firefox Extensions Check
Add-Content -Path $extensionReport -Value "`n== FIREFOX EXTENSIONS =="
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $firefoxProfilePath) {
    $extensionsFound = $false
    Get-ChildItem -Path $firefoxProfilePath -Directory | ForEach-Object {
        $extensionsJsonPath = Join-Path $_.FullName "extensions.json"
        if (Test-Path $extensionsJsonPath) {
            Try {
                $extensionsJson = Get-Content $extensionsJsonPath | ConvertFrom-Json
                if ($extensionsJson.addons -and $extensionsJson.addons.Count -gt 0) {
                    $extensionsFound = $true
                    Add-Content -Path $extensionReport -Value "Profile: $($_.Name)"
                    $extensionsJson.addons | ForEach-Object {
                        Add-Content -Path $extensionReport -Value "  - $($_.name) (ID: $($_.id))"
                    }
                }
            } Catch {
                Write-Warning "Could not parse Firefox extensions.json: $_"
            }
        }
    }
    if (-not $extensionsFound) {
        Add-Content -Path $extensionReport -Value "No extensions found."
    }
} else {
    Add-Content -Path $extensionReport -Value "Firefox profiles not found."
}

# Chrome Extensions Check
Add-Content -Path $extensionReport -Value "`n== CHROME/EDGE EXTENSIONS =="
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
$edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

$extensionsFound = $false
foreach ($extPath in @($chromeExtPath, $edgeExtPath)) {
    if (Test-Path $extPath) {
        $browserName = if ($extPath -match "Chrome") { "Chrome" } else { "Edge" }
        Add-Content -Path $extensionReport -Value "`n$browserName Extensions:"
        
        Get-ChildItem -Path $extPath -Directory | ForEach-Object {
            $manifestPath = Join-Path $_.FullName "*/manifest.json" | Get-Item -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($manifestPath) {
                Try {
                    $manifest = Get-Content $manifestPath.FullName | ConvertFrom-Json
                    Add-Content -Path $extensionReport -Value "  - $($manifest.name) (ID: $($_.Name))"
                    $extensionsFound = $true
                } Catch {
                    Add-Content -Path $extensionReport -Value "  - Extension ID: $($_.Name) (unable to read name)"
                }
            }
        }
    }
}

if (-not $extensionsFound) {
    Add-Content -Path $extensionReport -Value "No Chrome/Edge extensions found."
}

Write-Host "Browser extension audit saved to: $extensionReport" -ForegroundColor Green
Write-Host "REMINDER: Review extensions for unauthorized or suspicious add-ons." -ForegroundColor Yellow

# --- 18) File Sharing Audit (Disable Unauthorized Shares) ---
Force-Action "Audit and Disable Non-Administrative Shares" {
    # Get all shares that are NOT default administrative shares (C$, ADMIN$, IPC$, etc.)
    # System shares end with $ and cannot be removed — filter them out explicitly
    $unauthorizedShares = Get-SmbShare | Where-Object { -not $_.IsSpecial -and $_.Name -notlike '*$' }

    if ($unauthorizedShares) {
        foreach ($share in $unauthorizedShares) {
            Write-Host "FOUND UNAUTHORIZED SHARE: $($share.Name) at $($share.Path)" -ForegroundColor Yellow
            # Stop the share (Matches the 'Stop Sharing' action in the key)
            Remove-SmbShare -Name $share.Name -Force
            Write-Host "SUCCESS: Share '$($share.Name)' has been removed." -ForegroundColor Green
        }
    } else {
        Write-Host "No unauthorized non-admin shares found." -ForegroundColor Green
    }
}


# --- 19) Local Security & LSA ---

# --- 20) FIREWALL HARDENING (ADVANCED) ---
Force-Action "Reset and Harden Windows Firewall" {
    # Wipe any malicious rules added by a hacker
    netsh advfirewall reset
    # Enable and Block all incoming by default
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
    # Ensure RDP is still allowed since it is a Critical Service
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
}

Force-Action "Disable Prohibited Services (Xbox, RetailDemo)" {
    $badSvc = @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "RetailDemo")
    foreach ($srv in $badSvc) {
        if (Get-Service -Name $srv -ErrorAction SilentlyContinue) {
            Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            Set-Service -Name $srv -StartupType Disabled
        }
    }
}

Force-Action "Disable Legacy & P2P Services (Telnet, Routing, Peer-to-Peer)" {
    $legacySvc = @("TlntSvr", "Rasman", "p2psvc", "PNRPsvc", "p2pimsvc")
    foreach ($srv in $legacySvc) {
        $service = Get-Service -Name $srv -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $srv -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "$srv disabled." -ForegroundColor Green
        }
    }
}

# --- 21-23) Advanced Audit / SMB / File-sharing deduplicated above

# --- 24) ADVANCED NETWORKING HARDENING ---
Force-Action "Disable Insecure Protocols (LLMNR & NetBIOS)" {
    # Disable LLMNR
    $dnscPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnscPath)) { New-Item -Path $dnscPath -Force | Out-Null }
    New-ItemProperty -Path $dnscPath -Name "EnableMulticast" -Value 0 -Force | Out-Null

    # Disable NetBIOS over TCP/IP
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regPath | ForEach-Object { Set-ItemProperty -Path "HKLM:\$($_.Name)" -Name "NetbiosOptions" -Value 2 -Force | Out-Null }
}

Force-Action "Cleanse Hosts File & Disable Remote Assistance" {
    #  26.33)Reset Hosts file to default (removes redirects)
    $hosts = "127.0.0.1 localhost`n::1 localhost"
    $hosts | Out-File -FilePath "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding ASCII -Force | Out-Null
    # 26.66) Disable Remote Assistance (but keep RDP)
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    if (Test-Path $raPath) {
        Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Force
    } else {
        Write-Host "Remote Assistance registry path not found; skipping." -ForegroundColor Yellow
    }
}

# --- 25) BITLOCKER CHECK & REMINDER ---
Write-Host "`n--- BITLOCKER STATUS CHECK ---" -ForegroundColor Cyan
Try {
    $bitlockerFeature = Get-WindowsFeature -Name BitLocker -ErrorAction SilentlyContinue
    if ($bitlockerFeature -and $bitlockerFeature.Installed) {
        Write-Host "BitLocker feature: INSTALLED" -ForegroundColor Green
        
        $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bitlockerStatus) {
            if ($bitlockerStatus.ProtectionStatus -eq "On") {
                Write-Host "BitLocker C: drive: ENABLED ✓" -ForegroundColor Green
                Write-Host "Encryption method: $($bitlockerStatus.EncryptionMethod)" -ForegroundColor Green
            } else {
                Write-Host "BitLocker C: drive: DISABLED (not encrypted)" -ForegroundColor Yellow
                Write-Host "REMINDER: To enable BitLocker, run as admin:" -ForegroundColor Yellow
                Write-Host "  Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly" -ForegroundColor Cyan
            }
        }
    } else {
        Write-Host "BitLocker feature: NOT INSTALLED" -ForegroundColor Yellow
        Write-Host "REMINDER: To install and enable BitLocker, run as admin:" -ForegroundColor Yellow
        Write-Host "  Install-WindowsFeature -Name BitLocker -IncludeManagementTools" -ForegroundColor Cyan
        Write-Host "  Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly" -ForegroundColor Cyan
    }
} Catch {
    Write-Warning "Unable to check BitLocker status: $_"
}

function Find-ProhibitedFiles {
    <#
    Non-destructive scan for many media, document, archive, script and executable extensions.
    - Default scans common locations on all filesystem drives (Users, ProgramData, Program Files, Program Files (x86), and root).
    - You can override ScanRoots or pass ExtraPaths to add locations.
    - This function DOES NOT move/copy/delete files. It only reports and logs full file paths.
    #>

    param(
        [string[]]$ScanRoots = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Root }),
        [string[]]$ExtraPaths = @(),
        [string[]]$ExcludePaths = @(${env:SystemRoot}, $env:ProgramFiles, ${env:ProgramFiles(x86)})
    )

    Write-Host "`n--- STARTING EXPANDED DEEP SCAN FOR MEDIA, SCRIPTS & EXECUTABLES (READ-ONLY) ---" -ForegroundColor Magenta
    Write-Host "Default scan roots: $($ScanRoots -join ', ')" -ForegroundColor Gray

    # Categories (extensions WITHOUT leading dot)
    $videoExt   = @("mp4","avi","mov","mkv","wmv","flv","mpg","mpeg","m4v","webm","3gp","3g2","ts","m2ts","ogv","vob")
    $audioExt   = @("mp3","wav","m4a","flac","aac","ogg","wma","aiff","alac","opus")
    $scriptExt  = @("ps1","psm1","bat","cmd","vbs","vbe","js","jse","wsf","wsh","py","pl","rb","php","sh","psd1")
    $imageExt   = @("jpg","jpeg","png","gif","bmp","tiff","svg","webp","heic")
    $archiveExt = @("zip","rar","7z","tar","gz","bz2","xz","iso","msi")
    $documentExt= @("doc","docx","xls","xlsx","ppt","pptx","pdf","odt","ods","odp","rtf","txt","csv","md","tex")
    $exeExt     = @("exe","dll","bin","com","msi","scr","sys")  # executables / binaries

    $allExtensions = ($videoExt + $audioExt + $scriptExt + $imageExt + $archiveExt + $documentExt + $exeExt) | Sort-Object -Unique

    # Build scan path list
    $scanPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $ScanRoots) {
        if (-not $root) { continue }
        $candidates = @(
            (Join-Path $root "Users"),
            (Join-Path $root "ProgramData"),
            (Join-Path $root "Program Files"),
            (Join-Path $root "Program Files (x86)"),
            $root.TrimEnd('\')  # root (e.g., C:\)
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

        foreach ($p in $candidates) {
            $scanPaths.Add($p)
        }
    }

    foreach ($p in $ExtraPaths) { if ($p -and (Test-Path $p)) { $scanPaths.Add($p) } }

    # Apply exclusions (case-insensitive startswith)
    $scanPaths = $scanPaths | Where-Object {
        $exclude = $false
        foreach ($ex in $ExcludePaths) {
            if (-not $ex) { continue }
            if ($_.StartsWith($ex, [System.StringComparison]::InvariantCultureIgnoreCase)) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -Unique

    if (-not $scanPaths -or $scanPaths.Count -eq 0) {
        Write-Host "No valid scan paths found after applying excludes. Exiting." -ForegroundColor Yellow
        return
    }

    $reportFile = Join-Path $env:TEMP "cypat_prohibited_scan_report.txt"
    # Overwrite report header for each run
    Set-Content -Path $reportFile -Value ("Prohibited file scan report - {0}`nScan started: {1}`n" -f (Get-Date -Format o), (Get-Date)) -Encoding UTF8
    Add-Content -Path $reportFile -Value ("Scan paths: {0}`nPatterns: {1}`nResults:`n" -f ($scanPaths -join ', '), ($allExtensions -join ', '))

    # Counters
    $counts = [ordered]@{
        Scripts = 0
        Media = 0
        Images = 0
        Archives = 0
        Documents = 0
        Executables = 0
        Other = 0
        Errors = 0
    }

    foreach ($rootPath in $scanPaths) {
        Write-Host "`nScanning: $rootPath" -ForegroundColor Cyan
        try {
            $items = Get-ChildItem -Path $rootPath -Recurse -File -ErrorAction SilentlyContinue
            if (-not $items) { continue }

            foreach ($file in $items) {
                try {
                    $extNoDot = $file.Extension.TrimStart('.').ToLower()
                    if ([string]::IsNullOrEmpty($extNoDot)) { continue }

                    if ($scriptExt -contains $extNoDot) {
                        Write-Host "[POTENTIAL SCRIPT] $($file.FullName)" -ForegroundColor Red
                        Add-Content -Path $reportFile -Value ("[SCRIPT] {0}" -f $file.FullName)
                        $counts.Scripts++
                    }
                    elseif ($videoExt -contains $extNoDot -or $audioExt -contains $extNoDot) {
                        Write-Host "[MEDIA] $($file.FullName)" -ForegroundColor Yellow
                        Add-Content -Path $reportFile -Value ("[MEDIA] {0}" -f $file.FullName)
                        $counts.Media++
                    }
                    elseif ($imageExt -contains $extNoDot) {
                        Write-Host "[IMAGE] $($file.FullName)" -ForegroundColor Cyan
                        Add-Content -Path $reportFile -Value ("[IMAGE] {0}" -f $file.FullName)
                        $counts.Images++
                    }
                    elseif ($archiveExt -contains $extNoDot) {
                        Write-Host "[ARCHIVE] $($file.FullName)" -ForegroundColor Magenta
                        Add-Content -Path $reportFile -Value ("[ARCHIVE] {0}" -f $file.FullName)
                        $counts.Archives++
                    }
                    elseif ($documentExt -contains $extNoDot) {
                        Write-Host "[DOCUMENT] $($file.FullName)" -ForegroundColor Gray
                        Add-Content -Path $reportFile -Value ("[DOCUMENT] {0}" -f $file.FullName)
                        $counts.Documents++
                    }
                    elseif ($exeExt -contains $extNoDot) {
                        Write-Host "[EXECUTABLE] $($file.FullName)" -ForegroundColor DarkRed
                        Add-Content -Path $reportFile -Value ("[EXECUTABLE] {0}" -f $file.FullName)
                        $counts.Executables++
                    }
                    elseif ($allExtensions -contains $extNoDot) {
                        Write-Host "[OTHER MATCH] $($file.FullName)" -ForegroundColor White
                        Add-Content -Path $reportFile -Value ("[OTHER] {0}" -f $file.FullName)
                        $counts.Other++
                    }
                } catch {
                    $counts.Errors++
                    $msg = ("Error processing file {0}: {1}" -f $file.FullName, $_.Exception.Message)
                    Add-Content -Path $reportFile -Value $msg
                }
            }
        } catch {
            Write-Warning "Failed to recursively enumerate $rootPath : $_"
            Add-Content -Path $reportFile -Value ("Failed to enumerate path {0}: {1}" -f $rootPath, $_.Exception.Message)
        }
    }

    # Summary
    Add-Content -Path $reportFile -Value "`nSummary:`n"
    foreach ($k in $counts.Keys) {
        $line = "{0,-12} : {1}" -f $k, $counts[$k]
        Add-Content -Path $reportFile -Value $line
    }

    Write-Host "`nSearch Complete. Summary:" -ForegroundColor Magenta
    $counts.GetEnumerator() | ForEach-Object { Write-Host ("{0,-12} : {1}" -f $_.Name, $_.Value) }
    Write-Host "Full report saved to: $reportFile" -ForegroundColor Green
    Write-Host "CRITICAL: Do NOT delete files unless you are 100% sure they are prohibited." -ForegroundColor White
}

Write-Host "CYPat Enforcer finished. All security policies and advanced audit policies attempted." -ForegroundColor Green





