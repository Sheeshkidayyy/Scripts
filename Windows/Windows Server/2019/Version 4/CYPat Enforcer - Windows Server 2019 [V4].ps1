#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Windows Server 2019 V4 - human-audit-first hardening helper.

.DESCRIPTION
    Runs in audit mode by default. Use -Apply -Yes to permit approved policy
    changes. Every installed service that V4 can start or stop is presented as
    an interactive Y/N decision in Apply mode; Audit mode records the decision
    for the orange Human Review List without changing the machine.

    V4 never removes user accounts, group members, software, files, shares,
    certificates, firewall rules, or Windows updates. It does not install roles
    or features. Review the competition scenario before choosing Y or N.

.EXAMPLE
    .\CYPat_Enforcer_Server_V4_WS2019.ps1

.EXAMPLE
    .\CYPat_Enforcer_Server_V4_WS2019.ps1 -Apply -Yes -CreateBaseline
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$Yes,
    [switch]$CreateBaseline,
    [string]$BaselinePath = ''
)

if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
    $baselineFolder = Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($baselineFolder)) { $baselineFolder = (Get-Location).Path }
    $BaselinePath = Join-Path -Path $baselineFolder -ChildPath 'CYPat-WS2019-Baseline.json'
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if ($Apply -and -not $Yes) {
    throw 'Apply mode requires both -Apply and -Yes. Run without -Apply for audit-only mode.'
}
if ($Apply -and -not $PSBoundParameters.ContainsKey('Confirm')) { $ConfirmPreference = 'None' }

$script:Mode = if ($Apply) { 'APPLY' } else { 'AUDIT' }
$script:Review = [System.Collections.Generic.List[object]]::new()
$script:Changes = [System.Collections.Generic.List[object]]::new()
$script:Passed = 0
$script:ServiceDecisions = [ordered]@{}

function Write-Status {
    param([ValidateSet('OK','INFO','ORANGE','CHANGE')][string]$Kind, [string]$Message)
    $color = @{ OK='Green'; INFO='Cyan'; ORANGE='DarkYellow'; CHANGE='Yellow' }[$Kind]
    Write-Host "[$(Get-Date -Format HH:mm:ss)][$Kind] $Message" -ForegroundColor $color
}
function Add-Review {
    param([string]$Category,[string]$ReviewItem,[string]$ReviewEvidence,[string]$ReviewQuestion)
    $entry = [pscustomobject]@{ Category=$Category; Item=$ReviewItem; Evidence=$ReviewEvidence; Question=$ReviewQuestion }
    $script:Review.Add($entry)
}
function Add-Change {
    param([string]$Item,[string]$Result)
    $script:Changes.Add([pscustomobject]@{ Item=$Item; Result=$Result })
    Write-Status CHANGE "$Item - $Result"
}
function Invoke-GuardedChange {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([string]$Item,[scriptblock]$Action,[scriptblock]$Verify)
    if (-not $Apply) { return }
    if (-not $PSCmdlet.ShouldProcess($Item, 'Apply approved configuration')) { return }
    try {
        & $Action
        if (& $Verify) { Add-Change $Item 'Applied and verified' }
        else { Add-Review 'Verification' $Item 'The command completed but verification failed.' 'Check this setting manually.' }
    } catch {
        Add-Review 'Apply failure' $Item $_.Exception.Message 'Correct manually or restore the required service configuration.'
    }
}
function Set-RegistryValue {
    param([string]$Category,[string]$Path,[string]$Name,[object]$Value,[ValidateSet('DWord','String')][string]$Type='DWord')
    $current = try { Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop } catch { $null }
    if ($current -eq $Value) { $script:Passed++; return }
    Add-Review $Category $Name "Current='$current'; expected='$Value'" 'Apply the approved baseline?'
    $p=$Path; $n=$Name; $v=$Value; $t=$Type
    Invoke-GuardedChange "$Category / $Name" {
        if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force | Out-Null }
        New-ItemProperty -LiteralPath $p -Name $n -Value $v -PropertyType $t -Force -ErrorAction Stop | Out-Null
    } { (Get-ItemPropertyValue -LiteralPath $p -Name $n -ErrorAction SilentlyContinue) -eq $v }
}
function Read-YesNo {
    param([string]$Prompt)
    while ($true) {
        $response = (Read-Host "$Prompt [Y/N]").Trim()
        if ($response -match '^(?i:y|yes)$') { return $true }
        if ($response -match '^(?i:n|no)$') { return $false }
        Write-Host 'Enter Y or N.' -ForegroundColor Yellow
    }
}
function Get-ServiceState {
    param([string[]]$Names)
    @(foreach ($name in $Names) { Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue })
}
function Invoke-ServiceDecision {
    param([string]$Label,[string[]]$Names,[string]$Warning,[switch]$Rdp)
    $services = @(Get-ServiceState $Names)
    if (-not $services.Count -and -not $Rdp) { Write-Status INFO "$Label is not installed (N/A)."; return }
    $state = if ($Rdp) {
        if ((Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' -ErrorAction SilentlyContinue) -eq 0) {'enabled'} else {'disabled'}
    } else { ($services | ForEach-Object { "$($_.Name)=$($_.State)/$($_.StartMode)" }) -join '; ' }
    Add-Review 'Service decision' $Label "Current state: $state" "$Warning Choose whether this service should be enabled."
    $enable = Read-YesNo "Should $Label be enabled"
    $script:ServiceDecisions[$Label] = if ($enable) { 'Yes' } else { 'No' }
    if (-not $Apply) { return }
    $actionText = if ($enable) { 'enable' } else { 'disable' }
    $rdpValue = if ($enable) { 0 } else { 1 }
    if ($Rdp) {
        Invoke-GuardedChange "RDP $actionText" {
            Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value $rdpValue -Type DWord -Force
            if ($enable) { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue } else { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue }
        } { ((Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections -ErrorAction SilentlyContinue) -eq $rdpValue) }
        return
    }
    foreach ($service in $services) {
        $name=$service.Name
        Invoke-GuardedChange "$Label / $name $actionText" {
            if ($enable) { Set-Service -Name $name -StartupType Automatic -ErrorAction Stop; Start-Service -Name $name -ErrorAction Stop }
            else { Stop-Service -Name $name -Force -ErrorAction Stop; Set-Service -Name $name -StartupType Disabled -ErrorAction Stop }
        } {
            $verify=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
            if ($enable) { $verify -and $verify.State -eq 'Running' } else { $verify -and $verify.State -ne 'Running' -and $verify.StartMode -eq 'Disabled' }
        }
    }
}
function Get-BaselineObject {
    $accounts = @(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,PasswordNeverExpires,PasswordRequired)
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass)
    $services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,State,StartMode,StartName)
    $firewall = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Select-Object DisplayName,Profile,Direction,Action)
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskPath,TaskName,State)
    [pscustomobject]@{ Created=(Get-Date).ToString('o'); Computer=$env:COMPUTERNAME; Accounts=$accounts; Administrators=$admins; Services=$services; InboundAllowRules=$firewall; Tasks=$tasks }
}

Write-Status INFO "CYPat Enforcer V4 - Windows Server 2019 - $script:Mode mode"
Write-Status INFO 'No accounts, groups, software, files, shares, certificates, firewall rules, or updates are removed automatically.'

# Human account and group audit.
Write-Status INFO '=== ACCOUNTS AND GROUPS ==='
foreach ($user in Get-LocalUser -ErrorAction SilentlyContinue) {
    $neverExpiresProperty = $user.PSObject.Properties['PasswordNeverExpires']
    $neverExpires = if ($neverExpiresProperty) { $neverExpiresProperty.Value } else { 'Unavailable' }
    if ($user.Enabled -and ((-not $user.PasswordRequired) -or $neverExpires -eq $true -or $user.Name -eq 'Guest')) {
        Add-Review 'Account exception' $user.Name "PasswordRequired=$($user.PasswordRequired); NeverExpires=$neverExpires" 'Verify this account is authorized and secured.'
    }
}
foreach ($group in 'Administrators','Remote Desktop Users','Backup Operators','Server Operators','Account Operators','Print Operators') {
    $members = @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($members.Count) {
        Add-Review 'Privileged group' $group ($members -join ', ') 'Verify these memberships against the scenario.'
    }
}
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4 -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,LastLogonDate -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Review 'Active Directory account' $_.SamAccountName "Enabled=$($_.Enabled); NeverExpires=$($_.PasswordNeverExpires); PasswordNotRequired=$($_.PasswordNotRequired); LastLogon=$($_.LastLogonDate)" 'Is this domain account authorized?'
    }
}

# Account policy and security options.
Write-Status INFO '=== POLICY AND ACCESS AUDIT ==='
$policyPath = Join-Path $env:TEMP 'cypat-v4-security-policy.inf'
secedit.exe /export /cfg $policyPath /areas SECURITYPOLICY USER_RIGHTS 2>$null | Out-Null
if (Test-Path $policyPath) {
    $policy = Get-Content $policyPath -Raw
    foreach ($setting in @('MinimumPasswordLength','PasswordComplexity','PasswordHistorySize','MaximumPasswordAge','LockoutBadCount','ClearTextPassword')) {
        $line=[regex]::Match($policy,"(?m)^$setting\s*=\s*(.*)$")
        Add-Review 'Account policy' $setting ($line.Groups[1].Value) 'Does this meet the scenario requirement?'
    }
    foreach ($right in @('SeRemoteInteractiveLogonRight','SeNetworkLogonRight','SeServiceLogonRight','SeBatchLogonRight','SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyInteractiveLogonRight','SeDenyServiceLogonRight')) {
        $line=[regex]::Match($policy,"(?m)^$right\s*=\s*(.*)$")
        Add-Review 'Access right' $right ($line.Groups[1].Value) 'Are all assigned SIDs and deny rules expected?'
    }
}

$registryBaseline=@(
    @('Security Options','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA',1),
    @('Security Options','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','DontDisplayLastUserName',1),
    @('Security Options','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LimitBlankPasswordUse',1),
    @('Security Options','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','NoLMHash',1),
    @('Security Options','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel',5),
    @('Name Resolution','HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast',0),
    @('AutoPlay','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
    @('SMB','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature',1),
    @('SMB','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters','RequireSecuritySignature',1),
    @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging',1),
    @('Remote Assistance','HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowToGetHelp',0)
)
foreach($item in $registryBaseline){ Set-RegistryValue $item[0] $item[1] $item[2] $item[3] }

# Audit policy, firewall, remote management, and SMB.
Write-Status INFO '=== NETWORK, FIREWALL, SMB, AND WINRM ==='
foreach($sub in 'Logon','Account Lockout','User Account Management','Security Group Management','Process Creation','Audit Policy Change','Sensitive Privilege Use','System Integrity') {
    $auditState = (auditpol.exe /get /subcategory:"$sub" /r 2>$null | Out-String).Trim()
    if ($auditState -match 'No Auditing') { Add-Review 'Advanced audit policy' $sub $auditState 'Enable the required success/failure auditing.' } else { $script:Passed++ }
}
foreach($profile in Get-NetFirewallProfile -ErrorAction SilentlyContinue){
    if(-not $profile.Enabled -or $profile.DefaultInboundAction -ne 'Block'){
        Add-Review 'Firewall' $profile.Name "Enabled=$($profile.Enabled); Inbound=$($profile.DefaultInboundAction)" 'Apply enabled firewall with default inbound block?'
        $name=$profile.Name
        Invoke-GuardedChange "Firewall $name" { Set-NetFirewallProfile -Profile $name -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -ErrorAction Stop } { (Get-NetFirewallProfile -Name $name).Enabled }
    } else { $script:Passed++ }
}
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | ForEach-Object {
    $port=$_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $addr=$_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    $ports = @($port.LocalPort)
    $risky = @('Any',21,23,25,69,110,135,137,138,139,161,162,445,3389,5900,5985,5986)
    if (($ports | Where-Object { $_ -in $risky }) -or (@($addr.RemoteAddress) -contains 'Any' -and $ports -contains 'Any')) {
        Add-Review 'Firewall allow rule' $_.DisplayName "Protocol=$($port.Protocol -join ','); Port=$($ports -join ','); Remote=$($addr.RemoteAddress -join ',')" 'Verify this exposed rule is required.'
    }
}
try {
    $smb=Get-SmbServerConfiguration
    Add-Review 'SMB' 'Server configuration' "SMB1=$($smb.EnableSMB1Protocol); Signing=$($smb.RequireSecuritySignature); Encryption=$($smb.EncryptData); Guest=$($smb.EnableAuthenticateUserSharing)" 'Are these SMB settings appropriate for the scenario?'
    foreach($share in Get-SmbShare -ErrorAction SilentlyContinue){
        foreach($access in Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue | Where-Object {$_.AccountName -match 'Everyone|ANONYMOUS LOGON'}){
            Add-Review 'SMB share permission' $share.Name "$($access.AccountName)=$($access.AccessRight); Path=$($share.Path)" 'Is this access explicitly required?'
        }
    }
    Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object { Add-Review 'SMB session' $_.ClientUserName "Client=$($_.ClientComputerName); Encrypted=$($_.Encrypted)" 'Is this session expected?' }
} catch { Add-Review 'SMB' 'Configuration unavailable' $_.Exception.Message 'Review SMB manually.' }
try {
    Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | ForEach-Object { Add-Review 'WinRM listener' $_.Keys "Transport=$($_.Keys -join '; ')" 'Is this listener required and securely scoped?' }
    $winrm=Get-Item WSMan:\localhost\Service\Auth\* -ErrorAction SilentlyContinue
    $winrm | ForEach-Object { Add-Review 'WinRM authentication' $_.Name "Enabled=$($_.Value)" 'Is this authentication method required?' }
    $trusted=(Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if($trusted){ Add-Review 'WinRM' 'TrustedHosts' $trusted 'Is every trusted host required?' }
} catch { Write-Status INFO 'WinRM is not configured; no listener audit is needed.' }

# Browser hardening. Firefox policies are only written when Firefox is installed.
Write-Status INFO '=== BROWSER SECURITY ==='
$browsers=@{
    Chrome=@('HKLM:\SOFTWARE\Policies\Google\Chrome');
    Edge=@('HKLM:\SOFTWARE\Policies\Microsoft\Edge')
}
foreach($browser in $browsers.Keys){
    $path=$browsers[$browser][0]
    $installed=if($browser -eq 'Chrome'){(Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe') -or (Test-Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe')}else{(Test-Path 'C:\Program Files\Microsoft\Edge\Application\msedge.exe') -or (Test-Path 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')}
    if(-not $installed){Write-Status INFO "$browser is not installed (N/A).";continue}
    foreach($setting in @(@('SafeBrowsingProtectionLevel',2),@('PasswordManagerEnabled',0),@('DefaultPopupsSetting',2),@('BlockThirdPartyCookies',1))){Set-RegistryValue "$browser policy" $path $setting[0] $setting[1]}
}
$firefoxExe=@('C:\Program Files\Mozilla Firefox\firefox.exe','C:\Program Files (x86)\Mozilla Firefox\firefox.exe')|Where-Object{Test-Path $_}|Select-Object -First 1
if($firefoxExe){
    $firefoxPolicy=Join-Path (Split-Path $firefoxExe) 'distribution\policies.json'
    Add-Review 'Firefox policy' $firefoxPolicy "Exists=$(Test-Path $firefoxPolicy)" 'Apply recommended Firefox enterprise policies?'
    Invoke-GuardedChange 'Firefox enterprise policy' {
        $dir=Split-Path $firefoxPolicy
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        '{"policies":{"DisableTelemetry":true,"DisableFirefoxStudies":true,"OfferToSaveLogins":false,"PasswordManagerEnabled":false,"PopupBlocking":{"Default":true},"ExtensionSettings":{"*":{"installation_mode":"blocked"}}}}' | Set-Content -LiteralPath $firefoxPolicy -Encoding UTF8 -Force
    } { Test-Path $firefoxPolicy }
    $profiles=Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
    foreach($profile in $profiles){Get-ChildItem (Join-Path $profile.FullName 'extensions') -File -ErrorAction SilentlyContinue | ForEach-Object {Add-Review 'Firefox extension' $_.Name $_.FullName 'Is this extension authorized?'}}
}else{Write-Status INFO 'Firefox is not installed (N/A).'}

# Defender and platform audits only; no update installation.
Write-Status INFO '=== DEFENDER, PLATFORM, AND UPDATE AUDIT ==='
try{
    $mp=Get-MpComputerStatus
    if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled -or -not $mp.BehaviorMonitorEnabled) {
        Add-Review 'Defender' 'Protection state' "AV=$($mp.AntivirusEnabled); RTP=$($mp.RealTimeProtectionEnabled); Behavior=$($mp.BehaviorMonitorEnabled)" 'Restore approved Defender protection.'
    } else { $script:Passed++ }
    $pref=Get-MpPreference
    foreach($path in @($pref.ExclusionPath)){Add-Review 'Defender exclusion' $path 'Configured exclusion path' 'Is this exclusion authorized?'}
}catch{Add-Review 'Defender' 'Unavailable' $_.Exception.Message 'Verify approved antivirus protection manually.'}
try{Get-AppLockerPolicy -Effective -ErrorAction Stop | Out-Null; $script:Passed++}catch{Add-Review 'AppLocker/WDAC' 'Policy unavailable' $_.Exception.Message 'Audit AppLocker and WDAC manually.'}
$wu=Get-Service wuauserv -ErrorAction SilentlyContinue
if($wu){$script:Passed++}

# Interactive service state decisions occur last so all audit evidence is visible first.
Write-Status INFO '=== SERVICE DECISIONS ==='
Invoke-ServiceDecision 'Remote Desktop (RDP)' @('TermService') 'RDP exposes remote logon; verify authorized users and firewall scope first.' -Rdp
Invoke-ServiceDecision 'SMB/File Sharing' @('LanmanServer') 'Disabling SMB stops file and printer sharing.'
Invoke-ServiceDecision 'FTP' @('FTPSVC','MSFTPSVC') 'Enable only when the scenario explicitly requires FTP.'
Invoke-ServiceDecision 'SMTP' @('SMTPSVC') 'Enable only when the scenario explicitly requires SMTP.'
Invoke-ServiceDecision 'WinRM' @('WinRM') 'Enable only for approved remote management.'
Invoke-ServiceDecision 'OpenSSH' @('sshd','ssh-agent') 'Enable only for approved SSH administration.'
Invoke-ServiceDecision 'IIS' @('W3SVC') 'Enable only when this is an authorized web server.'
Invoke-ServiceDecision 'DNS' @('DNS') 'Enable only when this is an authorized DNS server.'
Invoke-ServiceDecision 'DHCP' @('DHCPServer') 'Enable only when this is an authorized DHCP server.'
Invoke-ServiceDecision 'Print Spooler' @('Spooler') 'Enable only when printing is required.'
Invoke-ServiceDecision 'Telnet Server' @('TlntSvr') 'Telnet is insecure and should normally remain disabled.'
Invoke-ServiceDecision 'Remote Registry' @('RemoteRegistry') 'Remote Registry should normally remain disabled.'
Invoke-ServiceDecision 'SNMP' @('SNMP','SNMPTRAP') 'Enable only when required for managed monitoring.'

if($CreateBaseline){
    Get-BaselineObject | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $BaselinePath -Encoding UTF8 -Force
    Write-Status OK "Baseline created: $BaselinePath"
}elseif(Test-Path $BaselinePath){
    try{
        $old=Get-Content -LiteralPath $BaselinePath -Raw|ConvertFrom-Json
        $new=Get-BaselineObject
        foreach($field in 'Accounts','Administrators','Services','InboundAllowRules','Tasks'){
            $before=@($old.$field|ConvertTo-Json -Depth 6);$after=@($new.$field|ConvertTo-Json -Depth 6)
            if(($before -join '') -ne ($after -join '')){Add-Review 'Baseline difference' $field 'Current state differs from the saved baseline.' 'Review differences before changing anything.'}
        }
    }catch{Add-Review 'Baseline' 'Comparison failed' $_.Exception.Message 'Recreate the baseline from a known-good image.'}
}else{Write-Status INFO "No baseline found. Create one later with -CreateBaseline: $BaselinePath"}

Write-Host "`n================ SUMMARY ================" -ForegroundColor Cyan
Write-Host "PASSED: $($script:Passed)  CHANGED: $($script:Changes.Count)  REVIEW: $($script:Review.Count)" -ForegroundColor Cyan
Write-Host 'SERVICE DECISIONS:' -ForegroundColor Cyan
$script:ServiceDecisions.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Cyan }
if($script:Review.Count){
    Write-Host 'FAILURES / HUMAN REVIEW:' -ForegroundColor DarkYellow
    $script:Review | ForEach-Object { Write-Host "  [ORANGE] $($_.Category): $($_.Item) - $($_.Evidence)" -ForegroundColor DarkYellow }
}
Write-Host "Completed in $script:Mode mode." -ForegroundColor Cyan

