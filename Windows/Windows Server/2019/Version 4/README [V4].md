# CYPat Enforcer - Windows Server 2019 V4

V4 is an audit-first CyberPatriot helper for Windows Server 2019.

## Use

```powershell
# Audit only: no system changes.
.\CYPat_Enforcer_Server_V4_WS2019.ps1

# Permit approved settings and interactive service Y/N decisions.
.\CYPat_Enforcer_Server_V4_WS2019.ps1 -Apply -Yes

# Save a known-good state after you have reviewed and secured an image.
.\CYPat_Enforcer_Server_V4_WS2019.ps1 -CreateBaseline
```

The script does not remove accounts, group members, programs, files, shares,
certificates, firewall rules, or Windows updates. In apply mode, RDP, SMB, FTP,
SMTP, WinRM, OpenSSH, IIS, DNS, DHCP, Print Spooler, Telnet, Remote Registry,
and SNMP each require a Y/N decision before their installed services are changed.

The final orange Human Review List identifies account/group authorization,
access rights, exposed rules, SMB/WinRM configuration, browser extensions,
Defender exclusions, and baseline differences that require a human decision.

