# Security Checks

The authoritative definition of every check lives in
`packages/checks/src/checks/` — one file per check implementing the
`SecurityCheck` interface. This document is generated-in-spirit from those
definitions; when they change, update this table.

Each check declares: `id`, `name`, `description`, `platform`, `category`,
`severity`, `rationale`, the read-only `collector` command(s) it uses,
`evaluate(evidence)` logic, `remediation` (what/why/fix/owner/effort/verify),
`frameworks` (CIS + NIST CSF), `references`, and `autoRemediationSupported`
(always `false` in the MVP).

## Categories
`Identity & Access` · `Endpoint Security` · `Network Security` ·
`Patch Management` · `Data Protection` · `Logging & Monitoring`

## Windows checks
| ID | Name | Category | Sev | Read-only collector |
| --- | --- | --- | --- | --- |
| WIN-EPP-001 | Defender real-time protection enabled | Endpoint Security | HIGH | `Get-MpComputerStatus` |
| WIN-EPP-002 | Defender signatures current | Endpoint Security | MEDIUM | `Get-MpComputerStatus` |
| WIN-EPP-003 | Security Center reports AV healthy | Endpoint Security | MEDIUM | `SecurityCenter2` WMI |
| WIN-FW-001 | Firewall enabled (all profiles) | Network Security | HIGH | `netsh advfirewall show allprofiles state` |
| WIN-PATCH-001 | Supported Windows build | Patch Management | HIGH | `Get-ComputerInfo` |
| WIN-PATCH-002 | Recent quality update installed | Patch Management | MEDIUM | `Get-HotFix` |
| WIN-PATCH-003 | Pending security updates | Patch Management | MEDIUM | Windows Update COM (read) |
| WIN-AUTH-001 | Guest account disabled | Identity & Access | HIGH | `Get-LocalUser` |
| WIN-AUTH-002 | Password policy meets baseline | Identity & Access | MEDIUM | `net accounts` |
| WIN-AUTH-003 | Account lockout configured | Identity & Access | MEDIUM | `net accounts` |
| WIN-AUTH-004 | Local administrators reviewed | Identity & Access | MEDIUM | `Get-LocalGroupMember Administrators` |
| WIN-AUTH-005 | No stale local accounts | Identity & Access | LOW | `Get-LocalUser` |
| WIN-RDP-001 | RDP disabled unless required | Network Security | MEDIUM | `fDenyTSConnections` registry (read) |
| WIN-RDP-002 | RDP requires Network Level Authentication | Network Security | HIGH | `UserAuthentication` registry (read) |
| WIN-CFG-001 | UAC enabled | Endpoint Security | HIGH | `EnableLUA` registry (read) |
| WIN-CFG-002 | Screen lock / inactivity timeout set | Identity & Access | MEDIUM | screensaver policy registry (read) |
| WIN-SMB-001 | SMBv1 disabled | Network Security | HIGH | `Get-WindowsOptionalFeature` / registry |
| WIN-DATA-001 | BitLocker protecting the system drive | Data Protection | HIGH | `Get-BitLockerVolume` |
| WIN-LOG-001 | Security auditing enabled | Logging & Monitoring | MEDIUM | `auditpol /get /category:*` |
| WIN-LOG-002 | Security event log adequately sized | Logging & Monitoring | LOW | `Get-WinEvent -ListLog Security` |
| WIN-NET-001 | Listening-service inventory reviewed | Network Security | LOW | `Get-NetTCPListener` |

## Linux checks
| ID | Name | Category | Sev | Read-only collector |
| --- | --- | --- | --- | --- |
| LNX-FW-001 | Host firewall active | Network Security | HIGH | `ufw status` / `firewall-cmd --state` / `nft list ruleset` |
| LNX-NET-001 | Listening-service inventory reviewed | Network Security | LOW | `ss -tulpn` |
| LNX-SSH-001 | SSH root login disabled | Identity & Access | HIGH | read `sshd_config` (+ `sshd -T`) |
| LNX-SSH-002 | SSH password auth disabled (keys only) | Identity & Access | MEDIUM | read `sshd_config` |
| LNX-SSH-003 | SSH not on default port / rate-limited | Network Security | LOW | read `sshd_config` |
| LNX-AUTH-001 | No non-root UID 0 accounts | Identity & Access | HIGH | read `/etc/passwd` |
| LNX-AUTH-002 | Sudoers has no unrestricted NOPASSWD | Identity & Access | MEDIUM | read `/etc/sudoers`, `/etc/sudoers.d/*` |
| LNX-AUTH-003 | Failed-login protection present | Identity & Access | MEDIUM | `fail2ban`/`sshguard` unit state |
| LNX-PATCH-001 | Supported OS release | Patch Management | HIGH | `/etc/os-release` |
| LNX-PATCH-002 | Security updates available | Patch Management | MEDIUM | `apt-get -s`/`dnf updateinfo` (read) |
| LNX-PATCH-003 | Automatic security updates enabled | Patch Management | MEDIUM | `unattended-upgrades`/`dnf-automatic` config |
| LNX-LOG-001 | Audit logging (auditd) active | Logging & Monitoring | MEDIUM | `systemctl is-active auditd` |
| LNX-CFG-001 | Sensitive file permissions correct | Data Protection | MEDIUM | `stat` on `/etc/shadow`, `/etc/passwd`, keys |
| LNX-CFG-002 | No world-writable files in sensitive paths | Data Protection | MEDIUM | `find` in `/etc`, `/usr/local` (bounded) |
| LNX-DATA-001 | Disk encryption present | Data Protection | MEDIUM | `lsblk`/`dmsetup` for LUKS |

Severity shown here is the registry value the server enforces (T3 in the threat
model). Full rationale, remediation steps, and framework mappings are in each
check's source file.
