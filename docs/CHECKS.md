# Security Checks

The authoritative definition of every check lives in
`packages/checks/src/checks/` (`windows.ts`, `linux.ts`), one object per check
implementing the `SecurityCheck` interface. The registry
(`packages/checks/src/registry.ts`) validates ids and severities at load. This
document mirrors that registry — regenerate the tables when checks change.

Each check declares: `id`, `name`, `description`, `platform`, `category`,
`severity`, `rationale`, the read-only `collectors` it uses, `evaluate(ctx)`
logic, `remediation` (whatWeFound / whyItMatters / recommendedFix / who / effort
/ verification / optional warning), `frameworks` (one CIS Controls v8 + one NIST
CSF 2.0 control), `references`, and `autoRemediationSupported` (always `false` in
the MVP).

## Categories
`Identity & Access` · `Endpoint Security` · `Network Security` ·
`Patch Management` · `Data Protection` · `Logging & Monitoring`

## Current registry — 26 checks (15 Windows, 11 Linux)

The spec targets "20–30 high-value checks". Severity shown is the registry value
the server enforces on ingestion (THREAT_MODEL T3); the uploaded scan's severity
is ignored.

### Windows
| ID | Name | Category | Severity |
| --- | --- | --- | --- |
| WIN-AUTH-001 | Built-in Guest account is disabled | Identity & Access | HIGH |
| WIN-AUTH-002 | Password policy meets a baseline | Identity & Access | MEDIUM |
| WIN-AUTH-003 | Account lockout policy is configured | Identity & Access | MEDIUM |
| WIN-AUTH-004 | Local Administrators group is small | Identity & Access | MEDIUM |
| WIN-CFG-001 | User Account Control (UAC) is enabled | Endpoint Security | HIGH |
| WIN-DATA-001 | BitLocker protects the system drive | Data Protection | HIGH |
| WIN-EPP-001 | Microsoft Defender real-time protection enabled | Endpoint Security | HIGH |
| WIN-EPP-002 | Defender antivirus definitions are current | Endpoint Security | MEDIUM |
| WIN-FW-001 | Windows Firewall enabled on all profiles | Network Security | HIGH |
| WIN-LOG-001 | Windows security auditing is enabled | Logging & Monitoring | MEDIUM |
| WIN-PATCH-001 | Windows build is a supported release | Patch Management | HIGH |
| WIN-PATCH-002 | A recent Windows quality update is installed | Patch Management | MEDIUM |
| WIN-RDP-001 | Remote Desktop is disabled unless required | Network Security | MEDIUM |
| WIN-RDP-002 | Remote Desktop requires Network Level Authentication | Network Security | HIGH |
| WIN-SMB-001 | SMBv1 is disabled | Network Security | HIGH |

### Linux
| ID | Name | Category | Severity |
| --- | --- | --- | --- |
| LNX-AUTH-001 | No unexpected UID 0 (root-equivalent) accounts | Identity & Access | HIGH |
| LNX-AUTH-002 | Sudoers has no blanket NOPASSWD access | Identity & Access | MEDIUM |
| LNX-AUTH-003 | Brute-force protection for SSH is present | Identity & Access | MEDIUM |
| LNX-CFG-001 | Sensitive files have safe permissions | Data Protection | MEDIUM |
| LNX-FW-001 | A host firewall is active | Network Security | HIGH |
| LNX-LOG-001 | Audit logging (auditd) is active | Logging & Monitoring | MEDIUM |
| LNX-PATCH-001 | Operating system release is identifiable and current | Patch Management | HIGH |
| LNX-PATCH-002 | No pending security updates | Patch Management | MEDIUM |
| LNX-PATCH-003 | Automatic security updates are enabled | Patch Management | MEDIUM |
| LNX-SSH-001 | SSH root login is disabled | Identity & Access | HIGH |
| LNX-SSH-002 | SSH password authentication is disabled | Identity & Access | MEDIUM |

## Read-only collectors

Every `collectors` id maps to a fixed, documented command in
`packages/scanner/src/collectors/catalog.ts`, run with `execFile` (no shell).
Examples: `Get-MpComputerStatus`, `netsh advfirewall show allprofiles state`,
`Get-BitLockerVolume`, `auditpol /get /category:*`, registry reads for
`fDenyTSConnections` / `UserAuthentication` / `EnableLUA`; `sshd -T`,
`cat /etc/passwd`, `stat` on `/etc/shadow`, `ufw status`, `apt-get -s upgrade`,
`systemctl is-active auditd`. A collector that cannot run yields a
`CheckOutcome` of `ERROR` ("could not assess") — never a silent pass.

## Room to grow

The interface is built so a new check is a single object added to `windows.ts`
or `linux.ts` (plus a collector entry if it needs a new data source). Natural
next additions: Defender Security Center health, stale local accounts, screen-lock
timeout, BitLocker recovery-key escrow, Windows listening-service inventory;
Linux SSH port/rate-limit, world-writable file sweep, LUKS disk-encryption
detection, `sshd` MACs/ciphers.
