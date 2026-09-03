# Scanner (`security-agent`)

A read-only endpoint configuration assessment tool. It assesses **the system it
is run on**. It is not a network scanner and has no capability to target other
hosts.

## Install / build
```bash
pnpm --filter @smb/scanner build
node packages/scanner/dist/cli.js <command>
# (a `security-agent` bin is exposed when the package is linked/installed)
```

## Commands
| Command | Description |
| --- | --- |
| `security-agent scan` | Run all checks for this platform; print a readable summary |
| `security-agent scan --output result.json` | Also write structured JSON |
| `security-agent scan --json` | Print JSON to stdout only |
| `security-agent scan --only WIN-FW-001,WIN-RDP-002` | Run a subset |
| `security-agent check WIN-FW-001` | Run one check, show evidence + remediation |
| `security-agent list` | List available checks for this platform |
| `security-agent version` | Print version + schema version |
| `-v, --verbose` | Show each collector command and raw evidence |

## Example
```
Security Assessment
Asset: ACME-PC-01   Platform: windows   OS: Windows 11 23H2

[PASS] WIN-FW-001   Windows Firewall enabled (all profiles)
[PASS] WIN-EPP-001  Microsoft Defender real-time protection enabled
[FAIL] WIN-SMB-001  SMBv1 is enabled
[FAIL] WIN-RDP-002  RDP Network Level Authentication not required
[WARN] WIN-PATCH-002 3 pending security updates

Summary:  2 passed   2 failed   1 warning   0 errors
```

## Output format
`schemaVersion: "1.0"`. See `packages/shared/src/scan-schema.ts` for the
authoritative Zod schema.

```jsonc
{
  "schemaVersion": "1.0",
  "asset": { "hostname": "ACME-PC-01", "platform": "windows", "osVersion": "..." },
  "scan": { "startedAt": "ISO-8601", "completedAt": "ISO-8601", "scannerVersion": "0.1.0" },
  "findings": [
    {
      "checkId": "WIN-FW-001",
      "status": "FAIL",              // PASS | FAIL | WARN | ERROR | NOT_APPLICABLE
      "evidence": "Firewall profile Domain: Disabled; Private: Enabled; Public: Enabled",
      "observedAt": "ISO-8601"
      // NOTE: the scanner MAY include severity/category for local display,
      // but the server ignores them and uses the registry.
    }
  ]
}
```

## Safety boundaries (enforced by design)
The scanner **does not**: exploit, brute-force, dump credentials, steal tokens,
read personal files / browser history, capture keystrokes or screenshots,
persist, disable security software, modify firewall rules, change passwords,
execute arbitrary remote commands, or scan arbitrary internet targets.

Collectors are an allowlist of specific, documented read-only commands / API
reads (e.g. `Get-MpComputerStatus`, `netsh advfirewall show allprofiles state`,
reading `/etc/ssh/sshd_config`). Each is listed in `CHECKS.md`. All collected
data is treated as sensitive; only the minimal evidence needed to justify a
finding is retained.
