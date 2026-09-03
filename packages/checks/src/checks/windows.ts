/**
 * Windows security checks. Every `collectors` entry is a documented, read-only
 * command (see docs/CHECKS.md). `evaluate` is a pure function of collected text.
 */
import type { SecurityCheck } from '../types.js';
import {
  collectorError,
  fail,
  firstLine,
  includesAny,
  parseNetAccounts,
  pass,
  pick,
  warn,
} from '../helpers.js';

/** Defensive JSON parse for `ConvertTo-Json` collector output. */
function j<T = unknown>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}

const NIST = 'NIST CSF 2.0';
const CIS = 'CIS Controls v8';

export const windowsChecks: SecurityCheck[] = [
  {
    id: 'WIN-EPP-001',
    name: 'Microsoft Defender real-time protection enabled',
    description: 'Verifies that Defender antivirus real-time protection is active.',
    platform: 'windows',
    category: 'Endpoint Security',
    severity: 'HIGH',
    rationale:
      'Real-time protection blocks malware as files are written or executed. Without it, an endpoint has no active on-access malware defense.',
    collectors: ['win.defender.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.defender.status');
      if (!c.ok) return collectorError(c, 'Defender status');
      const s = j<{ RealTimeProtectionEnabled?: boolean; AMRunningMode?: string }>(c.text);
      if (!s || s.RealTimeProtectionEnabled === undefined)
        return collectorError(c, 'Defender status');
      return s.RealTimeProtectionEnabled
        ? pass(`RealTimeProtectionEnabled: True (mode: ${s.AMRunningMode ?? 'unknown'})`)
        : fail('RealTimeProtectionEnabled: False');
    },
    remediation: {
      whatWeFound: 'Microsoft Defender real-time protection is turned off on this computer.',
      whyItMatters:
        'Real-time protection is the always-on shield that stops malware the moment it lands. With it off, threats can run before anything notices.',
      recommendedFix: [
        'Open Windows Security → Virus & threat protection → Manage settings.',
        'Turn "Real-time protection" back on.',
        'If it will not stay on, check whether another antivirus product has taken over; if so, confirm that product is healthy instead.',
        'If a policy (Group Policy / Intune) disabled it, remove that policy setting.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads Defender status and confirms real-time protection is enabled.',
    },
    frameworks: [
      { framework: CIS, controlId: '10.1', controlName: 'Deploy and maintain anti-malware software' },
      { framework: NIST, controlId: 'PR.PS-05', controlName: 'Malicious code prevention' },
    ],
    references: [
      { label: 'Microsoft: Turn on real-time protection', url: 'https://support.microsoft.com/windows/turn-off-defender-antivirus-protection-in-windows-security-99e6004f-c54c-8509-773c-a4d776b77960' },
    ],
  },
  {
    id: 'WIN-EPP-002',
    name: 'Defender antivirus definitions are current',
    description: 'Checks that antivirus signature definitions are no more than a few days old.',
    platform: 'windows',
    category: 'Endpoint Security',
    severity: 'MEDIUM',
    rationale:
      'Out-of-date definitions miss recent malware. Definition age is a direct measure of protection freshness.',
    collectors: ['win.defender.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.defender.status');
      if (!c.ok) return collectorError(c, 'Defender status');
      const s = j<{ AntivirusSignatureAge?: number }>(c.text);
      if (!s || s.AntivirusSignatureAge === undefined) return collectorError(c, 'Defender status');
      const age = s.AntivirusSignatureAge;
      if (age <= 3) return pass(`AntivirusSignatureAge: ${age} day(s)`);
      if (age <= 7) return warn(`AntivirusSignatureAge: ${age} days (should be <= 3)`);
      return fail(`AntivirusSignatureAge: ${age} days (definitions are stale)`);
    },
    remediation: {
      whatWeFound: 'Antivirus definitions on this computer are out of date.',
      whyItMatters:
        'Antivirus only recognizes threats it has definitions for. Stale definitions leave known, recent malware undetected.',
      recommendedFix: [
        'Open Windows Security → Virus & threat protection.',
        'Under "Virus & threat protection updates", click "Check for updates".',
        'Confirm the device has regular internet access and that Windows Update is not blocked.',
      ],
      who: 'Employee',
      effort: '5 minutes',
      verification: 'A re-scan confirms the signature age is back within 3 days.',
    },
    frameworks: [
      { framework: CIS, controlId: '10.2', controlName: 'Configure automatic anti-malware signature updates' },
      { framework: NIST, controlId: 'PR.PS-05', controlName: 'Malicious code prevention' },
    ],
    references: [
      { label: 'Microsoft: Update security intelligence', url: 'https://www.microsoft.com/wdsi/defenderupdates' },
    ],
  },
  {
    id: 'WIN-FW-001',
    name: 'Windows Firewall enabled on all profiles',
    description: 'Verifies the host firewall is on for the Domain, Private, and Public profiles.',
    platform: 'windows',
    category: 'Network Security',
    severity: 'HIGH',
    rationale:
      'The host firewall is the last line of defense against lateral movement and exposed local services. A disabled profile removes that boundary on that network type.',
    collectors: ['win.firewall.profiles'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.firewall.profiles');
      if (!c.ok) return collectorError(c, 'firewall profile state');
      // netsh output: blocks of "<Profile> Profile Settings:" then "State ON|OFF"
      const profiles: Record<string, string> = {};
      let current = '';
      for (const raw of c.text.split(/\r?\n/)) {
        const line = raw.trim();
        const p = line.match(/^(Domain|Private|Public)\s+Profile\s+Settings:/i);
        if (p && p[1]) current = p[1];
        const st = line.match(/^State\s+(ON|OFF)/i);
        if (st && current && st[1]) profiles[current] = st[1].toUpperCase();
      }
      const entries = Object.entries(profiles);
      if (entries.length === 0) return collectorError(c, 'firewall profile state');
      const off = entries.filter(([, v]) => v === 'OFF').map(([k]) => k);
      const summary = entries.map(([k, v]) => `${k}: ${v}`).join('; ');
      return off.length === 0 ? pass(summary) : fail(summary);
    },
    remediation: {
      whatWeFound: 'One or more Windows Firewall profiles are turned off.',
      whyItMatters:
        'When the firewall is off, any service listening on this computer is reachable by other devices on that network, which makes it far easier for an infection to spread.',
      recommendedFix: [
        'Open Windows Security → Firewall & network protection.',
        'For each network type shown (Domain, Private, Public), open it and switch the firewall On.',
        'If a Group Policy is forcing it off, update the "Windows Defender Firewall: Protect all network connections" policy to Enabled.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan runs "netsh advfirewall show allprofiles state" and confirms every profile is ON.',
    },
    frameworks: [
      { framework: CIS, controlId: '4.5', controlName: 'Implement and manage a host-based firewall' },
      { framework: NIST, controlId: 'PR.IR-01', controlName: 'Networks and environments protected from unauthorized access' },
    ],
    references: [
      { label: 'Microsoft: Turn Windows Firewall on or off', url: 'https://support.microsoft.com/windows/turn-microsoft-defender-firewall-on-or-off-ec0844f7-aebd-0583-67fe-601ecf5d774f' },
    ],
  },
  {
    id: 'WIN-PATCH-001',
    name: 'Windows build is a supported release',
    description: 'Checks that the Windows version still receives security updates.',
    platform: 'windows',
    category: 'Patch Management',
    severity: 'HIGH',
    rationale:
      'Unsupported Windows builds stop receiving security fixes entirely, so any newly discovered flaw remains exploitable forever.',
    collectors: ['win.computerinfo'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.computerinfo');
      if (!c.ok) return collectorError(c, 'Windows version');
      const info = j<{ WindowsProductName?: string; OsVersion?: string; OsBuildNumber?: string }>(
        c.text,
      );
      if (!info) return collectorError(c, 'Windows version');
      const name = info.WindowsProductName ?? '';
      const build = parseInt(info.OsBuildNumber ?? '0', 10);
      const label = `${name} (build ${info.OsBuildNumber ?? '?'}, ${info.OsVersion ?? '?'})`;
      // Windows 10 (build 19045 = 22H2) and Windows 11 (>= 22000) are supported
      // as of 2026. Older Windows 10 builds and anything < 10240 are EOL.
      if (/server/i.test(name)) {
        return build >= 14393
          ? pass(`${label} — supported Windows Server`)
          : fail(`${label} — end-of-life Windows Server`);
      }
      if (build >= 22000) return pass(`${label} — supported Windows 11`);
      if (build >= 19045) return pass(`${label} — supported Windows 10 22H2`);
      if (build >= 10240) return fail(`${label} — Windows 10 build past end of servicing`);
      return fail(`${label} — unsupported Windows version`);
    },
    remediation: {
      whatWeFound: 'This computer is running a version of Windows that no longer gets security updates (or is about to lose them).',
      whyItMatters:
        'Once Microsoft stops supporting a Windows version, newly found security holes are never fixed. Attackers specifically target these machines.',
      recommendedFix: [
        'Back up important files.',
        'Run Windows Update and install the latest feature update, or upgrade to Windows 11 if the hardware supports it.',
        'If the hardware cannot run a supported version, plan to replace the device.',
      ],
      who: 'IT administrator',
      effort: 'Requires IT support',
      verification: 'A re-scan reads the Windows build number and confirms it is a supported release.',
    },
    frameworks: [
      { framework: CIS, controlId: '2.2', controlName: 'Ensure authorized software is currently supported' },
      { framework: NIST, controlId: 'ID.AM-02', controlName: 'Software and services inventory maintained' },
    ],
    references: [
      { label: 'Windows release information', url: 'https://learn.microsoft.com/windows/release-health/' },
    ],
  },
  {
    id: 'WIN-PATCH-002',
    name: 'A recent Windows quality update is installed',
    description: 'Checks that the most recent installed update is not too old.',
    platform: 'windows',
    category: 'Patch Management',
    severity: 'MEDIUM',
    rationale:
      'A long gap since the last update usually means monthly security patches are not being applied.',
    collectors: ['win.hotfix'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.hotfix');
      if (!c.ok) return collectorError(c, 'update history');
      const rows = j<Array<{ HotFixID?: string; InstalledOn?: string }> | { HotFixID?: string; InstalledOn?: string }>(
        c.text,
      );
      const list = Array.isArray(rows) ? rows : rows ? [rows] : [];
      const dates = list
        .map((r) => (r.InstalledOn ? Date.parse(String(r.InstalledOn).replace(/\/Date\((\d+)\)\//, '$1')) : NaN))
        .filter((n) => !Number.isNaN(n));
      if (dates.length === 0) return collectorError(c, 'update history');
      const newest = Math.max(...dates);
      const ageDays = Math.floor((Date.now() - newest) / 86_400_000);
      const latest = list[0]?.HotFixID ?? 'unknown';
      if (ageDays <= 45) return pass(`Most recent update ${latest} installed ${ageDays} day(s) ago`);
      if (ageDays <= 75) return warn(`Most recent update installed ${ageDays} days ago (monthly patching may be lagging)`);
      return fail(`Most recent update installed ${ageDays} days ago`);
    },
    remediation: {
      whatWeFound: 'This computer has not installed a Windows update recently.',
      whyItMatters:
        'Microsoft ships security fixes every month. A machine that is months behind is missing fixes for flaws that are already public.',
      recommendedFix: [
        'Open Settings → Windows Update and click "Check for updates".',
        'Install everything offered, including optional cumulative updates, and restart.',
        'Make sure the device is left on and connected long enough for updates to complete (or configure an active-hours / maintenance window).',
      ],
      who: 'Employee',
      effort: '30 minutes',
      verification: 'A re-scan checks the install date of the most recent update.',
    },
    frameworks: [
      { framework: CIS, controlId: '7.3', controlName: 'Perform automated operating system patch management' },
      { framework: NIST, controlId: 'ID.RA-01', controlName: 'Vulnerabilities identified and recorded' },
    ],
    references: [
      { label: 'Microsoft: Update Windows', url: 'https://support.microsoft.com/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a' },
    ],
  },
  {
    id: 'WIN-AUTH-001',
    name: 'Built-in Guest account is disabled',
    description: 'Verifies the local Guest account is disabled.',
    platform: 'windows',
    category: 'Identity & Access',
    severity: 'HIGH',
    rationale:
      'The Guest account allows unauthenticated local access and is a well-known foothold. It should always be disabled.',
    collectors: ['win.localuser.guest'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.localuser.guest');
      if (!c.ok) return collectorError(c, 'Guest account state');
      const u = j<{ Name?: string; Enabled?: boolean }>(c.text);
      if (!u || u.Enabled === undefined) return collectorError(c, 'Guest account state');
      return u.Enabled ? fail('Local account "Guest" is Enabled') : pass('Local account "Guest" is Disabled');
    },
    remediation: {
      whatWeFound: 'The built-in Guest account on this computer is enabled.',
      whyItMatters:
        'The Guest account lets people use the computer without a real login and without accountability. It is a classic way in.',
      recommendedFix: [
        'Open an elevated PowerShell.',
        'Run: Disable-LocalUser -Name "Guest"',
        'Confirm no shared resource or application depends on Guest access first.',
      ],
      who: 'IT administrator',
      effort: '5 minutes',
      verification: 'A re-scan reads the Guest account and confirms it is disabled.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.2', controlName: 'Use unique passwords / manage default accounts' },
      { framework: NIST, controlId: 'PR.AA-01', controlName: 'Identities and credentials managed' },
    ],
    references: [
      { label: 'Microsoft: Disable-LocalUser', url: 'https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/disable-localuser' },
    ],
  },
  {
    id: 'WIN-AUTH-002',
    name: 'Password policy meets a baseline',
    description: 'Checks minimum password length and maximum password age.',
    platform: 'windows',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'Short passwords are brute-forced quickly. A minimum length of 12+ characters is the current baseline for SMBs.',
    collectors: ['win.netaccounts'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.netaccounts');
      if (!c.ok) return collectorError(c, 'password policy');
      const { minLength, maxAgeDays } = parseNetAccounts(c.text);
      if (minLength === undefined) return collectorError(c, 'password policy');
      const maxAge =
        maxAgeDays === undefined ? 'not reported' : maxAgeDays === Infinity ? 'Unlimited' : String(maxAgeDays);
      const parts = [`Minimum password length: ${minLength}`, `Maximum password age (days): ${maxAge}`];
      if (minLength >= 12) return pass(parts.join('; '));
      if (minLength >= 8) return warn(`${parts.join('; ')} (recommended minimum is 12)`);
      return fail(parts.join('; '));
    },
    remediation: {
      whatWeFound: 'The local password policy allows passwords that are shorter than recommended.',
      whyItMatters:
        'Modern hardware guesses short passwords in seconds. A 12-character minimum makes offline cracking dramatically harder.',
      recommendedFix: [
        'On a standalone PC, open an elevated command prompt and run: net accounts /minpwlen:12',
        'In a domain, set "Minimum password length" to 12 or more in the Default Domain Policy.',
        'Encourage passphrases (four or more unrelated words) rather than complex short strings.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads "net accounts" and confirms the minimum length is 12 or greater.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.2', controlName: 'Use unique, strong passwords' },
      { framework: NIST, controlId: 'PR.AA-01', controlName: 'Identities and credentials managed' },
    ],
    references: [
      { label: 'NIST SP 800-63B password guidance', url: 'https://pages.nist.gov/800-63-3/sp800-63b.html' },
    ],
  },
  {
    id: 'WIN-AUTH-003',
    name: 'Account lockout policy is configured',
    description: 'Checks that repeated failed logins lock the account.',
    platform: 'windows',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'Without lockout, an attacker can try passwords indefinitely. A threshold of roughly 5–10 attempts stops online guessing without causing constant self-lockouts.',
    collectors: ['win.netaccounts'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.netaccounts');
      if (!c.ok) return collectorError(c, 'lockout policy');
      const { lockoutThreshold } = parseNetAccounts(c.text);
      if (lockoutThreshold === undefined) return collectorError(c, 'lockout policy');
      if (lockoutThreshold === 0) return fail('Lockout threshold: Never (accounts never lock out)');
      if (lockoutThreshold > 10) return warn(`Lockout threshold: ${lockoutThreshold} (higher than recommended 5–10)`);
      return pass(`Lockout threshold: ${lockoutThreshold} attempts`);
    },
    remediation: {
      whatWeFound: 'Accounts on this computer are never locked out after wrong passwords.',
      whyItMatters:
        'With no lockout, someone can keep guessing passwords over and over until they get in.',
      recommendedFix: [
        'On a standalone PC, run in an elevated command prompt: net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15',
        'In a domain, configure the Account Lockout Policy in Group Policy.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads "net accounts" and confirms a lockout threshold between 1 and 10.',
    },
    frameworks: [
      { framework: CIS, controlId: '6.2', controlName: 'Establish an access-control policy' },
      { framework: NIST, controlId: 'PR.AA-03', controlName: 'Users and devices authenticated' },
    ],
    references: [
      { label: 'Microsoft: Account lockout policy', url: 'https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-policy' },
    ],
  },
  {
    id: 'WIN-AUTH-004',
    name: 'Local Administrators group is small',
    description: 'Flags when many accounts have local administrator rights.',
    platform: 'windows',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'Every local admin is a full-control account an attacker can target. Day-to-day accounts should be standard users.',
    collectors: ['win.localadmins'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.localadmins');
      if (!c.ok) return collectorError(c, 'local administrators');
      const rows = j<Array<{ Name?: string }> | { Name?: string }>(c.text);
      const names = (Array.isArray(rows) ? rows : rows ? [rows] : [])
        .map((r) => r.Name)
        .filter((n): n is string => Boolean(n));
      if (names.length === 0) return collectorError(c, 'local administrators');
      const summary = `${names.length} member(s): ${names.join(', ')}`;
      if (names.length <= 3) return pass(summary);
      return warn(`${summary} — review whether every account needs administrator rights`);
    },
    remediation: {
      whatWeFound: 'Several accounts have full administrator rights on this computer.',
      whyItMatters:
        'If any admin account is phished or reused elsewhere, the attacker gets total control of the machine. Fewer admins means less to protect.',
      recommendedFix: [
        'Open Computer Management → Local Users and Groups → Groups → Administrators.',
        'Remove any account that does not truly need admin rights; give people a standard account for daily work.',
        'Keep one dedicated administrative account plus the built-in Administrator (disabled or renamed).',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan lists the Administrators group and checks the member count.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.4', controlName: 'Restrict administrator privileges to dedicated accounts' },
      { framework: NIST, controlId: 'PR.AA-05', controlName: 'Access permissions follow least privilege' },
    ],
    references: [
      { label: 'CIS: Controlled Use of Administrative Privileges', url: 'https://www.cisecurity.org/controls' },
    ],
  },
  {
    id: 'WIN-RDP-001',
    name: 'Remote Desktop is disabled unless required',
    description: 'Reports whether inbound RDP is enabled on this computer.',
    platform: 'windows',
    category: 'Network Security',
    severity: 'MEDIUM',
    rationale:
      'Internet-exposed RDP is one of the most common ransomware entry points. If RDP is not needed it should be off.',
    collectors: ['win.rdp.deny'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.rdp.deny');
      if (!c.ok) return collectorError(c, 'RDP state');
      const v = firstLine(c.text);
      if (v === '1') return pass('fDenyTSConnections = 1 (Remote Desktop is disabled)');
      if (v === '0') return warn('fDenyTSConnections = 0 (Remote Desktop is enabled) — ensure it is required and not exposed to the internet');
      return collectorError(c, 'RDP state');
    },
    remediation: {
      whatWeFound: 'Remote Desktop is turned on for this computer.',
      whyItMatters:
        'Remote Desktop is a favorite target for ransomware crews, especially when it is reachable from the internet.',
      recommendedFix: [
        'If nobody connects to this computer remotely: Settings → System → Remote Desktop → turn it Off.',
        'If it is needed: require it only over a VPN, never a public port-forward; enforce Network Level Authentication (see WIN-RDP-002); limit who can connect.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads the fDenyTSConnections registry value.',
    },
    frameworks: [
      { framework: CIS, controlId: '4.8', controlName: 'Uninstall or disable unnecessary services' },
      { framework: NIST, controlId: 'PR.IR-01', controlName: 'Networks protected from unauthorized access' },
    ],
    references: [
      { label: 'CISA: Securing Remote Desktop', url: 'https://www.cisa.gov/news-events/alerts/2012/03/07/microsoft-remote-desktop-protocol' },
    ],
  },
  {
    id: 'WIN-RDP-002',
    name: 'Remote Desktop requires Network Level Authentication',
    description: 'If RDP is enabled, verifies NLA is required for connections.',
    platform: 'windows',
    category: 'Network Security',
    severity: 'HIGH',
    rationale:
      'NLA forces authentication before a session is created, which blocks pre-auth attacks against the RDP stack and reduces exposure to worms like BlueKeep.',
    collectors: ['win.rdp.deny', 'win.rdp.nla'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const deny = firstLine(pick(ctx, 'win.rdp.deny').text);
      if (deny === '1') return pass('Remote Desktop is disabled, so NLA is not applicable');
      const c = pick(ctx, 'win.rdp.nla');
      if (!c.ok) return collectorError(c, 'RDP NLA setting');
      const v = firstLine(c.text);
      if (v === '1') return pass('UserAuthentication = 1 (Network Level Authentication required)');
      if (v === '0') return fail('UserAuthentication = 0 (Network Level Authentication not required)');
      return collectorError(c, 'RDP NLA setting');
    },
    remediation: {
      whatWeFound: 'Remote Desktop is enabled but does not require Network Level Authentication (NLA).',
      whyItMatters:
        'Without NLA, a remote attacker can reach the Windows login screen and the underlying RDP code before proving who they are, which is how several RDP worms spread.',
      recommendedFix: [
        'Open System Properties → Remote tab (or Settings → Remote Desktop).',
        'Enable "Require devices to use Network Level Authentication to connect".',
        'In a domain, set the "Require user authentication for remote connections by using Network Level Authentication" policy to Enabled.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads the UserAuthentication registry value for RDP-Tcp.',
    },
    frameworks: [
      { framework: CIS, controlId: '4.1', controlName: 'Establish and maintain a secure configuration process' },
      { framework: NIST, controlId: 'PR.AA-03', controlName: 'Users and devices authenticated' },
    ],
    references: [
      { label: 'Microsoft: Configure NLA for RDS', url: 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access' },
    ],
  },
  {
    id: 'WIN-CFG-001',
    name: 'User Account Control (UAC) is enabled',
    description: 'Verifies UAC is on so privilege elevation requires consent.',
    platform: 'windows',
    category: 'Endpoint Security',
    severity: 'HIGH',
    rationale:
      'UAC keeps everyday actions running without admin rights and forces a prompt to elevate. Disabling it lets any process silently run as administrator.',
    collectors: ['win.uac.enablelua'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.uac.enablelua');
      if (!c.ok) return collectorError(c, 'UAC setting');
      const v = firstLine(c.text);
      if (v === '1') return pass('EnableLUA = 1 (UAC is enabled)');
      if (v === '0') return fail('EnableLUA = 0 (UAC is disabled)');
      return collectorError(c, 'UAC setting');
    },
    remediation: {
      whatWeFound: 'User Account Control (UAC) is turned off on this computer.',
      whyItMatters:
        'With UAC off, malware that runs as you can quietly gain full administrator control with no prompt and no trace.',
      recommendedFix: [
        'Open "Change User Account Control settings" from the Start menu.',
        'Move the slider to at least the default (second from top) position.',
        'Alternatively set the registry value EnableLUA to 1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System and restart.',
      ],
      who: 'IT administrator',
      effort: '5 minutes',
      verification: 'A re-scan reads the EnableLUA registry value.',
    },
    frameworks: [
      { framework: CIS, controlId: '4.1', controlName: 'Establish and maintain a secure configuration process' },
      { framework: NIST, controlId: 'PR.PS-01', controlName: 'Configuration management practices established' },
    ],
    references: [
      { label: 'Microsoft: How UAC works', url: 'https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/how-it-works' },
    ],
  },
  {
    id: 'WIN-SMB-001',
    name: 'SMBv1 is disabled',
    description: 'Verifies the legacy SMBv1 file-sharing protocol is not installed or enabled.',
    platform: 'windows',
    category: 'Network Security',
    severity: 'HIGH',
    rationale:
      'SMBv1 is obsolete and unpatched against attacks like EternalBlue/WannaCry. Microsoft recommends removing it entirely.',
    collectors: ['win.smb1.feature'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.smb1.feature');
      if (!c.ok) return collectorError(c, 'SMBv1 state');
      const feat = j<{ State?: string; FeatureName?: string }>(c.text);
      if (feat?.State) {
        return /enabled/i.test(feat.State)
          ? fail(`SMB1Protocol optional feature State: ${feat.State}`)
          : pass(`SMB1Protocol optional feature State: ${feat.State}`);
      }
      const cfg = j<{ EnableSMB1Protocol?: boolean }>(c.text);
      if (cfg && cfg.EnableSMB1Protocol !== undefined) {
        return cfg.EnableSMB1Protocol
          ? fail('EnableSMB1Protocol: True')
          : pass('EnableSMB1Protocol: False');
      }
      if (includesAny(c.text, 'disabled')) return pass('SMBv1 reported disabled');
      if (includesAny(c.text, 'enabled')) return fail('SMBv1 reported enabled');
      return collectorError(c, 'SMBv1 state');
    },
    remediation: {
      whatWeFound: 'The obsolete SMBv1 file-sharing protocol is still enabled on this computer.',
      whyItMatters:
        'SMBv1 has serious, unfixable flaws. WannaCry and NotPetya spread through it. There is no safe way to keep using it.',
      recommendedFix: [
        'Open an elevated PowerShell.',
        'Run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart',
        'For the server component only: Set-SmbServerConfiguration -EnableSMB1Protocol $false',
        'Restart the computer. Confirm no very old device (e.g. a legacy scanner/NAS) still needs SMBv1 before removing it.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan checks the SMB1Protocol optional feature / server configuration.',
    },
    frameworks: [
      { framework: CIS, controlId: '4.8', controlName: 'Uninstall or disable unnecessary services and protocols' },
      { framework: NIST, controlId: 'PR.PS-01', controlName: 'Configuration management practices established' },
    ],
    references: [
      { label: 'Microsoft: Detect, enable, disable SMBv1', url: 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3' },
    ],
  },
  {
    id: 'WIN-DATA-001',
    name: 'BitLocker protects the system drive',
    description: 'Verifies full-disk encryption is on and protecting the Windows drive.',
    platform: 'windows',
    category: 'Data Protection',
    severity: 'HIGH',
    rationale:
      'Without disk encryption, anyone who steals the laptop or its drive can read every file by attaching it to another computer.',
    collectors: ['win.bitlocker.system'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.bitlocker.system');
      if (!c.ok) return collectorError(c, 'BitLocker status');
      const v = j<{ VolumeStatus?: string; ProtectionStatus?: string | number }>(c.text);
      if (!v) return collectorError(c, 'BitLocker status');
      const prot = String(v.ProtectionStatus ?? '');
      const status = String(v.VolumeStatus ?? '');
      if (/on|1/i.test(prot) && /fullyencrypted/i.test(status))
        return pass(`VolumeStatus: ${status}; ProtectionStatus: On`);
      return fail(`VolumeStatus: ${status || 'unknown'}; ProtectionStatus: ${prot || 'Off'}`);
    },
    remediation: {
      whatWeFound: 'The Windows drive on this computer is not fully protected by BitLocker encryption.',
      whyItMatters:
        'If this device is lost or stolen, an unencrypted drive gives up all its data — customer records, saved passwords, everything.',
      recommendedFix: [
        'Confirm the device has a TPM (most business machines do).',
        'Open "Manage BitLocker" from the Start menu and turn on BitLocker for the operating-system drive.',
        'Save the recovery key somewhere safe and separate from the device (a password manager or your Microsoft/Entra account).',
        'Let encryption finish; keep the device plugged in.',
      ],
      who: 'IT administrator',
      effort: '1 hour',
      verification: 'A re-scan reads Get-BitLockerVolume and confirms the system drive is fully encrypted and protection is On.',
    },
    frameworks: [
      { framework: CIS, controlId: '3.6', controlName: 'Encrypt data on end-user devices' },
      { framework: NIST, controlId: 'PR.DS-01', controlName: 'Data-at-rest protected' },
    ],
    references: [
      { label: 'Microsoft: BitLocker overview', url: 'https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/' },
    ],
  },
  {
    id: 'WIN-LOG-001',
    name: 'Windows security auditing is enabled',
    description: 'Checks that audit policy records logon and account activity.',
    platform: 'windows',
    category: 'Logging & Monitoring',
    severity: 'MEDIUM',
    rationale:
      'If nothing is logged, there is no way to tell whether — or how — a breach happened. Basic logon/account auditing is the minimum for incident response.',
    collectors: ['win.auditpol'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'win.auditpol');
      if (!c.ok) return collectorError(c, 'audit policy');
      const lines = c.text.split(/\r?\n/).filter((l) => /,/.test(l));
      if (lines.length === 0) return collectorError(c, 'audit policy');
      // CSV rows: ...,Subcategory,GUID,Inclusion Setting  -> last column is the setting
      const settings = lines
        .map((l) => l.split(',').map((x) => x.trim()))
        .filter((cols) => cols.length >= 2)
        .map((cols) => (cols[cols.length - 1] ?? '').toLowerCase());
      const audited = settings.filter((s) => s.includes('success') || s.includes('failure')).length;
      const total = settings.filter((s) => s && !s.includes('inclusion setting')).length;
      if (total === 0) return collectorError(c, 'audit policy');
      if (audited === 0) return fail('No audit subcategories are set to log Success or Failure');
      if (audited < Math.ceil(total * 0.3))
        return warn(`Only ${audited} of ${total} audit subcategories are logging`);
      return pass(`${audited} of ${total} audit subcategories are logging Success/Failure`);
    },
    remediation: {
      whatWeFound: 'Windows is not recording security events like logons and account changes.',
      whyItMatters:
        'If something goes wrong, logs are how you find out what happened and how far it went. With auditing off, that history does not exist.',
      recommendedFix: [
        'Open Local Security Policy → Advanced Audit Policy Configuration.',
        'Enable Success and Failure auditing for at least: Logon/Logoff, Account Logon, Account Management, and Policy Change.',
        'In a domain, push this through Group Policy so every machine is consistent.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan runs "auditpol /get /category:*" and confirms key subcategories are logging.',
    },
    frameworks: [
      { framework: CIS, controlId: '8.2', controlName: 'Collect audit logs' },
      { framework: NIST, controlId: 'DE.CM-01', controlName: 'Networks and systems monitored' },
    ],
    references: [
      { label: 'Microsoft: Advanced security audit policy', url: 'https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings' },
    ],
  },
];
