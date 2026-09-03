/**
 * Linux security checks. Collectors are documented, read-only commands or file
 * reads (see docs/CHECKS.md). `evaluate` is a pure function of collected text.
 */
import type { SecurityCheck } from '../types.js';
import { collectorError, fail, includesAny, pass, pick, warn } from '../helpers.js';

const NIST = 'NIST CSF 2.0';
const CIS = 'CIS Controls v8';

/** Read a single directive from `sshd -T` (authoritative) or sshd_config text. */
function sshdValue(text: string, key: string): string | undefined {
  const re = new RegExp(`^\\s*${key}\\s+(.+?)\\s*$`, 'im');
  const m = text.match(re);
  return m?.[1]?.toLowerCase();
}

export const linuxChecks: SecurityCheck[] = [
  {
    id: 'LNX-FW-001',
    name: 'A host firewall is active',
    description: 'Verifies ufw, firewalld, or nftables is enforcing rules.',
    platform: 'linux',
    category: 'Network Security',
    severity: 'HIGH',
    rationale:
      'A host firewall limits which services are reachable from the network and contains the blast radius if one host is compromised.',
    collectors: ['lnx.firewall.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.firewall.status');
      if (!c.ok) return collectorError(c, 'firewall status');
      const t = c.text.toLowerCase();
      if (/status:\s*active/.test(t)) return pass('ufw status: active');
      if (/^running$/m.test(t) || /firewalld.*running/.test(t)) return pass('firewalld: running');
      if (/table\s+(inet|ip|ip6)\s+/.test(t) && !/^\s*$/.test(t))
        return pass('nftables ruleset present');
      if (/status:\s*inactive/.test(t)) return fail('ufw status: inactive');
      if (/not running/.test(t)) return fail('firewalld: not running');
      if (t.trim() === '') return fail('No firewall ruleset found (ufw/firewalld/nftables all empty or absent)');
      return warn(`Firewall state unclear: ${c.text.split(/\r?\n/)[0] ?? ''}`);
    },
    remediation: {
      whatWeFound: 'This server does not have an active host firewall.',
      whyItMatters:
        'Without a firewall, every listening service is exposed to whatever network the machine is on. One forgotten service becomes a way in.',
      recommendedFix: [
        'On Debian/Ubuntu: sudo ufw default deny incoming; sudo ufw allow OpenSSH; sudo ufw enable',
        'On RHEL/Fedora: sudo systemctl enable --now firewalld; then add only the services you need with firewall-cmd.',
        'Confirm you still have SSH access from another session before enabling.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan checks "ufw status" / "firewall-cmd --state" / "nft list ruleset".',
    },
    frameworks: [
      { framework: CIS, controlId: '4.5', controlName: 'Implement and manage a host-based firewall' },
      { framework: NIST, controlId: 'PR.IR-01', controlName: 'Networks protected from unauthorized access' },
    ],
    references: [
      { label: 'Ubuntu: UFW basics', url: 'https://help.ubuntu.com/community/UFW' },
    ],
  },
  {
    id: 'LNX-SSH-001',
    name: 'SSH root login is disabled',
    description: 'Verifies PermitRootLogin is "no" or key-only.',
    platform: 'linux',
    category: 'Identity & Access',
    severity: 'HIGH',
    rationale:
      'Allowing direct root login over SSH removes accountability and hands attackers the highest-value target to guess against.',
    collectors: ['lnx.sshd.effective'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.sshd.effective');
      if (!c.ok) return collectorError(c, 'sshd configuration');
      const v = sshdValue(c.text, 'permitrootlogin');
      if (v === undefined) return collectorError(c, 'sshd configuration');
      if (v === 'no') return pass('PermitRootLogin no');
      if (v === 'prohibit-password' || v === 'without-password')
        return pass(`PermitRootLogin ${v} (key-only root login)`);
      return fail(`PermitRootLogin ${v}`);
    },
    remediation: {
      whatWeFound: 'The SSH service on this server allows logging in directly as root.',
      whyItMatters:
        'root is the account attackers most want. Disabling direct root SSH forces them to first compromise a named user, and it means every admin action is tied to a real person.',
      recommendedFix: [
        'Edit /etc/ssh/sshd_config and set: PermitRootLogin no',
        'Make sure at least one normal user is in the sudo/wheel group and can log in first.',
        'Reload SSH: sudo systemctl reload ssh (or sshd).',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan reads the effective sshd configuration (sshd -T) for PermitRootLogin.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.4', controlName: 'Restrict administrator privileges to dedicated accounts' },
      { framework: NIST, controlId: 'PR.AA-05', controlName: 'Access permissions follow least privilege' },
    ],
    references: [
      { label: 'OpenSSH sshd_config manual', url: 'https://man.openbsd.org/sshd_config' },
    ],
  },
  {
    id: 'LNX-SSH-002',
    name: 'SSH password authentication is disabled',
    description: 'Verifies SSH accepts keys only, not passwords.',
    platform: 'linux',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'Password SSH is exposed to constant internet-wide brute forcing. Key-only authentication makes remote password guessing impossible.',
    collectors: ['lnx.sshd.effective'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.sshd.effective');
      if (!c.ok) return collectorError(c, 'sshd configuration');
      const v = sshdValue(c.text, 'passwordauthentication');
      const kbd = sshdValue(c.text, 'kbdinteractiveauthentication') ?? sshdValue(c.text, 'challengeresponseauthentication');
      if (v === undefined) return collectorError(c, 'sshd configuration');
      if (v === 'no' && kbd !== 'yes') return pass('PasswordAuthentication no');
      if (v === 'no' && kbd === 'yes')
        return warn('PasswordAuthentication no, but KbdInteractiveAuthentication yes (passwords may still work via PAM)');
      return fail(`PasswordAuthentication ${v}`);
    },
    remediation: {
      whatWeFound: 'The SSH service on this server accepts password logins.',
      whyItMatters:
        'Internet-facing SSH with passwords is hammered by automated guessing around the clock. SSH keys cannot be guessed.',
      recommendedFix: [
        'Make sure every admin has an SSH key installed (ssh-copy-id) and can log in with it.',
        'In /etc/ssh/sshd_config set: PasswordAuthentication no and KbdInteractiveAuthentication no',
        'Reload SSH: sudo systemctl reload ssh (or sshd). Keep an existing session open while you test a new one.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan reads sshd -T for PasswordAuthentication (and the keyboard-interactive setting).',
    },
    frameworks: [
      { framework: CIS, controlId: '4.1', controlName: 'Establish and maintain a secure configuration process' },
      { framework: NIST, controlId: 'PR.AA-03', controlName: 'Users and devices authenticated' },
    ],
    references: [
      { label: 'OpenSSH: key-based authentication', url: 'https://man.openbsd.org/ssh' },
    ],
  },
  {
    id: 'LNX-AUTH-001',
    name: 'No unexpected UID 0 (root-equivalent) accounts',
    description: 'Verifies "root" is the only account with UID 0.',
    platform: 'linux',
    category: 'Identity & Access',
    severity: 'HIGH',
    rationale:
      'Any account with UID 0 is fully root. A second UID 0 account is a common, easily missed backdoor.',
    collectors: ['lnx.passwd'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.passwd');
      if (!c.ok) return collectorError(c, '/etc/passwd');
      const uid0 = c.text
        .split(/\r?\n/)
        .map((l) => l.split(':'))
        .filter((f) => f.length >= 3 && f[2] === '0')
        .map((f) => f[0]);
      if (uid0.length === 0) return collectorError(c, '/etc/passwd');
      if (uid0.length === 1 && uid0[0] === 'root') return pass('Only "root" has UID 0');
      return fail(`Accounts with UID 0: ${uid0.join(', ')}`);
    },
    remediation: {
      whatWeFound: 'More than one account on this server has full root privileges (UID 0).',
      whyItMatters:
        'An extra UID 0 account is exactly what an attacker leaves behind as a hidden way back in. Legitimate setups almost never need one.',
      recommendedFix: [
        'Review each account listed in the finding.',
        'For any that should not be root-equivalent, change its UID to a normal value (usermod -u) or remove the account (userdel).',
        'If one is unfamiliar, treat the host as potentially compromised and investigate.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan parses /etc/passwd and confirms root is the only UID 0 account.',
      warning:
        'Changing or deleting accounts can break services. Identify what each account is used for before acting.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.1', controlName: 'Establish and maintain an inventory of accounts' },
      { framework: NIST, controlId: 'PR.AA-01', controlName: 'Identities and credentials managed' },
    ],
    references: [
      { label: 'Linux man: passwd(5)', url: 'https://man7.org/linux/man-pages/man5/passwd.5.html' },
    ],
  },
  {
    id: 'LNX-AUTH-002',
    name: 'Sudoers has no blanket NOPASSWD access',
    description: 'Flags unrestricted NOPASSWD rules in sudoers.',
    platform: 'linux',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'A broad NOPASSWD rule means a stolen or hijacked user session becomes instant root with no second factor.',
    collectors: ['lnx.sudoers'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.sudoers');
      if (!c.ok) return collectorError(c, 'sudoers');
      const risky = c.text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'))
        .filter((l) => /NOPASSWD:\s*ALL\s*$/i.test(l) || /NOPASSWD:\s*ALL\b/i.test(l));
      if (risky.length === 0) return pass('No unrestricted NOPASSWD:ALL rules in sudoers');
      return warn(`Unrestricted NOPASSWD rule(s): ${risky.slice(0, 3).join(' | ')}`);
    },
    remediation: {
      whatWeFound: 'The sudo configuration lets one or more users run any command as root without re-entering a password.',
      whyItMatters:
        'If that user account is phished or their laptop is left unlocked, the attacker gets root with zero friction.',
      recommendedFix: [
        'Run "sudo visudo" and review each NOPASSWD line.',
        'Remove NOPASSWD, or narrow it to the specific commands that genuinely need it (e.g. a single backup script).',
        'Keep interactive admin access password-protected.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan reads /etc/sudoers and /etc/sudoers.d/* for unrestricted NOPASSWD:ALL rules.',
    },
    frameworks: [
      { framework: CIS, controlId: '5.4', controlName: 'Restrict administrator privileges to dedicated accounts' },
      { framework: NIST, controlId: 'PR.AA-05', controlName: 'Access permissions follow least privilege' },
    ],
    references: [
      { label: 'sudoers manual', url: 'https://www.sudo.ws/docs/man/sudoers.man/' },
    ],
  },
  {
    id: 'LNX-AUTH-003',
    name: 'Brute-force protection for SSH is present',
    description: 'Checks that fail2ban or sshguard is installed and active.',
    platform: 'linux',
    category: 'Identity & Access',
    severity: 'MEDIUM',
    rationale:
      'Automated tools ban IPs after repeated failed logins, which shuts down password-guessing and cuts log noise.',
    collectors: ['lnx.bruteforce.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.bruteforce.status');
      if (!c.ok) return collectorError(c, 'brute-force protection');
      if (/fail2ban\S*\s+active/i.test(c.text) || /^active$/im.test(c.text) || /sshguard\S*\s+active/i.test(c.text))
        return pass('fail2ban or sshguard service is active');
      if (includesAny(c.text, 'inactive', 'not-found', 'could not be found', 'dead'))
        return fail('Neither fail2ban nor sshguard is active');
      return collectorError(c, 'brute-force protection');
    },
    remediation: {
      whatWeFound: 'This server has no automatic protection against repeated failed SSH logins.',
      whyItMatters:
        'Without it, attackers can keep guessing passwords or keys as fast as the network allows.',
      recommendedFix: [
        'Install fail2ban: sudo apt install fail2ban  (or sudo dnf install fail2ban).',
        'Enable it: sudo systemctl enable --now fail2ban',
        'The default sshd jail is usually sufficient; confirm with "sudo fail2ban-client status sshd".',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan checks whether the fail2ban or sshguard service is active.',
    },
    frameworks: [
      { framework: CIS, controlId: '6.2', controlName: 'Establish an access-control policy' },
      { framework: NIST, controlId: 'DE.CM-01', controlName: 'Networks and systems monitored' },
    ],
    references: [
      { label: 'fail2ban documentation', url: 'https://github.com/fail2ban/fail2ban/wiki' },
    ],
  },
  {
    id: 'LNX-PATCH-001',
    name: 'Operating system release is identifiable and current',
    description: 'Checks /etc/os-release names a supported distribution version.',
    platform: 'linux',
    category: 'Patch Management',
    severity: 'HIGH',
    rationale:
      'End-of-life distributions stop receiving security updates. Knowing the exact release is the first step to keeping it patched.',
    collectors: ['lnx.osrelease'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.osrelease');
      if (!c.ok) return collectorError(c, 'OS release');
      const get = (k: string) => c.text.match(new RegExp(`^${k}=\"?([^\"\\n]+)\"?`, 'm'))?.[1];
      const id = get('ID');
      const ver = get('VERSION_ID');
      const pretty = get('PRETTY_NAME') ?? `${id ?? 'unknown'} ${ver ?? ''}`.trim();
      if (!id || !ver) return collectorError(c, 'OS release');
      // Coarse EOL heuristics current as of 2026.
      const major = parseFloat(ver);
      const eol =
        (id === 'ubuntu' && major < 20.04) ||
        (id === 'debian' && major < 11) ||
        ((id === 'rhel' || id === 'centos' || id === 'rocky' || id === 'almalinux') && major < 8) ||
        (id === 'fedora' && major < 39);
      return eol
        ? fail(`${pretty} — this release is past end of life`)
        : pass(`${pretty} — supported release`);
    },
    remediation: {
      whatWeFound: 'This server runs a Linux release that no longer receives security updates.',
      whyItMatters:
        'On an end-of-life OS, security holes are simply never patched. It is only a matter of time.',
      recommendedFix: [
        'Plan an in-place upgrade to a supported release (e.g. do-release-upgrade on Ubuntu, or a major-version upgrade path for your distro).',
        'Where an in-place upgrade is risky, build a fresh server on a current release and migrate the workload.',
        'Until then, restrict network exposure of this host as much as possible.',
      ],
      who: 'IT administrator',
      effort: 'Requires IT support',
      verification: 'A re-scan reads /etc/os-release and confirms the version is still supported.',
    },
    frameworks: [
      { framework: CIS, controlId: '2.2', controlName: 'Ensure authorized software is currently supported' },
      { framework: NIST, controlId: 'ID.AM-02', controlName: 'Software and services inventory maintained' },
    ],
    references: [
      { label: 'endoflife.date', url: 'https://endoflife.date/' },
    ],
  },
  {
    id: 'LNX-PATCH-002',
    name: 'No pending security updates',
    description: 'Checks the package manager for available security updates.',
    platform: 'linux',
    category: 'Patch Management',
    severity: 'MEDIUM',
    rationale:
      'Available-but-uninstalled security updates are known, fixed flaws left in place.',
    collectors: ['lnx.updates.security'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.updates.security');
      if (!c.ok) return collectorError(c, 'pending updates');
      const t = c.text;
      // apt: "Inst pkg [old] (new ... Security)" lines
      const aptSec = (t.match(/^Inst .*Security/gim) ?? []).length;
      // dnf updateinfo summary: "N Security notice(s)"
      const dnfMatch = t.match(/(\d+)\s+Security\s+notice/i);
      const dnfSec = dnfMatch?.[1] ? parseInt(dnfMatch[1], 10) : 0;
      const count = Math.max(aptSec, dnfSec);
      if (/0 upgraded|nothing to do|no security updates/i.test(t) && count === 0)
        return pass('No pending security updates');
      if (count === 0 && t.trim() === '') return pass('No pending security updates');
      if (count === 0) return pass('No security updates reported pending');
      if (count <= 5) return warn(`${count} pending security update(s)`);
      return fail(`${count} pending security updates`);
    },
    remediation: {
      whatWeFound: 'This server has security updates available that have not been installed.',
      whyItMatters:
        'Each pending security update fixes a flaw that is already public. Installing them promptly is the single highest-value patching habit.',
      recommendedFix: [
        'Debian/Ubuntu: sudo apt update && sudo apt upgrade',
        'RHEL/Fedora: sudo dnf upgrade --security',
        'Reboot if a kernel or core library was updated.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan re-queries the package manager for outstanding security updates.',
    },
    frameworks: [
      { framework: CIS, controlId: '7.3', controlName: 'Perform automated operating system patch management' },
      { framework: NIST, controlId: 'ID.RA-01', controlName: 'Vulnerabilities identified and recorded' },
    ],
    references: [
      { label: 'Ubuntu security notices', url: 'https://ubuntu.com/security/notices' },
    ],
  },
  {
    id: 'LNX-PATCH-003',
    name: 'Automatic security updates are enabled',
    description: 'Checks for unattended-upgrades or dnf-automatic.',
    platform: 'linux',
    category: 'Patch Management',
    severity: 'MEDIUM',
    rationale:
      'SMBs rarely patch servers by hand on a schedule. Automating security updates closes that gap.',
    collectors: ['lnx.autoupdates.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.autoupdates.status');
      if (!c.ok) return collectorError(c, 'automatic updates');
      const t = c.text;
      if (/APT::Periodic::Unattended-Upgrade\s+\"?1\"?/.test(t)) return pass('unattended-upgrades enabled (Unattended-Upgrade "1")');
      if (/dnf-automatic\S*\s+(active|enabled)/i.test(t) || /^enabled$/im.test(t)) return pass('dnf-automatic timer enabled');
      if (/Unattended-Upgrade\s+\"?0\"?/.test(t) || includesAny(t, 'inactive', 'disabled', 'not-found', 'could not be found'))
        return fail('No automatic security-update mechanism is enabled');
      return warn('Could not confirm automatic security updates are enabled');
    },
    remediation: {
      whatWeFound: 'This server is not set up to install security updates automatically.',
      whyItMatters:
        'Manual patching slips. Automating just the security updates keeps the server current without anyone remembering to log in.',
      recommendedFix: [
        'Debian/Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades',
        'RHEL/Fedora: sudo dnf install dnf-automatic, set apply_updates=yes in /etc/dnf/automatic.conf, then: sudo systemctl enable --now dnf-automatic.timer',
        'Consider a reboot window for updates that need one.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan checks the unattended-upgrades / dnf-automatic configuration and timer.',
    },
    frameworks: [
      { framework: CIS, controlId: '7.3', controlName: 'Perform automated operating system patch management' },
      { framework: NIST, controlId: 'PR.PS-02', controlName: 'Software updates performed' },
    ],
    references: [
      { label: 'Debian: UnattendedUpgrades', url: 'https://wiki.debian.org/UnattendedUpgrades' },
    ],
  },
  {
    id: 'LNX-LOG-001',
    name: 'Audit logging (auditd) is active',
    description: 'Verifies the Linux audit daemon is running.',
    platform: 'linux',
    category: 'Logging & Monitoring',
    severity: 'MEDIUM',
    rationale:
      'auditd records security-relevant system events. Without it, forensic reconstruction after an incident is largely impossible.',
    collectors: ['lnx.auditd.status'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.auditd.status');
      if (!c.ok) return collectorError(c, 'auditd status');
      if (/^active$/im.test(c.text)) return pass('auditd service is active');
      if (includesAny(c.text, 'inactive', 'dead', 'not-found', 'could not be found'))
        return fail('auditd service is not active');
      return collectorError(c, 'auditd status');
    },
    remediation: {
      whatWeFound: 'The Linux audit daemon (auditd) is not running on this server.',
      whyItMatters:
        'If this server is ever compromised, auditd logs are often the only record of what the attacker did.',
      recommendedFix: [
        'Install: sudo apt install auditd  (or sudo dnf install audit).',
        'Enable: sudo systemctl enable --now auditd',
        'Consider adding a baseline rule set (for example the CIS or STIG audit rules) once it is running.',
      ],
      who: 'IT administrator',
      effort: '30 minutes',
      verification: 'A re-scan runs "systemctl is-active auditd".',
    },
    frameworks: [
      { framework: CIS, controlId: '8.2', controlName: 'Collect audit logs' },
      { framework: NIST, controlId: 'DE.CM-01', controlName: 'Networks and systems monitored' },
    ],
    references: [
      { label: 'RHEL: Auditing the system', url: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening' },
    ],
  },
  {
    id: 'LNX-CFG-001',
    name: 'Sensitive files have safe permissions',
    description: 'Checks ownership and mode of /etc/shadow and /etc/passwd.',
    platform: 'linux',
    category: 'Data Protection',
    severity: 'MEDIUM',
    rationale:
      '/etc/shadow holds password hashes; if it is world-readable, every account password can be attacked offline.',
    collectors: ['lnx.fileperms'],
    autoRemediationSupported: false,
    evaluate(ctx) {
      const c = pick(ctx, 'lnx.fileperms');
      if (!c.ok) return collectorError(c, 'file permissions');
      // Expected lines like: "/etc/shadow 640 root root" (mode owner group)
      const rows = c.text
        .split(/\r?\n/)
        .map((l) => l.trim().split(/\s+/))
        .filter((f) => f.length >= 4);
      if (rows.length === 0) return collectorError(c, 'file permissions');
      const problems: string[] = [];
      for (const [path, mode, owner] of rows) {
        const m = parseInt(mode ?? '', 8);
        if (Number.isNaN(m)) continue;
        const worldPerm = m & 0o007;
        if (path === '/etc/shadow') {
          if (owner !== 'root' || worldPerm !== 0 || (m & 0o070) > 0o040)
            problems.push(`${path} is ${mode} ${owner} (expected 0640 or stricter, root-owned)`);
        } else if (path === '/etc/passwd') {
          if (owner !== 'root' || (worldPerm & 0o002) !== 0)
            problems.push(`${path} is ${mode} ${owner} (expected 0644, root-owned, not world-writable)`);
        }
      }
      return problems.length === 0
        ? pass(rows.map((r) => `${r[0]}: ${r[1]} ${r[2]}:${r[3]}`).join('; '))
        : fail(problems.join('; '));
    },
    remediation: {
      whatWeFound: 'A sensitive system file has looser permissions than it should.',
      whyItMatters:
        '/etc/shadow contains hashed passwords. If a normal user can read it, they can try to crack every password on the system at their leisure.',
      recommendedFix: [
        'sudo chown root:root /etc/shadow && sudo chmod 640 /etc/shadow',
        'sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd',
        'Investigate how the permissions were changed in the first place.',
      ],
      who: 'IT administrator',
      effort: '15 minutes',
      verification: 'A re-scan re-reads the mode and owner of these files.',
    },
    frameworks: [
      { framework: CIS, controlId: '3.3', controlName: 'Configure data access control lists' },
      { framework: NIST, controlId: 'PR.DS-01', controlName: 'Data-at-rest protected' },
    ],
    references: [
      { label: 'Linux man: shadow(5)', url: 'https://man7.org/linux/man-pages/man5/shadow.5.html' },
    ],
  },
];
