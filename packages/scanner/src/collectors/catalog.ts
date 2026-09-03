import type { Platform } from '@smb/shared';
import type { CollectorOutput } from '@smb/checks';
import { readTextFile, runCommand, runPowerShell } from './exec.js';

export interface CollectorDefinition {
  id: string;
  platform: Platform;
  /** Human description of exactly what read-only command is executed. */
  describe: string;
  run: () => Promise<CollectorOutput>;
}

/** first non-empty line, used by a couple of registry-value collectors */
const firstProp = (script: string) => runPowerShell(script);

const WINDOWS: CollectorDefinition[] = [
  {
    id: 'win.defender.status',
    platform: 'windows',
    describe: 'Get-MpComputerStatus (Defender AV status) as JSON',
    run: () =>
      runPowerShell(
        'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AMRunningMode,AntivirusSignatureAge,AntispywareSignatureAge | ConvertTo-Json -Compress',
      ),
  },
  {
    id: 'win.firewall.profiles',
    platform: 'windows',
    describe: 'netsh advfirewall show allprofiles state',
    run: () => runCommand('netsh.exe', ['advfirewall', 'show', 'allprofiles', 'state']),
  },
  {
    id: 'win.computerinfo',
    platform: 'windows',
    describe: 'Get-ComputerInfo (OS name / version / build) as JSON',
    run: () =>
      runPowerShell(
        'Get-ComputerInfo -Property WindowsProductName,OsVersion,OsBuildNumber | ConvertTo-Json -Compress',
      ),
  },
  {
    id: 'win.hotfix',
    platform: 'windows',
    describe: 'Get-HotFix (5 most recent updates) as JSON',
    run: () =>
      runPowerShell(
        'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,InstalledOn | ConvertTo-Json -Compress',
      ),
  },
  {
    id: 'win.localuser.guest',
    platform: 'windows',
    describe: 'Get-LocalUser Guest (name/enabled) as JSON',
    run: () =>
      runPowerShell('Get-LocalUser -Name Guest | Select-Object Name,Enabled | ConvertTo-Json -Compress'),
  },
  {
    id: 'win.netaccounts',
    platform: 'windows',
    describe: 'net accounts (password + lockout policy)',
    run: () => runCommand('net.exe', ['accounts']),
  },
  {
    id: 'win.localadmins',
    platform: 'windows',
    describe: 'Get-LocalGroupMember Administrators (names) as JSON',
    run: () =>
      runPowerShell(
        'Get-LocalGroupMember -Group Administrators | Select-Object @{n="Name";e={$_.Name}} | ConvertTo-Json -Compress',
      ),
  },
  {
    id: 'win.rdp.deny',
    platform: 'windows',
    describe: 'registry read: fDenyTSConnections',
    run: () =>
      firstProp(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections",
      ),
  },
  {
    id: 'win.rdp.nla',
    platform: 'windows',
    describe: 'registry read: RDP-Tcp UserAuthentication',
    run: () =>
      firstProp(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication",
      ),
  },
  {
    id: 'win.uac.enablelua',
    platform: 'windows',
    describe: 'registry read: EnableLUA',
    run: () =>
      firstProp(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA",
      ),
  },
  {
    id: 'win.smb1.feature',
    platform: 'windows',
    describe: 'Get-SmbServerConfiguration EnableSMB1Protocol (fallback: optional feature) as JSON',
    run: () =>
      runPowerShell(
        '$c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; ' +
          'if ($c) { [pscustomobject]@{ EnableSMB1Protocol = $c.EnableSMB1Protocol } | ConvertTo-Json -Compress } ' +
          'else { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName,State | ConvertTo-Json -Compress }',
      ),
  },
  {
    id: 'win.bitlocker.system',
    platform: 'windows',
    describe: 'Get-BitLockerVolume for the system drive as JSON',
    run: () =>
      runPowerShell(
        'Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue | Select-Object VolumeStatus,ProtectionStatus | ConvertTo-Json -Compress',
      ),
  },
  {
    id: 'win.auditpol',
    platform: 'windows',
    describe: 'auditpol /get /category:* /r (CSV)',
    run: () => runCommand('auditpol.exe', ['/get', '/category:*', '/r']),
  },
];

const LINUX: CollectorDefinition[] = [
  {
    id: 'lnx.firewall.status',
    platform: 'linux',
    describe: 'ufw status || firewall-cmd --state || nft list ruleset',
    run: async () => {
      const ufw = await runCommand('ufw', ['status']);
      if (ufw.ok) return ufw;
      const fw = await runCommand('firewall-cmd', ['--state']);
      if (fw.ok) return fw;
      return runCommand('nft', ['list', 'ruleset']);
    },
  },
  {
    id: 'lnx.sshd.effective',
    platform: 'linux',
    describe: 'sshd -T (effective config) with sshd_config fallback',
    run: async () => {
      const t = await runCommand('sshd', ['-T']);
      if (t.ok) return t;
      return readTextFile('/etc/ssh/sshd_config');
    },
  },
  { id: 'lnx.passwd', platform: 'linux', describe: 'read /etc/passwd', run: () => readTextFile('/etc/passwd') },
  {
    id: 'lnx.sudoers',
    platform: 'linux',
    describe: 'read /etc/sudoers and /etc/sudoers.d/*',
    run: async () => {
      const base = await readTextFile('/etc/sudoers');
      const extra = await runCommand('sh', ['-c', 'cat /etc/sudoers.d/* 2>/dev/null']);
      const text = [base.text, extra.text].filter(Boolean).join('\n');
      return { ok: base.ok || extra.ok, text, error: base.ok || extra.ok ? undefined : base.error };
    },
  },
  {
    id: 'lnx.bruteforce.status',
    platform: 'linux',
    describe: 'systemctl is-active fail2ban / sshguard',
    run: async () => {
      const f2b = await runCommand('systemctl', ['is-active', 'fail2ban']);
      const sg = await runCommand('systemctl', ['is-active', 'sshguard']);
      return { ok: true, text: `fail2ban ${f2b.text || f2b.error}\nsshguard ${sg.text || sg.error}` };
    },
  },
  { id: 'lnx.osrelease', platform: 'linux', describe: 'read /etc/os-release', run: () => readTextFile('/etc/os-release') },
  {
    id: 'lnx.updates.security',
    platform: 'linux',
    describe: 'apt-get -s upgrade (or dnf updateinfo) - simulated, no changes',
    run: async () => {
      const apt = await runCommand('sh', ['-c', 'apt-get -s upgrade 2>/dev/null | grep -E "^Inst .*Security" || true']);
      if (apt.text) return apt;
      const dnf = await runCommand('sh', ['-c', 'dnf -q updateinfo summary 2>/dev/null || true']);
      return { ok: true, text: [apt.text, dnf.text].filter(Boolean).join('\n') };
    },
  },
  {
    id: 'lnx.autoupdates.status',
    platform: 'linux',
    describe: 'unattended-upgrades config / dnf-automatic timer state',
    run: async () => {
      const apt = await runCommand('sh', ['-c', 'cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true']);
      const dnf = await runCommand('systemctl', ['is-enabled', 'dnf-automatic.timer']);
      return { ok: true, text: [apt.text, dnf.text || dnf.error].filter(Boolean).join('\n') };
    },
  },
  {
    id: 'lnx.auditd.status',
    platform: 'linux',
    describe: 'systemctl is-active auditd',
    run: () => runCommand('systemctl', ['is-active', 'auditd']),
  },
  {
    id: 'lnx.fileperms',
    platform: 'linux',
    describe: 'stat -c "%n %a %U %G" on /etc/shadow and /etc/passwd',
    run: () => runCommand('stat', ['-c', '%n %a %U %G', '/etc/shadow', '/etc/passwd']),
  },
];

export const COLLECTOR_CATALOG: CollectorDefinition[] = [...WINDOWS, ...LINUX];

const catalogById = new Map(COLLECTOR_CATALOG.map((c) => [c.id, c]));

export function getCollector(id: string): CollectorDefinition | undefined {
  return catalogById.get(id);
}

export function collectorsForPlatform(platform: Platform): CollectorDefinition[] {
  return COLLECTOR_CATALOG.filter((c) => c.platform === platform);
}
