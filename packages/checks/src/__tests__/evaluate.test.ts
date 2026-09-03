import { describe, expect, it } from 'vitest';
import { getCheck } from '../index.js';
import type { CheckContext, CollectorOutput } from '../types.js';

const asset = { hostname: 'HOST', platform: 'windows' as const, osVersion: 'x' };
const ok = (text: string): CollectorOutput => ({ ok: true, text });
const bad = (error: string): CollectorOutput => ({ ok: false, text: '', error });

function ctx(collected: Record<string, CollectorOutput>, platform: 'windows' | 'linux' = 'windows'): CheckContext {
  return { asset: { ...asset, platform }, collected };
}

function run(id: string, collected: Record<string, CollectorOutput>, platform?: 'windows' | 'linux') {
  const check = getCheck(id);
  if (!check) throw new Error(`missing check ${id}`);
  return check.evaluate(ctx(collected, platform));
}

describe('Windows check evaluation', () => {
  it('WIN-FW-001 passes when all profiles are ON', () => {
    const text = `
Domain Profile Settings:
State                                 ON
Private Profile Settings:
State                                 ON
Public Profile Settings:
State                                 ON`;
    expect(run('WIN-FW-001', { 'win.firewall.profiles': ok(text) }).status).toBe('PASS');
  });

  it('WIN-FW-001 fails when a profile is OFF', () => {
    const text = `
Domain Profile Settings:
State                                 OFF
Private Profile Settings:
State                                 ON
Public Profile Settings:
State                                 ON`;
    const out = run('WIN-FW-001', { 'win.firewall.profiles': ok(text) });
    expect(out.status).toBe('FAIL');
    expect(out.evidence).toContain('Domain: OFF');
  });

  it('WIN-FW-001 reports ERROR when the collector failed', () => {
    expect(run('WIN-FW-001', { 'win.firewall.profiles': bad('access denied') }).status).toBe('ERROR');
  });

  it('WIN-EPP-001 fails when real-time protection is off', () => {
    const out = run('WIN-EPP-001', {
      'win.defender.status': ok(JSON.stringify({ RealTimeProtectionEnabled: false })),
    });
    expect(out.status).toBe('FAIL');
  });

  it('WIN-AUTH-001 fails when Guest is enabled', () => {
    const out = run('WIN-AUTH-001', {
      'win.localuser.guest': ok(JSON.stringify({ Name: 'Guest', Enabled: true })),
    });
    expect(out.status).toBe('FAIL');
  });

  it('WIN-AUTH-002 grades password length', () => {
    const mk = (len: number) => `Minimum password length: ${len}\nMaximum password age (days): 90`;
    expect(run('WIN-AUTH-002', { 'win.netaccounts': ok(mk(14)) }).status).toBe('PASS');
    expect(run('WIN-AUTH-002', { 'win.netaccounts': ok(mk(8)) }).status).toBe('WARN');
    expect(run('WIN-AUTH-002', { 'win.netaccounts': ok(mk(4)) }).status).toBe('FAIL');
  });

  it('WIN-RDP-002 is PASS (not applicable) when RDP is disabled', () => {
    const out = run('WIN-RDP-002', {
      'win.rdp.deny': ok('1'),
      'win.rdp.nla': ok('0'),
    });
    expect(out.status).toBe('PASS');
    expect(out.evidence).toMatch(/disabled/i);
  });

  it('WIN-RDP-002 fails when RDP is on without NLA', () => {
    const out = run('WIN-RDP-002', {
      'win.rdp.deny': ok('0'),
      'win.rdp.nla': ok('0'),
    });
    expect(out.status).toBe('FAIL');
  });

  it('WIN-SMB-001 fails when the SMB1 feature is Enabled', () => {
    const out = run('WIN-SMB-001', {
      'win.smb1.feature': ok(JSON.stringify({ FeatureName: 'SMB1Protocol', State: 'Enabled' })),
    });
    expect(out.status).toBe('FAIL');
  });

  it('WIN-PATCH-001 fails for an unsupported build', () => {
    const out = run('WIN-PATCH-001', {
      'win.computerinfo': ok(
        JSON.stringify({ WindowsProductName: 'Windows 10 Pro', OsVersion: '10.0.18363', OsBuildNumber: '18363' }),
      ),
    });
    expect(out.status).toBe('FAIL');
  });

  it('WIN-DATA-001 passes only when fully encrypted and protected', () => {
    expect(
      run('WIN-DATA-001', {
        'win.bitlocker.system': ok(JSON.stringify({ VolumeStatus: 'FullyEncrypted', ProtectionStatus: 'On' })),
      }).status,
    ).toBe('PASS');
    expect(
      run('WIN-DATA-001', {
        'win.bitlocker.system': ok(JSON.stringify({ VolumeStatus: 'FullyDecrypted', ProtectionStatus: 'Off' })),
      }).status,
    ).toBe('FAIL');
  });
});

describe('Linux check evaluation', () => {
  it('LNX-SSH-001 passes for PermitRootLogin no', () => {
    expect(
      run('LNX-SSH-001', { 'lnx.sshd.effective': ok('permitrootlogin no') }, 'linux').status,
    ).toBe('PASS');
  });

  it('LNX-SSH-001 fails for PermitRootLogin yes', () => {
    expect(
      run('LNX-SSH-001', { 'lnx.sshd.effective': ok('permitrootlogin yes') }, 'linux').status,
    ).toBe('FAIL');
  });

  it('LNX-SSH-002 fails when passwords are allowed', () => {
    expect(
      run('LNX-SSH-002', { 'lnx.sshd.effective': ok('passwordauthentication yes') }, 'linux').status,
    ).toBe('FAIL');
  });

  it('LNX-AUTH-001 fails on a second UID 0 account', () => {
    const passwd = 'root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash';
    const out = run('LNX-AUTH-001', { 'lnx.passwd': ok(passwd) }, 'linux');
    expect(out.status).toBe('FAIL');
    expect(out.evidence).toContain('backdoor');
  });

  it('LNX-AUTH-001 passes when only root is UID 0', () => {
    const passwd = 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash';
    expect(run('LNX-AUTH-001', { 'lnx.passwd': ok(passwd) }, 'linux').status).toBe('PASS');
  });

  it('LNX-FW-001 passes when ufw is active', () => {
    expect(
      run('LNX-FW-001', { 'lnx.firewall.status': ok('Status: active') }, 'linux').status,
    ).toBe('PASS');
  });

  it('LNX-FW-001 fails when ufw is inactive', () => {
    expect(
      run('LNX-FW-001', { 'lnx.firewall.status': ok('Status: inactive') }, 'linux').status,
    ).toBe('FAIL');
  });

  it('LNX-PATCH-001 fails for an EOL Ubuntu', () => {
    const os = 'ID=ubuntu\nVERSION_ID="16.04"\nPRETTY_NAME="Ubuntu 16.04.7 LTS"';
    expect(run('LNX-PATCH-001', { 'lnx.osrelease': ok(os) }, 'linux').status).toBe('FAIL');
  });

  it('LNX-CFG-001 fails when /etc/shadow is world-readable', () => {
    const perms = '/etc/shadow 644 root root\n/etc/passwd 644 root root';
    const out = run('LNX-CFG-001', { 'lnx.fileperms': ok(perms) }, 'linux');
    expect(out.status).toBe('FAIL');
  });

  it('LNX-CFG-001 passes for correct permissions', () => {
    const perms = '/etc/shadow 640 root root\n/etc/passwd 644 root root';
    expect(run('LNX-CFG-001', { 'lnx.fileperms': ok(perms) }, 'linux').status).toBe('PASS');
  });
});
