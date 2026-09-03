/**
 * Curated control metadata for the frameworks the MVP maps to.
 *
 * IMPORTANT: these `summary` strings are our own short paraphrases written to
 * orient a non-specialist. They are NOT the official control text. We store the
 * minimum needed to explain a mapping; refer to the official CIS / NIST
 * publications for authoritative wording.
 */
export const FRAMEWORKS = {
  CIS: 'CIS Controls v8',
  NIST: 'NIST CSF 2.0',
} as const;

export interface ControlDefinition {
  framework: string;
  controlId: string;
  title: string;
  /** Our paraphrase, one sentence. Not official text. */
  summary: string;
}

const CIS = FRAMEWORKS.CIS;
const NIST = FRAMEWORKS.NIST;

export const CONTROL_CATALOG: ControlDefinition[] = [
  // --- CIS Controls v8 (curated SMB-relevant subset) ---
  { framework: CIS, controlId: '2.2', title: 'Ensure authorized software is supported', summary: 'Only run operating systems and applications that still receive vendor security support.' },
  { framework: CIS, controlId: '3.3', title: 'Configure data access control lists', summary: 'Restrict access to sensitive files and data to only the accounts that need it.' },
  { framework: CIS, controlId: '3.6', title: 'Encrypt data on end-user devices', summary: 'Enable full-disk encryption on laptops and workstations that hold business data.' },
  { framework: CIS, controlId: '4.1', title: 'Establish a secure configuration process', summary: 'Maintain and apply hardened baseline settings for operating systems and software.' },
  { framework: CIS, controlId: '4.5', title: 'Implement a host-based firewall', summary: 'Run and manage a firewall on each endpoint, denying inbound traffic by default.' },
  { framework: CIS, controlId: '4.8', title: 'Disable unnecessary services', summary: 'Turn off or uninstall services, protocols, and features that are not required.' },
  { framework: CIS, controlId: '5.1', title: 'Establish an inventory of accounts', summary: 'Maintain an inventory of every user and administrator account on your systems.' },
  { framework: CIS, controlId: '5.2', title: 'Use unique, strong passwords', summary: 'Require long unique passwords and remove or secure default accounts.' },
  { framework: CIS, controlId: '5.4', title: 'Restrict administrator privileges', summary: 'Use dedicated accounts for admin work; everyday accounts are standard users.' },
  { framework: CIS, controlId: '6.2', title: 'Establish an access-granting/lockout policy', summary: 'Control how access is granted and lock accounts after repeated failed logins.' },
  { framework: CIS, controlId: '7.3', title: 'Automated operating system patch management', summary: 'Apply operating-system security updates automatically and promptly.' },
  { framework: CIS, controlId: '8.2', title: 'Collect audit logs', summary: 'Enable and retain security audit logging on systems.' },
  { framework: CIS, controlId: '10.1', title: 'Deploy anti-malware software', summary: 'Run centrally managed anti-malware protection on endpoints.' },
  { framework: CIS, controlId: '10.2', title: 'Automatic anti-malware signature updates', summary: 'Keep anti-malware detection content updated automatically.' },

  // --- NIST CSF 2.0 (subcategory level) ---
  { framework: NIST, controlId: 'ID.AM-02', title: 'Software/services inventory', summary: 'Inventories of software and services are maintained.' },
  { framework: NIST, controlId: 'ID.RA-01', title: 'Vulnerabilities identified', summary: 'Vulnerabilities in assets are identified, validated, and recorded.' },
  { framework: NIST, controlId: 'PR.AA-01', title: 'Identities and credentials managed', summary: 'Identities and credentials for authorized users and devices are managed.' },
  { framework: NIST, controlId: 'PR.AA-03', title: 'Users and devices authenticated', summary: 'Users, services, and hardware are authenticated.' },
  { framework: NIST, controlId: 'PR.AA-05', title: 'Least-privilege access', summary: 'Access permissions and authorizations follow least privilege and separation of duties.' },
  { framework: NIST, controlId: 'PR.DS-01', title: 'Data-at-rest protected', summary: 'The confidentiality and integrity of data at rest are protected.' },
  { framework: NIST, controlId: 'PR.IR-01', title: 'Networks protected', summary: 'Networks and environments are protected from unauthorized logical access.' },
  { framework: NIST, controlId: 'PR.PS-01', title: 'Configuration management', summary: 'Configuration management practices are established and applied.' },
  { framework: NIST, controlId: 'PR.PS-02', title: 'Software maintenance', summary: 'Software is maintained, replaced, and removed commensurate with risk.' },
  { framework: NIST, controlId: 'PR.PS-05', title: 'Malicious code prevention', summary: 'Installation and execution of unauthorized software and malicious code are prevented.' },
  { framework: NIST, controlId: 'DE.CM-01', title: 'Network monitoring', summary: 'Networks and network services are monitored to find potentially adverse events.' },
];

const key = (framework: string, controlId: string): string => `${framework}::${controlId}`;

const catalogIndex = new Map<string, ControlDefinition>(
  CONTROL_CATALOG.map((c) => [key(c.framework, c.controlId), c]),
);

export function getControl(framework: string, controlId: string): ControlDefinition | undefined {
  return catalogIndex.get(key(framework, controlId));
}

export const FRAMEWORK_REFERENCES: Record<string, { label: string; url: string }> = {
  [CIS]: { label: 'CIS Critical Security Controls v8', url: 'https://www.cisecurity.org/controls/v8' },
  [NIST]: { label: 'NIST Cybersecurity Framework 2.0', url: 'https://www.nist.gov/cyberframework' },
};
