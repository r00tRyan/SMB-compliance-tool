#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { getCheck, listChecks } from '@smb/checks';
import { SCAN_SCHEMA_VERSION, type Platform } from '@smb/shared';
import { formatReadable } from './format.js';
import { runScan, SCANNER_VERSION } from './runner.js';

const HELP = `security-agent — read-only endpoint security assessment (v${SCANNER_VERSION})

This tool assesses the system it is run on. It does not scan other hosts,
exploit anything, or change any configuration.

Usage:
  security-agent scan [--output <file>] [--json] [--only <id,id>] [-v]
  security-agent check <CHECK-ID>
  security-agent list
  security-agent version

Options:
  --output <file>   also write the structured JSON result to <file>
  --json            print JSON to stdout only (no readable summary)
  --only <ids>      run only these comma-separated check ids
  -v, --verbose     show evidence for every check (not just failures)
`;

interface ParsedArgs {
  command: string;
  positional: string[];
  output?: string;
  json: boolean;
  only?: string[];
  verbose: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { command: argv[0] ?? 'help', positional: [], json: false, verbose: false };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--output') out.output = argv[++i];
    else if (a === '--json') out.json = true;
    else if (a === '--only') out.only = (argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '-v' || a === '--verbose') out.verbose = true;
    else if (a && !a.startsWith('-')) out.positional.push(a);
  }
  return out;
}

function detectPlatform(): Platform | null {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'linux') return 'linux';
  return null;
}

async function cmdScan(args: ParsedArgs): Promise<number> {
  const run = await runScan({ only: args.only });
  if (args.output) {
    await writeFile(args.output, JSON.stringify(run.result, null, 2) + '\n', 'utf8');
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(run.result, null, 2) + '\n');
  } else {
    process.stdout.write(formatReadable(run, args.verbose) + '\n');
    if (args.output) process.stdout.write(`\nWrote ${args.output}\n`);
  }
  const failed = run.result.findings.some((f) => f.status === 'FAIL');
  return failed ? 1 : 0;
}

async function cmdCheck(id: string): Promise<number> {
  const check = getCheck(id);
  if (!check) {
    process.stderr.write(`Unknown check id: ${id}\n`);
    return 2;
  }
  const platform = detectPlatform();
  if (platform && check.platform !== platform) {
    process.stdout.write(`${check.id} — ${check.name}\n`);
    process.stdout.write(`(this check targets ${check.platform}; current host is ${platform})\n`);
  }
  const run = await runScan({ platform: check.platform, only: [id] });
  const evaluated = run.checks[0]!;
  process.stdout.write(`${check.id} — ${check.name}\n`);
  process.stdout.write(`Category: ${check.category}   Severity: ${check.severity}\n\n`);
  process.stdout.write(`Result:   ${evaluated.status}\n`);
  process.stdout.write(`Evidence: ${evaluated.evidence}\n\n`);
  if (evaluated.status !== 'PASS') {
    process.stdout.write(`Why it matters: ${check.rationale}\n\n`);
    process.stdout.write('Recommended fix:\n');
    for (const step of check.remediation.recommendedFix) process.stdout.write(`  - ${step}\n`);
    process.stdout.write(`\nWho: ${check.remediation.who}   Effort: ${check.remediation.effort}\n`);
    process.stdout.write(`Verification: ${check.remediation.verification}\n`);
  }
  return evaluated.status === 'FAIL' ? 1 : 0;
}

function cmdList(): number {
  const platform = detectPlatform();
  const checks = listChecks(platform ?? undefined);
  process.stdout.write(
    platform ? `Checks for ${platform}:\n` : 'All checks (host platform not Windows/Linux):\n',
  );
  for (const c of checks) {
    process.stdout.write(`  ${c.id.padEnd(14)} ${c.severity.padEnd(8)} ${c.category.padEnd(22)} ${c.name}\n`);
  }
  process.stdout.write(`\n${checks.length} checks.\n`);
  return 0;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  switch (args.command) {
    case 'scan':
      return cmdScan(args);
    case 'check': {
      const id = args.positional[0];
      if (!id) {
        process.stderr.write('Usage: security-agent check <CHECK-ID>\n');
        return 2;
      }
      return cmdCheck(id);
    }
    case 'list':
      return cmdList();
    case 'version':
      process.stdout.write(`security-agent ${SCANNER_VERSION} (scan schema ${SCAN_SCHEMA_VERSION})\n`);
      return 0;
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(HELP);
      return 0;
    default:
      process.stderr.write(`Unknown command: ${args.command}\n\n${HELP}`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`Scan failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  });
