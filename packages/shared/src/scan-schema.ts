/**
 * The scan-ingestion trust boundary.
 *
 * Anything posted to `/api/scans` is UNTRUSTED. This schema is deliberately
 * strict: unknown keys are rejected, arrays are length-bounded, strings are
 * length-bounded, and timestamps must be real ISO-8601. The server further
 * ignores any `severity`/`category` the client sends and derives authoritative
 * values from the `@smb/checks` registry (see THREAT_MODEL T3/T4).
 */
import { z } from 'zod';
import { CHECK_STATUSES, PLATFORMS } from './types.js';

export const SCAN_SCHEMA_VERSION = '1.0' as const;

const MAX_FINDINGS = 500;
const MAX_EVIDENCE_CHARS = 4_000;

const isoDateTime = z
  .string()
  .datetime({ offset: true })
  .describe('ISO-8601 timestamp with timezone offset');

/** A single check outcome as observed on the endpoint (Detection only). */
export const ScanFindingSchema = z
  .object({
    checkId: z
      .string()
      .regex(/^[A-Z]{3}-[A-Z0-9]{2,6}-\d{3}$/, 'checkId must look like WIN-FW-001'),
    status: z.enum(CHECK_STATUSES),
    /** Verbatim, minimal proof supporting the status. Rendered as text only. */
    evidence: z.string().max(MAX_EVIDENCE_CHARS),
    observedAt: isoDateTime,
    /**
     * The scanner MAY include these for its own local display. The server
     * strips them; they are never trusted. Kept in the schema so a payload
     * that includes them is still accepted rather than rejected.
     */
    severity: z.string().max(16).optional(),
    category: z.string().max(64).optional(),
  })
  .strict();

export type ScanFinding = z.infer<typeof ScanFindingSchema>;

export const SecurityScanResultSchema = z
  .object({
    schemaVersion: z.literal(SCAN_SCHEMA_VERSION),
    asset: z
      .object({
        hostname: z.string().min(1).max(255),
        platform: z.enum(PLATFORMS),
        osVersion: z.string().min(1).max(255),
      })
      .strict(),
    scan: z
      .object({
        startedAt: isoDateTime,
        completedAt: isoDateTime,
        scannerVersion: z.string().min(1).max(32),
      })
      .strict()
      .refine((s) => Date.parse(s.completedAt) >= Date.parse(s.startedAt), {
        message: 'completedAt must be at or after startedAt',
        path: ['completedAt'],
      }),
    findings: z.array(ScanFindingSchema).min(1).max(MAX_FINDINGS),
  })
  .strict()
  .superRefine((result, ctx) => {
    const seen = new Set<string>();
    result.findings.forEach((f, i) => {
      if (seen.has(f.checkId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate checkId ${f.checkId}`,
          path: ['findings', i, 'checkId'],
        });
      }
      seen.add(f.checkId);
    });
  });

export type SecurityScanResult = z.infer<typeof SecurityScanResultSchema>;

export const SCAN_LIMITS = {
  MAX_FINDINGS,
  MAX_EVIDENCE_CHARS,
} as const;
