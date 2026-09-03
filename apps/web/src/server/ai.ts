import 'server-only';
import { getCheck } from '@smb/checks';
import { createAiClient, type AiArtifact, type AiFinding, type AiReportInput } from '@smb/ai';
import { env } from '@/lib/env';
import { computePosture } from '@/server/scoring';
import { activeFindingsForOrg } from '@/server/tenant';

const client = createAiClient({
  apiKey: env.ANTHROPIC_API_KEY || undefined,
  model: env.ANTHROPIC_MODEL,
  maxTokens: env.ANTHROPIC_MAX_TOKENS,
});

export const aiEnabled = client.enabled;

/** Assemble the minimized, structured AI input for an organization. */
export async function buildAiInput(organizationId: string, organizationName: string, isDemo: boolean): Promise<AiReportInput> {
  const [posture, active] = await Promise.all([
    computePosture(organizationId),
    activeFindingsForOrg(organizationId),
  ]);

  // one AiFinding per checkId, aggregated across assets
  const byCheck = new Map<string, AiFinding>();
  for (const f of active) {
    const check = getCheck(f.checkId);
    const existing = byCheck.get(f.checkId);
    if (existing) {
      existing.affectedAssets += 1;
      continue;
    }
    byCheck.set(f.checkId, {
      id: f.id,
      checkId: f.checkId,
      title: check?.name ?? f.checkId,
      severity: f.severity,
      category: f.category,
      affectedAssets: 1,
      whatWeFound: check?.remediation.whatWeFound ?? 'A configuration gap was detected.',
      recommendedFix: check?.remediation.recommendedFix.join(' ') ?? 'See remediation guidance.',
      frameworks: (check?.frameworks ?? []).map((fm) => `${fm.framework.split(' ')[0]} ${fm.controlId}`),
    });
  }

  return {
    organization: organizationName,
    isDemo,
    score: posture.score ?? 100,
    band: posture.band ?? 'Excellent',
    counts: posture.counts,
    assetCount: posture.assetCount,
    findings: [...byCheck.values()].sort(
      (a, b) =>
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(a.severity) -
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(b.severity),
    ),
  };
}

export async function generateArtifact(
  artifact: AiArtifact,
  input: AiReportInput,
): Promise<{ text: string; degraded: boolean; model: string | null }> {
  const res = await client.generate(artifact, input);
  return { text: res.text, degraded: res.degraded, model: res.model };
}

/** For a single-finding explanation, narrow the input to that finding. */
export function narrowToFinding(input: AiReportInput, findingId: string): AiReportInput {
  const finding = input.findings.find((f) => f.id === findingId);
  return { ...input, findings: finding ? [finding] : input.findings.slice(0, 1) };
}
