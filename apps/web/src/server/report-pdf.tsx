import 'server-only';
import { Document, Page, Text, View, StyleSheet, renderToBuffer, type DocumentProps } from '@react-pdf/renderer';
import { createElement as h, type ReactElement } from 'react';
import type { ReportSnapshot } from '@/server/report';

const s = StyleSheet.create({
  page: { padding: 40, fontSize: 10, fontFamily: 'Helvetica', color: '#0f172a', lineHeight: 1.4 },
  h1: { fontSize: 20, fontFamily: 'Helvetica-Bold', marginBottom: 4 },
  h2: { fontSize: 13, fontFamily: 'Helvetica-Bold', marginTop: 16, marginBottom: 4 },
  muted: { color: '#64748b' },
  score: { fontSize: 32, fontFamily: 'Helvetica-Bold', marginVertical: 6 },
  row: { flexDirection: 'row', justifyContent: 'space-between', borderBottom: '1 solid #e2e8f0', paddingVertical: 2 },
  tag: { fontSize: 8, color: '#475569' },
  block: { marginBottom: 8 },
  disclaimer: { marginTop: 20, fontSize: 8, color: '#64748b', borderTop: '1 solid #e2e8f0', paddingTop: 8 },
});

function ReportDoc({ snap }: { snap: ReportSnapshot }) {
  return h(
    Document,
    null,
    h(
      Page,
      { size: 'A4', style: s.page },
      h(Text, { style: s.h1 }, `Security Assessment — ${snap.organization}${snap.isDemo ? ' (DEMO DATA)' : ''}`),
      h(Text, { style: s.muted }, `Generated ${new Date(snap.generatedAt).toLocaleString('en-US')}`),
      h(Text, { style: s.score }, `${snap.score} / 100 — ${snap.band}`),
      h(Text, { style: s.muted }, 'This score is an internal risk indicator, not a precise measurement.'),

      h(Text, { style: s.h2 }, `Executive Summary  [${snap.executiveSummary.provenance}]`),
      h(Text, { style: s.block }, snap.executiveSummary.text),

      h(Text, { style: s.h2 }, 'Security Posture  [assessed]'),
      ...snap.posture.categories.map((c, i) =>
        h(View, { key: i, style: s.row }, h(Text, null, c.category), h(Text, null, String(c.score ?? '—'))),
      ),

      h(Text, { style: s.h2 }, 'Top Risks  [assessed]'),
      ...snap.topRisks.items.map((r, i) =>
        h(Text, { key: i }, `${r.rank}. ${r.title} — ${r.severity}, ${r.affectedAssets} device(s), effort ${r.effortLabel}`),
      ),

      h(Text, { style: s.h2 }, 'Detailed Findings'),
      ...snap.findings.items.map((f, i) =>
        h(
          View,
          { key: i, style: s.block },
          h(Text, { style: { fontFamily: 'Helvetica-Bold' } }, `${f.title} — ${f.severity}`),
          h(Text, { style: s.tag }, `Observed: ${f.observed}`),
          h(Text, { style: s.tag }, `Assessed: ${f.assessed}`),
          h(Text, { style: s.tag }, `Recommended: ${f.recommended.join(' ')}`),
          h(Text, { style: s.tag }, `Verification: ${f.verification}`),
          h(Text, { style: s.tag }, f.controls.join(' · ')),
        ),
      ),

      h(Text, { style: s.h2 }, 'Control Alignment  [assessed]'),
      ...snap.controlAlignment.frameworks.map((fw, i) =>
        h(
          Text,
          { key: i },
          `${fw.framework}: ${fw.aligned} aligned, ${fw.gaps} with gaps, ${fw.notAssessed} not assessed (of ${fw.total})`,
        ),
      ),

      h(Text, { style: s.h2 }, `Narrative  [${snap.narrative.provenance}]`),
      h(Text, { style: s.block }, snap.narrative.text),

      h(Text, { style: s.h2 }, 'Methodology & Limitations  [assessed]'),
      h(Text, { style: s.block }, snap.methodology.text),
      h(Text, { style: s.block }, snap.limitations.text),

      h(Text, { style: s.disclaimer }, snap.disclaimer),
    ),
  );
}

export function renderReportPdf(snap: ReportSnapshot): Promise<Buffer> {
  return renderToBuffer(h(ReportDoc, { snap }) as unknown as ReactElement<DocumentProps>);
}
