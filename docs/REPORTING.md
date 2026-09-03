# Reporting

A report is an immutable snapshot of an organization's posture at generation
time. It can be viewed online and downloaded as PDF.

## Structure
1. **Cover** — organization, assessment date, security score, scan count
2. **Executive Summary** *(AI-generated or deterministic fallback)*
3. **Security Posture** — org score + category scores, trend vs. previous scan
4. **Top Risks** — prioritization-engine output ("fix these first")
5. **Detailed Findings** — grouped by severity; each with the four provenance
   blocks below
6. **Remediation Recommendations** — owner, effort, steps, verification method
7. **Control Alignment** — CIS Controls v8 + NIST CSF 2.0 coverage tables
8. **Remediation Progress** — resolved / new / unchanged since prior report
9. **Assessment Methodology** — what was checked and how (read-only)
10. **Limitations** — coverage gaps, point-in-time nature, no network testing
11. **Disclaimer** — verbatim text below

## Integrity model — every statement is labeled by provenance
| Label | Source | Example |
| --- | --- | --- |
| **Observed** | Scanner evidence, verbatim | "Firewall profile Domain: Disabled" |
| **Assessed** | Deterministic app logic | "Status: FAIL · Severity: HIGH · Category: Network Security" |
| **Recommended** | Check definition | "Enable the Domain firewall profile via …" |
| **AI-generated** | Claude narration | "Your organization has a moderate posture…" |

AI-generated text is visually distinct and never overwrites Observed/Assessed
values. If AI is unavailable the report still generates with deterministic text
in the narrative slots.

## Disclaimer (included on every report)
> This assessment identifies security configuration gaps and provides
> control-alignment guidance. It is not a legal determination of regulatory
> compliance, certification, or audit readiness. Results reflect the state of the
> assessed systems at the time of the scan and depend on the checks performed;
> absence of a finding is not a guarantee that no risk exists.

## Score presentation
The score is rendered as `NN / 100` with a band label (Excellent / Good /
Moderate / Weak / Critical) and the sentence: *"This is an internal risk
indicator, not a precise measurement."* The report links to the scoring model
(`packages/risk-engine/SCORING.md`) so any number can be explained.

## PDF
Rendered server-side with `@react-pdf/renderer` from the same report JSON. No
client-side generation; the download route is org-scoped.
