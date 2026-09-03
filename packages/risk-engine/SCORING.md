# Scoring Model

This model is **deterministic**. The same findings always produce the same
numbers. AI plays no part in any value here. The score is an **internal risk
indicator, not a precise measurement** — the UI says so wherever a number is
shown.

## Inputs

- The set of **active** findings. A finding is active unless its status is
  `RESOLVED`, `ACCEPTED_RISK`, or `FALSE_POSITIVE`.
- Each finding carries a `severity` and `category` — both taken from the
  `@smb/checks` registry, never from the uploaded scan.
- The list of asset ids in the organization.

## Organization score (0–100)

```
for each asset:
    assetPenalty = Σ SEVERITY_PENALTY[finding.severity]   over active findings on that asset
    assetScore   = clamp(100 - assetPenalty, 0, 100)

orgScore = round( mean(assetScore over all assets) )
```

With **no assets**, the score is `null` (empty state, not zero).

### Severity penalties

| Severity | Points removed per failing check (per asset) |
| --- | --- |
| CRITICAL | 40 |
| HIGH | 20 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO | 0 |

Rationale: two HIGH findings on a machine (−40) are treated as roughly one
CRITICAL (−40). Five MEDIUMs (−40) likewise. The clamp means a very unhealthy
machine bottoms out at 0 rather than going negative and dragging the mean.

### Bands

| Score | Band |
| --- | --- |
| 90–100 | Excellent |
| 75–89 | Good |
| 60–74 | Moderate |
| 40–59 | Weak |
| 0–39 | Critical |

## Category scores

Identical computation, restricted to findings whose `category` matches. An asset
with no findings in a category scores 100 for that category. The six categories:
Identity & Access, Endpoint Security, Network Security, Patch Management, Data
Protection, Logging & Monitoring.

## "Why is my score 71?"

`computeOrgScore` returns `contributions`: one row per failing check, aggregated
across assets, with `pointsDeducted` and `affectedAssets`, sorted by impact. The
dashboard renders this directly, e.g.:

> Windows Firewall disabled — HIGH — 4 devices — −80 points across your fleet

(The per-fleet figure is the sum of per-asset penalties; the org score itself is
the mean of per-asset scores, so a fleet-wide −80 with 5 assets moves the mean
by 16.)

## Prioritization ("fix these first")

Findings are grouped by `checkId` (one row of work, however many machines it
touches) and ranked by:

```
base       = SEVERITY_PRIORITY_WEIGHT[severity]         CRITICAL 40 / HIGH 20 / MEDIUM 8 / LOW 3 / INFO 1
coverage   = 0.5 + 0.5 * (affectedAssets / totalAssets)   0.5 .. 1.0
exposure   = EXPOSURE_FACTOR[category]                    Network 1.3, Identity 1.15, Endpoint/Data 1.1,
                                                          Patch 1.0, Logging 0.9
confidence = 0.6 if every affected result was a scanner ERROR, else 1.0
effortDiv  = 1.0 (≤5m) · 1.1 (≤15m) · 1.3 (≤30m) · 1.6 (≤1h) · 2.2 (IT support)

priorityScore = base * coverage * exposure * confidence / effortDiv
```

Ties break by severity, then affected-asset count, then effort (ascending), then
`checkId`. The result is deliberately *not* a plain severity sort: a HIGH fix
that takes 10 minutes and affects the whole fleet outranks a HIGH fix that needs
a hardware replacement on one machine.
