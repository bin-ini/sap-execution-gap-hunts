# Contributing

Thanks for considering a contribution. This repo is cross-domain SAP + Defender **hunting** content, so
the bar is a little different from a tuned detection ruleset.

## Adding or changing a hunt

Each hunt lives in `hunts/EGnn_short_name.kql` and must keep the standard header block so the notebook
loader and `scripts/validate.py` can parse it:

```
// Hunt ID   : EGnn
// Title     : <one line>
// Theme     : <theme>
// Hypothesis: <what adversary behaviour this tests>
// MITRE     : <techniques>
// Data      : <tables / functions / prerequisites>
```

Guidelines:

- **Cross the boundary.** If a hunt can be satisfied by SAP telemetry alone, it probably overlaps the OOB
  solution — say why it does not, or make it a SAP-only hunt only when the sequence logic is the point
  (EG04).
- **Baseline, don't blocklist.** Prefer first-seen / rarity over static "bad" lists where you can.
- **Be explicit about correlation.** State the time window and the host-join assumption; there is no
  shared key between SAP SAL and MDE.
- **Stay portable.** Use `column_ifexists(...)` for fields that differ between the native `ABAPAuditLog`,
  the legacy `*_CL` tables, and the `SAPAuditLog` function.
- **Document false positives and triage** in the header. A hunt without an FP section is not done.

## Before you open a PR

```bash
python scripts/validate.py
```

CI runs the same check. Please note in the PR whether the query was executed against a real workspace or
only structurally validated, and never commit `msticpyconfig.yaml` or any secret.

## Novelty claims

If you describe content as "new," cite the sources you checked and the date. Prefer "not found in X as of
<date>" over absolute claims, and credit prior art you build on.
