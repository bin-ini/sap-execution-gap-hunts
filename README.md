# Hunting the SAP Execution Gap

Cross-domain Microsoft Sentinel + Microsoft Defender threat-hunting content that correlates **SAP
business intent** (what Sentinel sees inside SAP) with **downstream technical execution** (what Defender
sees on the infrastructure). The aim is to surface attack chains that live in the **boundary between the
two telemetry layers** — where SAP says one thing and the host does another — rather than reproducing the
out-of-the-box (OOB) Sentinel solution for SAP or Content Hub detections.

> Microsoft Sentinel gives the SOC visibility into what happened *inside* SAP, while Defender provides
> rich visibility into endpoint and infrastructure activity. Sophisticated attacks can hide in the
> boundary between those layers. This content explores whether correlating SAP business intent with
> downstream technical execution surfaces attack chains that neither telemetry source makes obvious in
> isolation.

See [`docs/hunting-the-sap-execution-gap.md`](docs/hunting-the-sap-execution-gap.md) for the full write-up.

## The hunts

| ID | Hunt | The join it computes | Tables |
|----|------|----------------------|--------|
| [EG01](hunts/EG01_sap_txn_to_unexpected_os_process.kql) | SAP activity → unexpected OS child process | SAP action on a host ↔ first-seen process lineage under SAP parents on that host | `ABAPAuditLog` + `DeviceProcessEvents` |
| [EG02](hunts/EG02_sap_action_to_first_seen_destination.kql) | SAP action → first-seen outbound destination | SAP action on a host ↔ a destination that host's workload has never reached | `ABAPAuditLog` + `DeviceNetworkEvents` |
| [EG03](hunts/EG03_sap_os_identity_divergence.kql) | SAP actor ↔ OS identity divergence | powerful host activity under an unexpected OS principal near SAP admin events | `ABAPAuditLog` + `DeviceProcessEvents` |
| [EG04](hunts/EG04_sap_landscape_traversal_anomaly.kql) | SAP landscape traversal anomaly | one identity crossing SAP tiers (DEV/QA/PROD) in a tight window | `SAPAuditLog` + `SAPSystems()` |
| [EG05](hunts/EG05_sap_low_and_slow_chain.kql) | SAP low-and-slow execution chain | logon → privilege → action → host process → destination, scored together | all of the above |

EG04 uses only SAP telemetry, so it runs even without Defender on the SAP hosts; the rest are true
cross-domain hunts. Each `.kql` carries its own header: hypothesis, ATT&CK mapping, why-not-OOB,
data/prereqs, tuning, false positives, and triage. See [`hunts/README.md`](hunts/README.md) for the index.

## The notebook

[`notebooks/SAP_Execution_Chain_Hunter.ipynb`](notebooks/SAP_Execution_Chain_Hunter.ipynb) (MSTICpy +
Sentinel) builds the host↔device map, an identity baseline and a host baseline, sweeps the five hunts,
computes an **explainable `SequenceRisk`** per identity (every term attributable), draws a
User→System→Host→Process→Destination landscape graph, and scores per-host business-to-infrastructure
divergence. A percent-format `.py` export sits alongside it for easy reading/diffing.

## Prerequisites

1. **Microsoft Sentinel solution for SAP applications** deployed and ingesting the SAP tables.
2. **Microsoft Defender for Endpoint on the SAP application servers** (for the cross-domain hunts), via
   the Microsoft Defender XDR connector.
3. **A reliable SAP-host ↔ Defender-device join.** SAP `Host`/`Computer`/`Instance` must map to Defender
   `DeviceName`. The hunts match on the lower-cased short hostname; for production, maintain an explicit
   map (a `SAP - Host Map` watchlist, or the notebook's `HOST_MAP`). Every unmatched host is a blind spot.
4. There is **no shared correlation key** between SAP SAL and MDE, so correlation is **temporal +
   same-host**. Treat results as leads, not verdicts.

> **SAP → OS identity is not literal.** SAP work runs as `<sid>adm` / `SAPService<SID>`; EG03 and the
> divergence score reason about *expected vs unexpected OS principals*, never a literal SAP-user→OS-user map.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
jupyter lab notebooks/SAP_Execution_Chain_Hunter.ipynb
```

Set your workspace in `msticpyconfig.yaml`, run the notebook top to bottom, and review the host-map output
before trusting any cross-domain result. Or paste a single `.kql` into Sentinel Logs / Defender Advanced
hunting to test it directly.

## Schema portability

- **EG04** queries the schema-stable `SAPAuditLog` *function* (portable across the agentless native
  `ABAPAuditLog` and the legacy agent `ABAPAuditLog_CL`).
- **EG01/EG02/EG03/EG05** read native tables (`ABAPAuditLog`, `ABAPChangeDocsLog`) because they need host
  columns; legacy equivalents are the `*_CL` tables. Every query uses `column_ifexists(...)` for fields
  that differ between schemas, so it degrades gracefully.

## Novelty & honesty

The *direction* (SAP↔Defender correlation) is endorsed by Microsoft's SAP solution docs and demonstrated
in incident write-ups; the *specific* execution-gap / landscape-traversal / divergence hunts here were
**not found** in the current OOB SAP solution, Content Hub, or adjacent community content **as of October
2026**. That is "not found," not "proven novel." Re-check the Content Hub SAP solution, the
`Azure/Azure-Sentinel` repo (hunting queries *and* solutions), Tech Community, the SAP community blogs, and
MSTIC research before publishing, and credit adjacent prior art (e.g. the `DeviceProcessEvents-ProcessTree`
make-graph function). See the write-up for details.

## Status & disclaimer

These are **hunting** queries, not tuned production detections. Thresholds, the SAP-parent process list,
the debug message IDs, and `Variable*` field positions are starting points that need tuning to your
kernel / SAL configuration and estate. Validated for structure, **not** executed against a live workspace.
Test in a non-production workspace first. Provided as-is under the MIT License.

## Layout

```
.
├── hunts/            # EG01–EG05 KQL hunts (+ index)
├── notebooks/        # SAP Execution Chain Hunter (.ipynb + .py)
├── docs/             # the write-up
├── scripts/          # repo validation (used by CI)
├── results/          # notebook CSV exports land here (git-ignored)
├── requirements.txt
├── CONTRIBUTING.md
└── LICENSE
```

## License

[MIT](LICENSE). Change the copyright holder in `LICENSE` before publishing.
