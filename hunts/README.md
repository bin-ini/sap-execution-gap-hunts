# Hunts index

Five execution-gap hunts. Each file is standalone and carries its full header (hypothesis, ATT&CK,
why-not-OOB, data/prereqs, tuning, false positives, triage). Paste one into Sentinel **Logs** or Defender
**Advanced hunting**, or run them all from the notebook.

| ID | File | ATT&CK | Needs MDE on SAP hosts? |
|----|------|--------|-------------------------|
| EG01 | `EG01_sap_txn_to_unexpected_os_process.kql` | T1059, T1059.004, T1203 | Yes |
| EG02 | `EG02_sap_action_to_first_seen_destination.kql` | T1071, T1041 | Yes |
| EG03 | `EG03_sap_os_identity_divergence.kql` | T1078, T1134 | Yes |
| EG04 | `EG04_sap_landscape_traversal_anomaly.kql` | T1021, T1199 | No (SAP telemetry only) |
| EG05 | `EG05_sap_low_and_slow_chain.kql` | chains T1001/T1078/T1059/T1071 | Yes (for stages D/E) |

## Running order (recommended)

1. **EG04** and the notebook baselines first — least environment-sensitive, no host-join dependency.
2. Build/verify the **SAP host ↔ Defender device** map (notebook section 4, or a `SAP - Host Map` watchlist).
3. Then **EG01 → EG02 → EG03**, and finally **EG05** once the others are behaving.

## Tuning knobs you will almost certainly touch

- `baseline` / `detect` windows and the `corrWindow` correlation windows.
- `sapParents` — the SAP application-server process names in your estate.
- The debug message IDs in EG03/EG05 (`CUL`, `BUZ`, `CU_M`, `CUN`, `CUO`, `CUP`) — confirm the active set
  for your kernel via `RSAU_SYNC_EVENTS`.
- `Variable*` field positions used to pull a target user / RFC FM name — validate against your SAL layout.
- Watchlists referenced: **SAP - Systems** (EG04), **SAP - Sensitive Transactions** (EG05), and the
  optional **SAP - Networks** / **SAP - Host Map** / **SAP - Host Service Accounts** you maintain.
