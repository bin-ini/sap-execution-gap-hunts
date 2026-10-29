# Hunting the SAP Execution Gap

*Finding attacks where SAP says one thing and the underlying infrastructure does another.*

Most SAP detection content answers one question very well: *what did a user do inside SAP?* Microsoft's
Sentinel solution for SAP is a good example. It reads the Security Audit Log, change documents, user
master data and authorization details, and it fires when someone runs a sensitive transaction, grants a
dangerous profile, debugs in production, or disables the audit log. That visibility is real and it is
valuable.

But it stops at the edge of SAP. The moment a business action turns into something on the operating
system — a process spawned on the application server, an outbound connection to a host that server has
never talked to, a command running under an OS identity that has nothing to do with the SAP user — the
SAP audit log goes quiet. Microsoft Defender sees that layer in rich detail, but Defender on its own has
no idea which SAP transaction or which SAP user set it in motion.

Sophisticated attacks live in that seam. An adversary who has learned to operate inside an SAP landscape
knows that the two telemetry worlds are usually watched by different rules, different teams, sometimes
different portals. This post is about deliberately hunting the seam: correlating SAP *business intent*
with downstream *technical execution* to surface chains that neither source makes obvious alone. It comes
with five hunts and a notebook, and — just as importantly — an honest account of what is hard about it and
what is genuinely new.

## Two telemetry worlds, one attack

Think of an SAP compromise as a chain that crosses a boundary:

```
SAP user  →  transaction / report  →  SAP application server  →  SAP work process
                                                                      ↓
                                                        UNEXPECTED OS process
                                                                      ↓
                                                        network connection to a
                                                        destination never seen
                                                        for this workload
```

The top half of that chain is SAP's world. `ABAPAuditLog` knows the user, the client, the transaction,
the program, the terminal. The bottom half is Defender's world. `DeviceProcessEvents` knows the parent
process, the child process, the command line and the OS account; `DeviceNetworkEvents` knows the remote
address and the process that opened it. Each half is well instrumented. What is missing is the line drawn
*between* them.

A single-domain rule cannot draw that line. An SAP-only rule that flags "debugging in production" never
learns that thirty seconds later `disp+work` spawned a shell that ran `curl`. A Defender-only rule that
flags "a server contacted a rare IP" never learns that the server is an SAP production system and the
connection followed a sensitive RFC call by a dormant account. The signal is the *join*: same host, close
in time, business action followed by anomalous execution. That join is what these hunts compute, and it is
also, as we will see, the part that takes real care to get right.

## Why not just write more SAP-audit rules

Because that ground is already well covered, and pretending otherwise would waste everyone's time. Before
building anything, it is worth being specific about what the out-of-the-box (OOB) solution and Content Hub
already detect, so the new work aims at a real gap rather than a crowded one. The shipped SAP content
includes, among roughly four dozen rules:

- Sensitive transaction, program and function-module execution, and direct sensitive-table access by both
  dialog and RFC logon.
- Dynamic RFC destinations, debugging activity, data changed during debugging, and audit-log deactivation
  or reconfiguration.
- User creation-and-use, unlock-and-use, sensitive-role and sensitive-profile assignment,
  critical-authorization assignment, and privileged-user changes.
- Multiple-file download, high-volume sensitive-data export, and even a preview rule correlating SAP
  sensitive activity with Defender device file events and recently mounted USB media.
- Two dynamic audit-log engines — a deterministic monitor and an unsupervised anomaly monitor — that score
  SAP audit events themselves.

That is a strong SAP-audit-centric program. A sixth rule for "sensitive transaction executed" adds
nothing. The unaddressed space is almost entirely *cross-domain*: the OOB anomaly processing reasons about
SAP events in isolation, and the one cross-product rule that exists is narrow (USB media). So the design
principle for everything that follows is simple — if a hunt can be satisfied by SAP telemetry alone, it
probably already exists; the value is in the join to infrastructure behavior.

## The five hunts

| ID | Hunt | The join it computes | Tables |
|----|------|----------------------|--------|
| EG01 | SAP activity → unexpected OS child process | SAP action on a host ↔ first-seen process lineage under SAP parents on that host | `ABAPAuditLog` + `DeviceProcessEvents` |
| EG02 | SAP action → first-seen destination | SAP action on a host ↔ a destination that host's workload has never reached | `ABAPAuditLog` + `DeviceNetworkEvents` |
| EG03 | SAP actor ↔ OS identity divergence | powerful host activity under an unexpected OS principal near SAP admin events | `ABAPAuditLog` + `DeviceProcessEvents` |
| EG04 | Landscape traversal anomaly | one identity crossing SAP tiers (DEV/QA/PROD) in a tight window | `SAPAuditLog` + `SAPSystems()` |
| EG05 | Low-and-slow execution chain | logon → privilege → action → host process → destination, scored together | all of the above |

EG04 is the one that needs only SAP telemetry, so it runs even without Defender on the SAP hosts; the rest
are true cross-domain hunts.

**EG01 in detail.** The hypothesis is that a SAP application-server process — `disp+work`, `sapstartsrv`,
`gwrd`, `icman`, `sapxpg` and friends — spawns a child it has no business spawning. The naive version of
this is a blocklist of "bad" binaries, which ages badly and misses anything novel. EG01 instead *baselines
the host's own lineage*: over thirty days it records which (parent → child) pairs are normal for SAP
parents on each SAP host, then in the detection window it reports only the lineage that has never been seen
there. A shell or interpreter or network tool born from the SAP process tree scores highest, but the
detection is the first-seen lineage, not the name.

The cross-domain step is the enrichment: each anomalous process is joined back to the nearest preceding SAP
action on the same host, so the analyst sees *who* was doing *what* in SAP in the ten minutes before
`disp+work` launched a shell. Crucially, that join is temporal and host-based, not a shared identifier —
SAP and Defender share no correlation key — so EG01 is explicit about its window and treats the result as
a lead to confirm, not a verdict.

## EG05 and an explainable risk score

The most interesting hunt is the one that refuses to fire on any single event. A capable attacker spreads
steps out: an unusual logon at T0, a quiet privilege change at T0+17m, a sensitive transaction at T0+2h,
an odd process on the SAP host at T0+5h, a first-seen destination at T0+7h. Each link, on its own, sits
below every threshold. Assembled, the chain is loud.

EG05 and its companion notebook reconstruct that chain per identity and score it. The score is
deliberately *explainable* — not "the model says 0.91," but a sum of attributable terms:

```
SequenceRisk = ( IdentityRarity      // new source / hour / system for this user
              + TransactionRarity    // transactions this user never ran
              + PrivilegeDelta       // a privilege change targeted this user
              + ProcessRarity        // first-seen SAP-parent child process on a host they used
              + DestinationRarity )  // first-seen external destination from a host they used
              × (1 + TemporalCompression)   // how tightly the stages cluster in time
```

Every term carries its evidence, so a triaging analyst can read *why* an identity scored where it did and
dismiss or escalate on the merits. The notebook does the rigorous version: it learns per-user and per-host
baselines, computes each term from real rarity rather than a static list, keeps the per-term breakdown on
every row, and draws a landscape graph of the top chains (user → system → host → process → destination).
The KQL version of EG05 is a lighter triage-grade assembler that approximates the same idea directly in
Log Analytics — useful on its own, and honest about where it is coarse (it attributes host-level process
and network anomalies to every identity active on that host, which the notebook then refines).

## The hard parts (don't skip these)

This approach has three failure modes that will quietly wreck it if ignored.

**The host join is load-bearing.** Everything cross-domain depends on mapping an SAP host to a Defender
device. SAP gives you `Host`, `Computer` and `Instance` (formatted `<HOST>*<SYSID>*<SYSNR>`); Defender
gives you `DeviceName`. The hunts match on the lower-cased short hostname, which works until it doesn't —
FQDNs, clustered instances, virtual hostnames and renamed devices all break it silently. In production,
maintain an explicit mapping (a `SAP - Host Map` watchlist, or the notebook's `HOST_MAP`), and treat every
unmatched SAP host as a blind spot the notebook calls out for you. Get this wrong and you get confident
nonsense.

**SAP identity is not OS identity.** SAP never passes the SAP dialog user down to the operating system;
work processes run as `<sid>adm` or `SAPService<SID>`. So there is no literal SAP-user-to-OS-user mapping
to join on. EG03 and the divergence score therefore reason about *expected versus unexpected OS principals*
performing powerful actions on SAP hosts around the time of SAP admin events. That surfaces candidates — a
human admin account, an unexpected service account — for review; it is not proof of impersonation, and the
hunt says so.

**Correlation is temporal, not causal.** With no shared key between SAL and MDE, "the process followed the
transaction" is an inference from proximity in time on a shared host. Busy production servers will produce
coincidences. That is why these are *hunts* with explicit windows, feeding analyst judgment, rather than
high-confidence alerts — and why the notebook's baselines exist, to push the coincidence rate down before a
human ever looks.

And one prerequisite that is really a design constraint: Defender for Endpoint must be deployed on the SAP
application servers themselves. Without it, four of the five hunts have no infrastructure side to join to,
and only EG04 (pure SAP telemetry) remains.

## On the word "novel"

It is worth being careful here, because overclaiming is easy and cheap. The *direction* is not new and is
in fact encouraged: Microsoft's own SAP solution documentation tells you to correlate SAP activity with
Defender for Endpoint, Entra and network signals, and there are good demonstrations of cross-product
correlation in practice — the "Worm in the Supply Chain" write-up tying Defender for Endpoint to Sentinel
for SAP BTP, and conceptual agentic-SOC patterns that chain a process to its parent and then to a
first-seen outbound destination. This work also stands on existing building blocks such as the
`DeviceProcessEvents-ProcessTree` make-graph function in the Azure-Sentinel repository.

What a review of the current OOB SAP solution, the Content Hub, and adjacent community content did *not*
surface, as of October 2026, was packaged hunts that implement these specific joins: SAP business action
to infrastructure execution (EG01/EG02), SAP-actor to OS-identity divergence (EG03), landscape traversal
scored by tier role (EG04), or an explainable multi-stage SAP-plus-Defender sequence score (EG05). The
honest phrasing is therefore "not found in those sources as of this date," not "nobody has ever done this."
The Azure-Sentinel repository's broader hunting-query collection is larger than the packaged SAP solution,
so before publishing anything with the word *novel* in it, re-check: the Content Hub SAP solution; the
Azure-Sentinel repo's hunting queries and solutions; Tech Community; the SAP community blogs; and MSTIC
research. Then credit the adjacent prior art you built on. That posture costs a little swagger and buys a
lot of credibility.

## Running it, tuning it, promoting it

To put this to work:

1. **Confirm prerequisites.** The Sentinel solution for SAP ingesting the SAP tables, and Defender for
   Endpoint on the SAP application servers. Build or verify the SAP-host to Defender-device map first —
   nothing downstream is trustworthy until that is right.
2. **Start in the notebook.** It connects with MSTICpy, builds the host map and the identity and host
   baselines, sweeps the five hunts, computes the explainable `SequenceRisk`, and draws the landscape
   graph. Review what the host map failed to match before trusting the cross-domain results.
3. **Tune to your estate.** Every hunt exposes its windows and thresholds, and uses `column_ifexists(...)`
   so it degrades gracefully across the native `ABAPAuditLog`, the legacy `*_CL` tables, and the
   schema-stable `SAPAuditLog` function. Expect to adjust the SAP-parent process list, the baseline
   length, and the correlation windows; production servers are noisy and the baselines need a few
   iterations to settle.
4. **Promote what proves out.** When a hunt earns its keep, copy its KQL into a Sentinel scheduled
   analytics rule or a Defender custom detection, map entities (`User` to Account, host and remote address
   to Host and IP, `SystemID` to a custom entity), keep the behavioral windows, and reference the EG id in
   the rule description so the lineage back to this research is clear.

The larger point is not these five queries. It is that SAP security monitoring has quietly become an XDR
problem. The business layer and the infrastructure layer are each well instrumented; the attacks that
matter increasingly cross between them, and the detections that matter will have to cross with them.
