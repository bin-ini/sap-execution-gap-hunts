# SAP Execution Chain Hunter — notebook exported as a percent-format script.
# Open directly in Jupyter/VS Code, or import with jupytext. Cells are marked with # %%.

# %% [markdown]
# # SAP Execution Chain Hunter — hunting the SAP *execution gap*
# 
# Microsoft Sentinel shows the SOC **what happened inside SAP** (ABAPAuditLog, ABAPChangeDocsLog,
# user and authorization details). Microsoft Defender shows **what the infrastructure did**
# (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, identity/logon telemetry). Sophisticated
# attacks hide in the **boundary between those layers**: SAP says one thing, the host does another.
# 
# This notebook correlates SAP *business intent* with downstream *technical execution* to reconstruct
# attack chains that neither telemetry source makes obvious on its own. It is the companion to the
# execution-gap KQL hunts in `../hunts/` (EG01–EG05).
# 
# **What it builds, in order**
# 1. A SAP **host inventory** and a SAP-host ↔ Defender-device **map** (the hard join).
# 2. An **identity behavioural baseline** (per SAP user: usual systems, transactions, hours, sources).
# 3. A **host behavioural baseline** (per SAP host: usual SAP-parent child processes and destinations).
# 4. A sweep of the **five EG hunts**.
# 5. A **landscape graph**: User → System → Host → Process → Destination.
# 6. An **explainable `SequenceRisk`** per identity (every term attributable, no black box).
# 7. A **business-to-infrastructure divergence score** per host.
# 
# > **Honesty note.** The *direction* (SAP↔Defender correlation) is endorsed by Microsoft's SAP solution
# > docs and shown in incident write-ups; the *specific* execution-gap / landscape-traversal / divergence
# > hunts here were **not found** in the current OOB SAP solution, Content Hub, or adjacent community
# > content as of Oct 2026. That is "not found," not "proven novel" — do a fresh check before publishing.

# %% [markdown]
# ## 0. Prerequisites & assumptions (read first)
# 
# - **MDE on the SAP application servers.** The cross-domain hunts need Defender for Endpoint telemetry
#   from the SAP app servers themselves, flowing via the Microsoft Defender XDR connector.
# - **The host join is the hard part.** SAP `Host`/`Computer`/`Instance` must resolve to Defender
#   `DeviceName`. This notebook matches on the short hostname and lets you **override with an explicit map**
#   (`HOST_MAP` below or a `SAP - Host Map` watchlist). Get this wrong and every cross-domain result is wrong.
# - **No shared correlation key.** SAP SAL and MDE do not share a transaction ID, so correlation is
#   **temporal + same-host**. We state windows explicitly and treat results as leads.
# - **SAP → OS identity is not literal.** SAP work runs as `<sid>adm`/`SAPService<SID>`. EG03 / the
#   divergence score reason about *expected vs unexpected OS principals*, never a literal SAP-user→OS-user map.
# - `pip install msticpy[azsentinel] pandas matplotlib networkx`.

# %%
# Install if needed (safe to re-run; comment out once set up)
# %pip install --upgrade "msticpy[azsentinel]" pandas matplotlib networkx

import msticpy as mp
mp.init_notebook(globals())

# %% [markdown]
# ## 1. Connect to the workspace

# %%
from msticpy.data import QueryProvider

WORKSPACE = "Default"   # entry name in msticpyconfig.yaml, or 'Default'

qry_prov = QueryProvider("MSSentinel")
try:
    qry_prov.connect(workspace=WORKSPACE)
except Exception as exc:
    print(f"Named connect failed ({exc}); trying default connect...")
    qry_prov.connect()
print("Connected:", qry_prov.connected)

# %% [markdown]
# ## 2. Parameters
# 
# `BASELINE` learns "normal"; `DETECT` is the hunting window. `HOST_MAP` lets you pin SAP hostnames to
# Defender device names when short-name matching is not reliable.

# %%
from pathlib import Path
import pandas as pd, numpy as np

HUNTS_DIR   = Path("../hunts")
RESULTS_DIR = Path("../results"); RESULTS_DIR.mkdir(exist_ok=True)

BASELINE = "30d"
DETECT   = "3d"

# Optional explicit SAP-host -> Defender-device map (short, lower-case names).
# Leave empty to auto-match on short hostname. Example:
# HOST_MAP = {"prodapp01": "prodapp01.corp.contoso.com", ...}
HOST_MAP = {}

def short(name: str) -> str:
    return str(name).split(".")[0].strip().lower() if name else ""

pd.set_option("display.max_columns", 50); pd.set_option("display.width", 220)

# %% [markdown]
# ## 3. Load the EG hunt library (`../hunts/*.kql`)

# %%
import re

def parse_hunt(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    def grab(field):
        m = re.search(rf"//\s*{field}\s*:\s*(.+)", text)
        return m.group(1).strip() if m else ""
    body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//")).strip()
    return {"id": grab("Hunt ID") or path.stem, "title": grab("Title"),
            "theme": grab("Theme"), "file": path.name, "query": body}

hunts = [parse_hunt(p) for p in sorted(HUNTS_DIR.glob("*.kql"))]
catalog = pd.DataFrame([{k: h[k] for k in ("id","title","file")} for h in hunts])
print(f"Loaded {len(hunts)} hunts"); catalog

# %%
def run_kql(query: str, label: str = "") -> pd.DataFrame:
    try:
        df = qry_prov.exec_query(query)
        return df if df is not None else pd.DataFrame()
    except Exception as exc:
        print(f"[{label}] query error: {exc}")
        return pd.DataFrame({"_error": [str(exc)]})

# %% [markdown]
# ## 4. SAP host inventory + host ↔ device map
# 
# Pulls the SAP application-server hostnames from the audit log and the Defender device list, then builds
# the mapping. Review `host_map_df` carefully — unmatched SAP hosts mean blind spots in EG01/EG02/EG03/EG05.

# %%
sap_hosts = run_kql(f'''
    ABAPAuditLog
    | where TimeGenerated > ago({BASELINE})
    | extend SapHost = tolower(tostring(coalesce(column_ifexists("Host",""), column_ifexists("Computer",""),
                        tostring(split(column_ifexists("Instance",""), "*")[0]))))
    | where isnotempty(SapHost)
    | summarize events=count(), systems=make_set(tostring(column_ifexists("SystemId","")), 20) by SapHost
''', "sap_hosts")

mde_devices = run_kql(f'''
    DeviceInfo
    | where TimeGenerated > ago({BASELINE})
    | summarize by DeviceName, DeviceId
''', "mde_devices")

rows = []
mde_short = {short(d): d for d in mde_devices.get("DeviceName", pd.Series(dtype=str))}
for h in sap_hosts.get("SapHost", pd.Series(dtype=str)):
    if h in HOST_MAP:
        dev, how = HOST_MAP[h], "explicit"
    elif h in mde_short:
        dev, how = mde_short[h], "shortname"
    else:
        dev, how = None, "UNMATCHED"
    rows.append({"SapHost": h, "DeviceName": dev, "match": how})
host_map_df = pd.DataFrame(rows)
print(host_map_df["match"].value_counts().to_dict())
host_map_df

# %% [markdown]
# ## 5. Identity behavioural baseline (SAP side)
# 
# Per SAP user: the systems, transactions, active hours and source IPs that are *normal* for them over the
# baseline. These feed the `IdentityRarity` and `TransactionRarity` terms of the risk score.

# %%
id_base = run_kql(f'''
    SAPAuditLog
    | where TimeGenerated between (ago({BASELINE}) .. ago({DETECT}))
    | extend Src = tostring(column_ifexists("TerminalIPv6", column_ifexists("SalIpAddress","")))
    | summarize
        Systems  = make_set(SystemID, 50),
        Tcodes   = make_set(TransactionCode, 500),
        Sources  = make_set(Src, 100),
        Hours    = make_set(hourofday(TimeGenerated), 24),
        Events   = count()
      by User
''', "id_base")

# Lookups for O(1) rarity checks
def _as_set(x):
    return set(x) if isinstance(x, (list, np.ndarray)) else set()

id_profile = {}
for _, r in id_base.iterrows():
    id_profile[r["User"]] = {
        "systems": _as_set(r.get("Systems")), "tcodes": _as_set(r.get("Tcodes")),
        "sources": _as_set(r.get("Sources")), "hours": _as_set(r.get("Hours")),
        "events": r.get("Events", 0),
    }
print(f"Baselined {len(id_profile)} SAP identities")
id_base.head()

# %% [markdown]
# ## 6. Host behavioural baseline (infrastructure side)
# 
# Per SAP host: the child processes normally spawned under SAP parent processes, and the destinations the
# host normally reaches. These feed `ProcessRarity` and `DestinationRarity`.

# %%
mapped_hosts = [d for d in host_map_df["DeviceName"].dropna().tolist()]
mapped_short = [short(d) for d in mapped_hosts]
short_list_kql = "dynamic([" + ",".join(f'"{s}"' for s in mapped_short) + "])"

host_proc_base = run_kql(f'''
    DeviceProcessEvents
    | where TimeGenerated between (ago({BASELINE}) .. ago({DETECT}))
    | extend DevHost = tolower(tostring(split(DeviceName, ".")[0]))
    | where DevHost in ({short_list_kql})
    | where tolower(InitiatingProcessFileName) has_any ("disp+work","sapstartsrv","gwrd","icman","sapxpg","r3trans","tp")
    | summarize ChildProcs = make_set(tolower(FileName), 500) by DevHost
''', "host_proc_base") if mapped_short else pd.DataFrame()

host_dest_base = run_kql(f'''
    DeviceNetworkEvents
    | where TimeGenerated between (ago({BASELINE}) .. ago({DETECT}))
    | extend DevHost = tolower(tostring(split(DeviceName, ".")[0]))
    | where DevHost in ({short_list_kql})
    | summarize Dests = make_set(tolower(coalesce(RemoteUrl, RemoteIP)), 1000) by DevHost
''', "host_dest_base") if mapped_short else pd.DataFrame()

host_profile = {}
for _, r in host_proc_base.iterrows():
    host_profile.setdefault(r["DevHost"], {})["procs"] = _as_set(r.get("ChildProcs"))
for _, r in host_dest_base.iterrows():
    host_profile.setdefault(r["DevHost"], {})["dests"] = _as_set(r.get("Dests"))
print(f"Baselined {len(host_profile)} SAP hosts (process/destination)")

# %% [markdown]
# ## 7. Sweep the five EG hunts

# %%
results, summary = {}, []
for h in hunts:
    df = run_kql(h["query"], h["id"])
    results[h["id"]] = df
    is_err = (not df.empty) and ("_error" in df.columns)
    summary.append({"id": h["id"], "title": h["title"],
                    "rows": 0 if is_err else len(df),
                    "status": "error" if is_err else ("hits" if len(df) else "clean")})
summary = pd.DataFrame(summary); summary

# %% [markdown]
# ## 8. Explainable SequenceRisk (Python)
# 
# This is the heart of the notebook. For each identity active in the detect window we assemble stage events
# and score six **attributable** terms — no "the model says anomalous":
# 
# | Term | Meaning |
# |---|---|
# | `IdentityRarity` | logged on from a source / at an hour / on a system not in the user's baseline |
# | `TransactionRarity` | executed transactions the user never ran in baseline |
# | `PrivilegeDelta` | a privilege change document targeted the user in the window |
# | `ProcessRarity` | a first-seen SAP-parent child process ran on a host the user was active on |
# | `DestinationRarity` | a first-seen external destination left a host the user was active on |
# | `TemporalCompression` | how tightly the stages cluster in time (faster = higher) |
# 
# `SequenceRisk = (sum of term weights) * (1 + TemporalCompression)`, and we keep the per-term contributions
# so every score is explainable in triage.

# %%
# Pull the raw stage events for the detect window (SAP side), then fold in host-level signals.
sap_events = run_kql(f'''
    SAPAuditLog
    | where TimeGenerated > ago({DETECT})
    | extend Src = tostring(column_ifexists("TerminalIPv6", column_ifexists("SalIpAddress","")))
    | project TimeGenerated, User, SystemID, TransactionCode, MessageID, Src,
              Hour = hourofday(TimeGenerated)
''', "sap_events")

priv_changes = run_kql(f'''
    ABAPChangeDocsLog
    | where TimeGenerated > ago({DETECT})
    | where ObjectClass in ("IDENTITY","USER","PFCG") or TableName in ("AGR_USERS","UST04","USR04","AGR_1251")
    | extend TargetUser = tostring(column_ifexists("ObjectId",""))
    | where isnotempty(TargetUser)
    | summarize changes=count(), firstChange=min(TimeGenerated) by TargetUser
''', "priv_changes")
priv_set = set(priv_changes.get("TargetUser", pd.Series(dtype=str)))

# host-level anomalies from the EG hunt outputs (already temporally correlated there)
eg01 = results.get("EG01", pd.DataFrame())   # unexpected process (has DevHost, ProcTime, SapUser)
eg02 = results.get("EG02", pd.DataFrame())   # first-seen dest    (has DevHost, NetTime, SapUser)

W = dict(IdentityRarity=2.0, TransactionRarity=2.0, PrivilegeDelta=3.0, ProcessRarity=3.0, DestinationRarity=3.0)

def host_user_signal(df, time_col):
    # Map a hunt output to {user: earliest_time} using its SapUser attribution when present.
    out = {}
    if df is None or df.empty or "_error" in df.columns:
        return out
    ucol = "SapUser" if "SapUser" in df.columns else None
    if not ucol:
        return out
    for _, r in df.dropna(subset=[ucol]).iterrows():
        u = r[ucol]
        t = pd.to_datetime(r.get(time_col), errors="coerce")
        if pd.isna(t):
            continue
        out[u] = min(out.get(u, t), t)
    return out

proc_users = host_user_signal(eg01, "ProcTime")
dest_users = host_user_signal(eg02, "NetTime")

rows = []
if not sap_events.empty and "_error" not in sap_events.columns:
    for user, g in sap_events.groupby("User"):
        prof = id_profile.get(user, {})
        times, contrib = [], {}

        # IdentityRarity: new source / new hour / new system vs baseline
        new_src  = {s for s in g["Src"].dropna().unique() if s and s not in prof.get("sources", set())}
        new_hour = {int(h) for h in g["Hour"].dropna().unique() if int(h) not in prof.get("hours", set())}
        new_sys  = {s for s in g["SystemID"].dropna().unique() if s not in prof.get("systems", set())}
        if new_src or new_hour or new_sys:
            contrib["IdentityRarity"] = W["IdentityRarity"]
            times.append(pd.to_datetime(g["TimeGenerated"]).min())

        # TransactionRarity: tcodes never seen for this user
        new_tc = {t for t in g["TransactionCode"].dropna().unique() if t and t not in prof.get("tcodes", set())}
        if new_tc:
            contrib["TransactionRarity"] = W["TransactionRarity"]
            times.append(pd.to_datetime(g["TimeGenerated"]).min())

        # PrivilegeDelta
        if user in priv_set:
            contrib["PrivilegeDelta"] = W["PrivilegeDelta"]
            ft = pd.to_datetime(priv_changes.loc[priv_changes["TargetUser"] == user, "firstChange"]).min()
            times.append(ft)

        # ProcessRarity / DestinationRarity (host-level, attributed via hunt SapUser)
        if user in proc_users:
            contrib["ProcessRarity"] = W["ProcessRarity"]; times.append(proc_users[user])
        if user in dest_users:
            contrib["DestinationRarity"] = W["DestinationRarity"]; times.append(dest_users[user])

        if len(contrib) < 2:
            continue  # need at least two independent stages to be a "chain"

        times = [t for t in times if pd.notna(t)]
        span_h = (max(times) - min(times)).total_seconds() / 3600.0 if len(times) > 1 else 0.0
        temporal = round(1.0 / (1.0 + span_h), 3)
        base = sum(contrib.values())
        risk = round(base * (1 + temporal), 2)
        rows.append({
            "User": user, "SequenceRisk": risk, "Stages": len(contrib),
            "Terms": ", ".join(f"{k}={v}" for k, v in contrib.items()),
            "SpanHours": round(span_h, 1), "TemporalCompression": temporal,
            "NewSources": ";".join(sorted(new_src))[:120],
            "NewTcodes": ";".join(sorted(new_tc))[:160],
            "FirstStage": min(times) if times else pd.NaT, "LastStage": max(times) if times else pd.NaT,
        })

chains = pd.DataFrame(rows).sort_values("SequenceRisk", ascending=False) if rows else pd.DataFrame()
print(f"{len(chains)} identities formed a multi-stage chain")
chains.head(25)

# %%
import matplotlib.pyplot as plt
if not chains.empty:
    top = chains.head(15)
    ax = top.set_index("User")["SequenceRisk"].plot(kind="barh", figsize=(8, 0.45*len(top)+1))
    ax.invert_yaxis(); ax.set_xlabel("SequenceRisk"); ax.set_title("Top execution-gap chains")
    plt.tight_layout(); plt.show()
else:
    print("No chains this run.")

# %% [markdown]
# ## 9. Landscape graph — User → System → Host → Process → Destination
# 
# A directed graph of the highest-risk chains, so an analyst can *see* how a business identity connects to
# infrastructure execution. Edges are drawn from the hunt outputs and context queries.

# %%
try:
    import networkx as nx
except ImportError:
    nx = None
    print("networkx not installed — run: %pip install networkx")

if nx and not chains.empty:
    G = nx.DiGraph()
    focus = set(chains.head(10)["User"])

    # User -> System (from sap_events)
    for _, r in sap_events[sap_events["User"].isin(focus)].iterrows():
        G.add_edge(f"U:{r['User']}", f"S:{r['SystemID']}")

    # System/Host -> Process (EG01) and Host -> Destination (EG02), attributed to focus users
    def _focus_rows(df):
        if df is None or df.empty or "SapUser" not in df.columns:
            return
        for _, r in df[df["SapUser"].isin(focus)].iterrows():
            yield r
    for r in _focus_rows(eg01):
        G.add_edge(f"U:{r['SapUser']}", f"H:{r['DevHost']}")
        G.add_edge(f"H:{r['DevHost']}", f"P:{r.get('Child','?')}")
    for r in _focus_rows(eg02):
        G.add_edge(f"U:{r['SapUser']}", f"H:{r['DevHost']}")
        dest = r.get("RemoteUrl") or r.get("RemoteIP") or "?"
        G.add_edge(f"H:{r['DevHost']}", f"D:{dest}")

    if G.number_of_nodes():
        color = {"U": "#4C78A8", "S": "#59A14F", "H": "#E15759", "P": "#F28E2B", "D": "#B07AA1"}
        colors = [color.get(n.split(":")[0], "#999") for n in G.nodes]
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G, k=0.6, seed=7)
        nx.draw(G, pos, node_color=colors, with_labels=True, node_size=900, font_size=7, arrows=True)
        plt.title("SAP execution-gap landscape (top chains)"); plt.tight_layout(); plt.show()
    else:
        print("No graph edges — check that EG01/EG02 returned SapUser-attributed rows.")
else:
    print("Graph skipped (no networkx or no chains).")

# %% [markdown]
# ## 10. Business-to-infrastructure divergence score (per host)
# 
# For each SAP host: what fraction of its powerful execution / outbound activity in the window is **not**
# explained by the expected SAP baseline — first-seen child processes, first-seen destinations, and
# activity under OS principals outside the sanctioned set. A high divergence host is where SAP intent and
# infrastructure behaviour have drifted apart.

# %%
div_rows = []
for devhost in mapped_short:
    prof = host_profile.get(devhost, {})
    base_procs = prof.get("procs", set())
    base_dests = prof.get("dests", set())

    cur = run_kql(f'''
        let dh = "{devhost}";
        let proc = DeviceProcessEvents | where TimeGenerated > ago({DETECT})
            | extend DevHost = tolower(tostring(split(DeviceName,".")[0])) | where DevHost == dh
            | where tolower(InitiatingProcessFileName) has_any ("disp+work","sapstartsrv","gwrd","icman","sapxpg")
            | summarize total=count(), procs=make_set(tolower(FileName),200), accts=make_set(tolower(AccountName),50);
        let net = DeviceNetworkEvents | where TimeGenerated > ago({DETECT})
            | extend DevHost = tolower(tostring(split(DeviceName,".")[0])) | where DevHost == dh
            | where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
            | summarize nettotal=count(), dests=make_set(tolower(coalesce(RemoteUrl,RemoteIP)),500);
        proc | extend k=1 | join kind=fullouter (net | extend k=1) on k
    ''', f"div_{devhost}")
    if cur.empty or "_error" in cur.columns:
        continue
    row = cur.iloc[0]
    procs = _as_set(row.get("procs")); dests = _as_set(row.get("dests")); accts = _as_set(row.get("accts"))
    new_procs = procs - base_procs
    new_dests = dests - base_dests
    import re as _re
    ok = _re.compile(r"(adm$|^sapservice|^sapadm|^daaadm|^sdb|^sqd|nt authority|^system$|^root$|^local service|^network service)")
    odd_accts = {a for a in accts if a and not ok.search(a)}
    denom = max(len(procs) + len(dests), 1)
    divergence = round((len(new_procs) + len(new_dests) + 2*len(odd_accts)) / denom, 3)
    div_rows.append({"Host": devhost, "Divergence": divergence,
                     "NewProcs": len(new_procs), "NewDests": len(new_dests),
                     "OddOSAccounts": ";".join(sorted(odd_accts))[:120]})

divergence_df = pd.DataFrame(div_rows).sort_values("Divergence", ascending=False) if div_rows else pd.DataFrame()
divergence_df

# %% [markdown]
# ## 11. Triage helpers

# %%
def show(hunt_id, n=50):
    df = results.get(hunt_id)
    if df is None: print("Run the sweep first."); return pd.DataFrame()
    print(f"{hunt_id}: {len(df)} rows"); return df.head(n)

def chain_detail(user, lookback=None):
    lb = lookback or DETECT
    return run_kql(f'''
        SAPAuditLog | where TimeGenerated > ago({lb}) | where User == "{user}"
        | project TimeGenerated, SystemID, MessageID, TransactionCode,
                  Src = column_ifexists("TerminalIPv6", column_ifexists("SalIpAddress","")),
                  MessageText = column_ifexists("MessageText","")
        | sort by TimeGenerated asc
    ''', "chain_detail")

# show("EG04");  chain_detail("SUSPECT_USER")

# %% [markdown]
# ## 12. Export results

# %%
from datetime import datetime
stamp = datetime.utcnow().strftime("%Y%m%d")
saved = []
for hid, df in results.items():
    if df.empty or "_error" in df.columns: continue
    p = RESULTS_DIR / f"{hid}_{stamp}.csv"; df.to_csv(p, index=False); saved.append(str(p))
if not chains.empty:
    p = RESULTS_DIR / f"SequenceRisk_{stamp}.csv"; chains.to_csv(p, index=False); saved.append(str(p))
if 'divergence_df' in dir() and not divergence_df.empty:
    p = RESULTS_DIR / f"HostDivergence_{stamp}.csv"; divergence_df.to_csv(p, index=False); saved.append(str(p))
print("Saved:\n" + "\n".join(saved) if saved else "Nothing to save.")

# %% [markdown]
# ## 13. From hunt to detection, and an honesty checklist
# 
# **Promote** a hunt that proves itself: copy the `.kql` body into Sentinel → Analytics (or a Defender custom
# detection), map entities (`User`→Account, `DevHost`/`RemoteIP`→Host/IP, `SystemID`→custom), keep the
# behavioural windows, and reference the EG id in the rule description.
# 
# **Before you call any of this "novel" in a blog:**
# - Re-check the Content Hub SAP solution and the `Azure/Azure-Sentinel` repo (hunting queries + solutions).
# - Search Tech Community, the SAP community blogs, and MSTIC research for SAP↔Defender correlation.
# - State findings as *"not found in X as of <date>"* rather than an absolute claim.
# - Credit adjacent prior art you build on (e.g. the `DeviceProcessEvents-ProcessTree` make-graph function,
#   and Microsoft's own guidance to correlate SAP with Defender/Entra via ASIM).
