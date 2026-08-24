"""
Discovery script: fetch CALDERA abilities + Splunk ESCU searches, print raw data for analysis.
Usage: python discover_mappings.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import httpx

# ── Load settings inline (avoid importing full orchestrator stack) ─────────────

CALDERA_BASE = "http://localhost:8888"
CALDERA_KEY  = os.environ["CALDERA_API_KEY"]

SPLUNK_BASE  = "https://172.16.171.130:8089"
SPLUNK_TOKEN = os.environ["SPLUNK_TOKEN"]

TACTICS = {"impact", "defense-evasion", "credential-access", "execution"}

# ── CALDERA ───────────────────────────────────────────────────────────────────

async def fetch_caldera_abilities() -> list[dict]:
    headers = {"KEY": CALDERA_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient(headers=headers, timeout=30) as c:
        r = await c.get(f"{CALDERA_BASE}/api/v2/abilities")
        r.raise_for_status()
        abilities = r.json()

    windows = []
    for ab in abilities:
        # keep Windows-capable abilities in target tactics
        executors = ab.get("executors", [])
        platforms = {e.get("platform", "") for e in executors}
        if "windows" not in platforms:
            continue
        tactic = ab.get("tactic", "").lower().replace(" ", "-")
        if tactic not in TACTICS:
            continue
        windows.append({
            "id":          ab.get("ability_id", ""),
            "name":        ab.get("name", ""),
            "tactic":      tactic,
            "technique_id": ab.get("technique_id", ""),
            "technique_name": ab.get("technique_name", ""),
            "executors":   [
                {
                    "platform":  e.get("platform"),
                    "executor":  e.get("name"),        # psh / cmd / sh
                    "command":   (e.get("command") or "")[:300],
                }
                for e in executors if e.get("platform") == "windows"
            ],
        })
    return windows


# ── Splunk ─────────────────────────────────────────────────────────────────────

async def fetch_escu_searches() -> list[dict]:
    headers   = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    timeout   = httpx.Timeout(60.0, connect=10.0)
    all_items = []
    offset    = 0
    batch     = 200

    async with httpx.AsyncClient(headers=headers, verify=False, timeout=timeout) as c:
        while True:
            r = await c.get(
                f"{SPLUNK_BASE}/services/saved/searches",
                params={
                    "output_mode": "json",
                    "count":       batch,
                    "offset":      offset,
                    "search":      "ESCU",   # name filter
                },
            )
            r.raise_for_status()
            data    = r.json()
            entries = data.get("entry", [])
            if not entries:
                break
            all_items.extend(entries)
            offset += len(entries)
            if len(entries) < batch:
                break

    searches = []
    for e in all_items:
        name    = e.get("name", "")
        content = e.get("content", {})
        spl     = content.get("search", "")
        tags    = content.get("tags", "")
        disabled = content.get("disabled", True)

        # Filter: only correlation searches (they dispatch and create notables)
        # Correlation searches contain action.notable in their content
        has_notable = bool(content.get("action.notable", ""))

        # Tactic filter via search content keywords
        tactic_keywords = {
            "impact":            ["shadow", "vss", "bcdedit", "wbadmin", "encrypt", "ransom", "inhibit", "T1490", "T1486", "T1491"],
            "defense-evasion":   ["disable", "tamper", "lolbin", "bypass", "inject", "hollow", "masquerad", "T1027", "T1055", "T1562", "T1218"],
            "credential-access": ["lsass", "mimikatz", "credential", "sam ", "ntds", "kerberos", "ticket", "T1003", "T1558", "T1110"],
            "execution":         ["powershell", "wscript", "mshta", "regsvr", "rundll", "cscript", "T1059", "T1204", "T1569"],
        }
        matched_tactic = None
        spl_lower = spl.lower()
        name_lower = name.lower()
        for tac, kws in tactic_keywords.items():
            if any(kw.lower() in spl_lower or kw.lower() in name_lower for kw in kws):
                matched_tactic = tac
                break

        if not matched_tactic:
            continue

        searches.append({
            "name":     name,
            "tactic":   matched_tactic,
            "disabled": disabled,
            "notable":  has_notable,
            "spl":      spl[:600],
        })

    return searches


# ── Main ───────────────────────────────────────────────────────────────────────

async def main() -> None:
    print("Querying CALDERA and Splunk in parallel...\n", flush=True)

    abilities, searches = await asyncio.gather(
        fetch_caldera_abilities(),
        fetch_escu_searches(),
    )

    print(f"=== CALDERA Windows Abilities ({len(abilities)} total in target tactics) ===\n")
    for ab in sorted(abilities, key=lambda x: (x["tactic"], x["technique_id"])):
        print(f"[{ab['tactic'].upper():<20}] {ab['technique_id']:<12} {ab['name']}")
        print(f"    id: {ab['id']}")
        for ex in ab["executors"]:
            print(f"    executor={ex['executor']:<5}  cmd: {ex['command'][:120]}")
        print()

    print(f"\n=== ESCU Correlation Searches ({len(searches)} matched) ===\n")
    for s in sorted(searches, key=lambda x: (x["tactic"], x["name"])):
        status = "DISABLED" if s["disabled"] else "enabled "
        notable = "notable=YES" if s["notable"] else "notable=no "
        print(f"[{s['tactic'].upper():<20}] [{status}] [{notable}] {s['name']}")
        print(f"    SPL: {s['spl'][:200]}")
        print()

    # Also dump to JSON for later analysis
    out = {"abilities": abilities, "escu_searches": searches}
    with open("/tmp/discovery_output.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nFull data written to /tmp/discovery_output.json")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    asyncio.run(main())
