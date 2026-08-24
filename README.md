# CALDERA + Splunk ES Automation Orchestrator

🇧🇷 [Versão em Português](README.pt-BR.md)

Runs 47 adversary emulation operations against a Windows lab VM on a recurring schedule. Each operation maps to one validated (ESCU detection, CALDERA ability) pair. Between every operation the VM is reverted to a known snapshot so each technique runs against a consistent machine state.

> **VMware vCenter is required.** The snapshot revert mechanism — which resets the target VM to a clean state between operations — is built on top of `govc` and requires vCenter API access. Without a vCenter environment this orchestrator cannot function.

---

## What it does

```
On startup:
  Delete previous cycle's 47 operations from CALDERA (keeps CALDERA clean)

Every 2 hours:
  For each of the 47 adversaries (in kill-chain order):
    1. Pre-flight: if the agent is untrusted, trust it via API
    2. Start a CALDERA operation for this adversary
    3. Poll until CALDERA marks the operation finished (up to 30 min)
    4. Revert the Win10 VM to the configured snapshot via vCenter
    5. Wait for the Sandcat agent to beacon back
       → If it comes back untrusted (CALDERA's timer fired during revert),
         automatically trust it via API — no manual action needed
  Save the 47 operation IDs to disk for cleanup next cycle
  Emit an operations report to the log
```

The orchestrator does **not** query Splunk or validate detections — its job is to reliably execute attack techniques on the endpoint so that Splunk ES has real telemetry to fire against.

---

## Kill-chain execution order

Adversaries run in a realistic attack sequence so the telemetry in Splunk reflects a coherent intrusion, not random noise.

| Phase | Adversaries | Count |
|---|---|:---:|
| Discovery | escu_045, escu_046, escu_047 | 3 |
| Command & Control | escu_009 (BITSAdmin first), then escu_001–008 | 9 |
| Execution | escu_010–015 | 6 |
| Privilege Escalation | escu_016 | 1 |
| Defense Evasion | escu_017–033 | 17 |
| Credential Access | escu_034–042 | 9 |
| Impact | escu_043, escu_044 | 2 |

---

## Prerequisites

| Component | Details |
|---|---|
| CALDERA | Running locally on port 8888, red API key exported as `CALDERA_API_KEY` |
| Sandcat agent | Pre-deployed on the target Windows VM, beaconing to CALDERA |
| VMware vCenter | Required — the orchestrator uses `govc` to revert the VM snapshot after each operation |
| VM snapshot | Taken while the VM was **powered on** with Sandcat running, so revert resumes from memory (no Windows boot) |
| `govc` binary | At `./govc` or `/usr/local/bin/govc` — VMware CLI for snapshot operations |
| vCenter credentials | Exported as `GOVC_USERNAME` and `GOVC_PASSWORD` |

---

## Installation

```bash
git clone https://github.com/renatomag/caldera-splunk-orchestrator.git
cd caldera-splunk-orchestrator
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Create your local config from the example and fill in your environment values
cp config/settings.yaml.example config/settings.yaml
```

Edit `config/settings.yaml` and replace every `<placeholder>` with the values for your environment before running.

> **Note for systemd users:** the unit file's `WorkingDirectory` must match wherever you cloned the repo. Update it to your actual path before enabling the service.

---

## Credentials

Credentials are never stored in YAML files. They are loaded from the systemd environment file at `/etc/caldera-orchestrator/credentials`:

```
CALDERA_API_KEY=<your-caldera-red-api-key>
GOVC_USERNAME=<vcenter-username>
GOVC_PASSWORD=<vcenter-password>
```

To use ad-hoc commands outside systemd, source the file first:

```bash
set -a && source /etc/caldera-orchestrator/credentials && set +a
```

---

## Configuration

### `config/settings.yaml` — main settings

Fill in the fields marked with angle brackets (`<...>`) for your environment. Fields using `${VAR}` syntax are loaded from the credentials file and should not be edited.

```yaml
caldera:
  host: localhost
  port: 8888
  api_key: "${CALDERA_API_KEY}"

vmware:
  host: <vcenter-hostname>            # vCenter hostname or IP address
  username: "${GOVC_USERNAME}"
  password: "${GOVC_PASSWORD}"
  vm_name: <vm-name>                  # exact VM display name as shown in vCenter
  snapshot_name: "<snapshot-name>"    # snapshot to revert to after each operation
  datacenter: <datacenter-name>       # vCenter datacenter name (leave blank if using default)
  verify_ssl: false
  agent_ready_timeout_minutes: 10     # how long to wait for Sandcat to beacon after revert

agents:
  - name: <agent-name>
    fqdn: <agent-name>.<domain>
    role: workstation

schedule:
  mode: interval                      # "interval" | "cron" | "manual"
  interval_hours: 2
  cron_expression: "0 * * * *"        # only used when mode=cron
  operation_timeout_minutes: 30       # give up on a stuck CALDERA operation after this

reporting:
  mode: log_only                      # "webhook" | "email" | "both" | "log_only"

active_adversaries:
  - escu_045   # Discovery — nltest DC
  - escu_046   # Discovery — nltest remote
  # ... all 47 in kill-chain order (see file for full list)
```

### `config/adversaries/escu_NNN.yaml` — one file per adversary

Each file defines one (ESCU detection, CALDERA ability) pair. There are 47 of these.

```yaml
name: escu_045
display_name: "SPLUNK ES / Domain Controller Discovery with Nltest / Discover domain controller"
description: "T1018 | discovery | Domain Controller Discovery with Nltest"
caldera_adversary_id: "<adversary-uuid>"   # must exist in CALDERA
targets:
  - role: workstation
techniques:
  - id: T1018
    name: "Discover domain controller (nltest)"
    caldera_ability_id: "<ability-uuid>"
    target_role: workstation
```

`caldera_adversary_id` is required. It must already exist in CALDERA — the orchestrator does not create adversaries.

### `detection_ability_map.json` — source of truth

Maps every ESCU detection to the CALDERA ability that exercises it. Used to generate the 47 adversary profiles and as the reference for understanding which technique maps to which detection. The orchestrator itself does not read this file at runtime.

---

## Running

### Check that everything is connected (no operations triggered)

```bash
venv/bin/python main.py --dry-run
```

Validates `settings.yaml`, checks CALDERA connectivity and agent liveness, and checks vCenter connectivity. No operations are started.

### Run all 47 adversaries once right now

```bash
venv/bin/python main.py --run-now
```

### Run a single adversary by name

```bash
venv/bin/python main.py --adversary escu_045
```

### Start the persistent scheduler (runs forever, fires every 2 hours)

```bash
venv/bin/python main.py
```

### All CLI options

```
--config-dir DIR    Path to config directory (default: ./config)
--dry-run           Validate config and test connectivity only — no operations
--run-now           Run all active adversaries once immediately
--adversary NAME    Run one named adversary (implies --run-now)
--log-level LEVEL   DEBUG | INFO | WARNING | ERROR  (default: INFO)
```

---

## Running as a systemd service

The service is already installed. Standard commands:

```bash
# Start / stop / restart
sudo systemctl start caldera-orchestrator
sudo systemctl stop caldera-orchestrator
sudo systemctl restart caldera-orchestrator

# Check status
systemctl status caldera-orchestrator

# Follow live logs
sudo journalctl -u caldera-orchestrator -f
```

---

## Monitoring a running cycle

Source credentials before running these ad-hoc checks (skip if already in your shell):

```bash
set -a && source /etc/caldera-orchestrator/credentials && set +a
```

**Are operations actually executing abilities?** (the most important check)

```bash
curl -s http://localhost:8888/api/v2/operations \
  -H "KEY: $CALDERA_API_KEY" | python3 -c "
import json, sys
ops = sorted(json.load(sys.stdin), key=lambda o: o.get('start',''), reverse=True)
for o in ops[:10]:
    ran = sum(1 for l in o.get('chain',[]) if l.get('finish') and l.get('status') != -3)
    print(f'ran={ran}  state={o[\"state\"]:<12}  {o[\"name\"][:55]}')
"
```

Healthy output shows `ran=1` for each completed operation. `ran=0` means the ability was skipped — almost always because the agent is untrusted.

**Is the agent trusted?**

```bash
curl -s http://localhost:8888/api/v2/agents \
  -H "KEY: $CALDERA_API_KEY" | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    print(f'host={a[\"host\"]}  trusted={a[\"trusted\"]}  last_seen={a[\"last_seen\"]}')
"
```

If `trusted=False` while the service is running, the orchestrator will auto-trust it before the next operation. You can also trust it manually:

```bash
PAW=$(curl -s http://localhost:8888/api/v2/agents -H "KEY: $CALDERA_API_KEY" | \
  python3 -c "import json,sys; print([a['paw'] for a in json.load(sys.stdin) if a['host']=='<agent-name>'][0])")

curl -s -X PATCH http://localhost:8888/api/v2/agents/$PAW \
  -H "KEY: $CALDERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"trusted": true}'
```

---

## Why the agent sometimes comes back untrusted

CALDERA has an `untrusted_timer` (set to 120 seconds). If an agent is silent for more than `untrusted_timer + sleep_max` seconds (120 + 20 = 140 s), CALDERA marks it untrusted. Once untrusted, CALDERA never re-trusts automatically.

The VM revert takes long enough to exceed this threshold. The orchestrator handles this by calling `PATCH /api/v2/agents/{paw}` with `{"trusted": true}` automatically whenever it sees the agent beaconing as untrusted — both in `wait_for_agent_ready` after each revert and in `ensure_agents_trusted` before each operation starts.

---

## CALDERA operation cleanup

CALDERA stores every operation permanently. With 47 operations per cycle every 2 hours, this accumulates fast (7500+ operations were found when cleanup was first implemented).

The orchestrator solves this by tracking the previous cycle's 47 operation IDs in `data/prev_cycle_ops.json`. At the start of each new cycle, those IDs are deleted from CALDERA before any new operations are created. CALDERA therefore holds at most ~47 operations at steady state.

If the service is restarted, the IDs are reloaded from the JSON file so the cleanup still runs on the next cycle.

---

## Adding a new adversary

1. Create the adversary in CALDERA (add the ability to it) and copy its UUID
2. Create `config/adversaries/escu_NNN.yaml` with `caldera_adversary_id` set to that UUID
3. Add `escu_NNN` to `active_adversaries` in `config/settings.yaml` in the correct kill-chain position
4. Restart the service: `sudo systemctl restart caldera-orchestrator`
5. Verify with `--dry-run` that the new adversary loads without errors

---

## Project layout

```
caldera-splunk-orchestrator/
├── main.py                     # CLI entry point and --dry-run connectivity check
├── orchestrator.py             # Scheduling loop, per-adversary execution, VM revert
├── caldera_client.py           # CALDERA REST API client (operations, agents, trust)
├── vmware_client.py            # govc wrapper — snapshot.revert via vCenter
├── reporter.py                 # Log / webhook report builder
├── config_loader.py            # YAML loader with env-var expansion and validation
├── models.py                   # Pydantic config models
├── splunk_client.py            # Splunk REST API client (detection validation, future use)
├── discover_mappings.py        # One-off setup script: fetch CALDERA abilities + ESCU searches
├── config/
│   ├── settings.yaml           # Main configuration (edit this)
│   └── adversaries/
│       ├── escu_001.yaml       # One file per adversary (47 total)
│       └── ...
├── data/
│   └── prev_cycle_ops.json     # Persisted operation IDs for next-cycle cleanup
├── detection_ability_map.json  # Source mapping: ESCU detection ↔ CALDERA ability
└── govc                        # govc binary (VMware CLI)
```
