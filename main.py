"""Entry point — argument parsing and --dry-run connectivity validation."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from config_loader import load_config, ConfigError
from caldera_client import CalderaClient, CalderaError
from vmware_client import VMwareClient, VMwareError

log = logging.getLogger(__name__)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orchestrator",
        description="CALDERA Adversary Emulation Orchestrator",
    )
    p.add_argument(
        "--config-dir",
        type=Path,
        default=Path("config"),
        metavar="DIR",
        help="Path to the config directory (default: ./config)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and test connectivity without triggering any operations",
    )
    p.add_argument(
        "--run-now",
        action="store_true",
        help="Trigger all active adversaries immediately, ignoring the schedule",
    )
    p.add_argument(
        "--adversary",
        metavar="NAME",
        help="Run a single named adversary (implies --run-now)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return p


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, level),
    )


# ── Dry-run ───────────────────────────────────────────────────────────────────

async def _dry_run(config_dir: Path) -> int:
    ok = True
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           CALDERA Orchestrator — Dry Run Check              ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    # ── 1. Load & validate YAML ───────────────────────────────────────────────
    print(f"\n[1/3] Loading configuration from {config_dir} ...")
    try:
        cfg = load_config(config_dir)
        print(f"      ✓ settings.yaml       valid")
        print(f"      ✓ adversary profiles  {len(cfg.adversaries)} loaded")
        active = cfg.active_adversary_profiles()
        print(f"      ✓ active adversaries  {len(active)} configured")
    except ConfigError as exc:
        print(f"      ✗ CONFIG ERROR: {exc}", file=sys.stderr)
        return 1

    # ── 2. CALDERA connectivity ───────────────────────────────────────────────
    caldera_url = cfg.settings.caldera.base_url
    print(f"\n[2/3] Testing CALDERA connectivity ({caldera_url}) ...")
    caldera = CalderaClient(cfg.settings)
    try:
        health = await caldera.check_connectivity()
        ver = health.get("version", "?")
        print(f"      ✓ CALDERA reachable   v{ver}")
        agents = await caldera.validate_agents()
        for name, agent in agents.items():
            icon = "✓" if agent.alive else "⚠"
            status = "alive" if agent.alive else "DEAD (not trusted)"
            print(f"      {icon} {name:<28} paw={agent.paw}  group={agent.group}  [{status}]")
        if any(not a.alive for a in agents.values()):
            print("      ⚠ One or more agents are not trusted — operations may fail")
            ok = False
        for t in cfg.settings.targets:
            print(f"      ℹ {t.name:<28} [lateral movement target — deployed dynamically]")
    except CalderaError as exc:
        print(f"      ✗ CALDERA ERROR: {exc}", file=sys.stderr)
        ok = False

    # ── 3. VMware connectivity ────────────────────────────────────────────────
    if cfg.settings.vmware:
        vc = cfg.settings.vmware
        print(f"\n[3/3] Testing VMware connectivity ({vc.host}) ...")
        vmware = VMwareClient(vc)
        try:
            info = await vmware.check_connectivity()
            first_line = info.splitlines()[0] if info else "(no output)"
            print(f"      ✓ vCenter reachable   {first_line}")
            print(f"      ✓ VM name             {vc.vm_name}")
            print(f"      ✓ Snapshot            {vc.snapshot_name}")
        except VMwareError as exc:
            print(f"      ✗ VMWARE ERROR: {exc}", file=sys.stderr)
            ok = False
    else:
        print(f"\n[3/3] VMware — not configured (snapshot revert disabled)")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    if ok:
        print("══════════════════════════════════════════════════════════════")
        print("  ✓  All checks passed — orchestrator is ready to run.")
        print("══════════════════════════════════════════════════════════════")
    else:
        print("══════════════════════════════════════════════════════════════", file=sys.stderr)
        print("  ✗  One or more checks failed — review errors above.", file=sys.stderr)
        print("══════════════════════════════════════════════════════════════", file=sys.stderr)

    print()
    return 0 if ok else 1


# ── Async main ────────────────────────────────────────────────────────────────

async def _async_main(args: argparse.Namespace) -> int:
    if args.dry_run:
        return await _dry_run(args.config_dir)

    from orchestrator import Orchestrator

    cfg = load_config(args.config_dir)
    orch = Orchestrator(cfg)

    if args.adversary or args.run_now:
        await orch.run_once(adversary_filter=args.adversary)
    else:
        await orch.start()

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.log_level)

    try:
        sys.exit(asyncio.run(_async_main(args)))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
