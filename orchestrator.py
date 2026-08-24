"""Core orchestration loop: trigger CALDERA ops → wait → revert VM."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config_loader import LoadedConfig
from caldera_client import CalderaClient, CalderaError
from vmware_client import VMwareClient, VMwareError
from reporter import Reporter, AdversaryResult

log = logging.getLogger(__name__)

# CALDERA operation states that mean "no more links will run"
_TERMINAL_STATES = {"finished", "paused", "out_of_time", "cleanup"}

# File that persists the previous cycle's operation IDs across restarts
_PREV_CYCLE_FILE = Path(__file__).parent / "data" / "prev_cycle_ops.json"


def _load_prev_cycle_ops() -> list[str]:
    try:
        return json.loads(_PREV_CYCLE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_prev_cycle_ops(op_ids: list[str]) -> None:
    _PREV_CYCLE_FILE.parent.mkdir(exist_ok=True)
    _PREV_CYCLE_FILE.write_text(json.dumps(op_ids))


class Orchestrator:
    def __init__(self, cfg: LoadedConfig) -> None:
        self.cfg = cfg
        self.caldera = CalderaClient(cfg.settings)
        self.reporter = Reporter(cfg)
        self._scheduler = AsyncIOScheduler()
        self.vmware = (
            VMwareClient(cfg.settings.vmware) if cfg.settings.vmware else None
        )
        self._prev_cycle_op_ids: list[str] = _load_prev_cycle_ops()

    # ── Public entry points ───────────────────────────────────────────────────

    async def run_once(self, adversary_filter: Optional[str] = None) -> None:
        """Run all active adversaries (or a single named one) and emit a report."""
        profiles = self.cfg.active_adversary_profiles()
        if adversary_filter:
            profiles = [p for p in profiles if p.name == adversary_filter]
            if not profiles:
                available = [p.name for p in self.cfg.active_adversary_profiles()]
                raise ValueError(
                    f"Adversary '{adversary_filter}' not found. Available: {available}"
                )

        await self._delete_prev_cycle_ops()

        op_window_start = datetime.now(timezone.utc)
        adversary_results: list[AdversaryResult] = []
        current_cycle_op_ids: list[str] = []

        for profile in profiles:
            log.info("▶ Starting adversary: %s", profile.display_name)
            try:
                result = await self._run_adversary(profile, op_window_start)
                adversary_results.append(result)
                current_cycle_op_ids.append(result.operation_id)
            except (CalderaError, VMwareError, ValueError) as exc:
                log.error("Adversary '%s' failed — skipping: %s", profile.name, exc)

        self._prev_cycle_op_ids = current_cycle_op_ids
        _save_prev_cycle_ops(current_cycle_op_ids)
        log.info("Saved %d operation IDs for next-cycle cleanup", len(current_cycle_op_ids))

        report = self.reporter.build_report(adversary_results)
        await self.reporter.send(report)

    async def start(self) -> None:
        """Start the persistent scheduled loop (blocks until SIGINT)."""
        sched = self.cfg.settings.schedule
        log.info("Starting orchestrator in '%s' mode", sched.mode)

        if sched.mode == "interval":
            self._scheduler.add_job(
                self.run_once,
                "interval",
                hours=sched.interval_hours,
                next_run_time=datetime.now(timezone.utc),
            )
        elif sched.mode == "cron":
            parts = sched.cron_expression.split()
            if len(parts) != 5:
                raise ValueError(f"Invalid cron_expression: '{sched.cron_expression}'")
            self._scheduler.add_job(
                self.run_once,
                "cron",
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4],
            )
        elif sched.mode == "manual":
            log.info("Manual mode — use --run-now or --adversary to trigger operations")
            await asyncio.Event().wait()
            return

        self._scheduler.start()
        try:
            await asyncio.Event().wait()
        finally:
            self._scheduler.shutdown(wait=False)

    # ── Previous-cycle cleanup ────────────────────────────────────────────────

    async def _delete_prev_cycle_ops(self) -> None:
        if not self._prev_cycle_op_ids:
            return
        log.info("Cleaning up %d operation(s) from previous cycle ...",
                 len(self._prev_cycle_op_ids))
        for op_id in self._prev_cycle_op_ids:
            try:
                await self.caldera.delete_operation(op_id)
            except CalderaError as exc:
                log.warning("Could not delete operation %s: %s", op_id[:8], exc)
        self._prev_cycle_op_ids = []
        _save_prev_cycle_ops([])
        log.info("Previous cycle cleanup complete")

    # ── Per-adversary execution ───────────────────────────────────────────────

    async def _run_adversary(
        self, profile, op_window_start: datetime
    ) -> AdversaryResult:
        if not profile.caldera_adversary_id:
            raise ValueError(
                f"Adversary '{profile.name}' has no caldera_adversary_id. "
                f"Create the adversary in CALDERA and set the ID in the adversary YAML."
            )
        log.info("Using adversary id: %s", profile.caldera_adversary_id)

        await self.caldera.ensure_agents_trusted(self.cfg.settings.agents)

        op_name = f"{profile.display_name} {op_window_start:%Y-%m-%d %H:%M UTC}"
        op_id = await self.caldera.start_operation(
            op_name, profile.caldera_adversary_id, group="red"
        )

        result = AdversaryResult(
            adversary_name=profile.name,
            operation_id=op_id,
            started_at=datetime.now(timezone.utc),
        )

        await self._wait_for_operation(op_id)
        result.completed_at = datetime.now(timezone.utc)

        await self._revert_and_wait()

        return result

    # ── VM snapshot revert ────────────────────────────────────────────────────

    async def _revert_and_wait(self) -> None:
        """Revert WIN10 to clean snapshot, then wait for Sandcat to beacon back."""
        if self.vmware is None:
            return

        try:
            await self.vmware.revert_snapshot()
        except VMwareError as exc:
            log.error("Snapshot revert failed: %s — continuing without revert", exc)
            return

        timeout = self.cfg.settings.vmware.agent_ready_timeout_minutes
        for agent in self.cfg.settings.agents:
            ready = await self.caldera.wait_for_agent_ready(
                agent.hostname, timeout_minutes=timeout
            )
            if not ready:
                log.warning(
                    "Agent '%s' did not come back within %d minutes after revert",
                    agent.hostname, timeout,
                )

    # ── Operation polling ─────────────────────────────────────────────────────

    async def _wait_for_operation(self, op_id: str) -> None:
        timeout_min = self.cfg.settings.schedule.operation_timeout_minutes
        deadline = time.monotonic() + timeout_min * 60

        while time.monotonic() < deadline:
            try:
                op = await self.caldera.get_operation(op_id)
            except CalderaError as exc:
                log.warning("Error polling operation %s: %s — retrying", op_id[:8], exc)
                await asyncio.sleep(15)
                continue

            state: str = op.get("state", "unknown")
            log.info("Operation %s  state=%s", op_id[:8], state)

            if state in _TERMINAL_STATES:
                log.info("Operation %s reached state '%s'", op_id[:8], state)
                return

            await asyncio.sleep(15)

        log.warning(
            "Operation %s did not finish within %d min — moving to next adversary",
            op_id[:8], timeout_min,
        )
