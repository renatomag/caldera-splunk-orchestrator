"""Operation report builder and dispatcher."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from config_loader import LoadedConfig

log = logging.getLogger(__name__)

_W = 66  # report line width


# ── Result data classes ───────────────────────────────────────────────────────

@dataclass
class AdversaryResult:
    adversary_name: str
    operation_id: str
    started_at: datetime
    completed_at: datetime | None = None

    def duration_s(self) -> int | None:
        if self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None


@dataclass
class ReadinessReport:
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    adversary_results: list[AdversaryResult] = field(default_factory=list)


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:
    def __init__(self, cfg: LoadedConfig) -> None:
        self.cfg = cfg

    def build_report(self, adversary_results: list[AdversaryResult]) -> ReadinessReport:
        return ReadinessReport(adversary_results=adversary_results)

    async def send(self, report: ReadinessReport) -> None:
        mode = self.cfg.settings.reporting.mode
        self._log_report(report)
        if mode in ("webhook", "both"):
            await self._send_webhook(report)
        if mode in ("email", "both"):
            log.warning("Email dispatch is not yet implemented — skipping")

    # ── Log / console output ──────────────────────────────────────────────────

    def _log_report(self, report: ReadinessReport) -> None:
        ran = len(report.adversary_results)
        lines: list[str] = [
            "═" * _W,
            f"  OPERATIONS REPORT  {report.generated_at:%Y-%m-%d %H:%M:%S} UTC",
            f"  Adversaries run: {ran}",
            "═" * _W,
        ]

        for adv in report.adversary_results:
            dur = adv.duration_s()
            duration = f"{dur}s" if dur is not None else "—"
            lines.append(
                f"  ▸ {adv.adversary_name:<20}  "
                f"op={adv.operation_id[:8]}  "
                f"duration={duration}"
            )

        lines.append("═" * _W)
        log.info("\n%s", "\n".join(lines))

    # ── Webhook dispatch ──────────────────────────────────────────────────────

    async def _send_webhook(self, report: ReadinessReport) -> None:
        url = self.cfg.settings.reporting.webhook_url
        payload = self._to_dict(report)
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(url, json=payload)
                r.raise_for_status()
            log.info("Webhook delivered → %s  (HTTP %d)", url, r.status_code)
        except httpx.HTTPError as exc:
            log.error("Webhook delivery failed: %s", exc)

    # ── JSON serialisation ────────────────────────────────────────────────────

    def _to_dict(self, report: ReadinessReport) -> dict[str, Any]:
        return {
            "generated_at": report.generated_at.isoformat(),
            "adversaries_run": len(report.adversary_results),
            "adversaries": [
                {
                    "name": r.adversary_name,
                    "operation_id": r.operation_id,
                    "started_at": r.started_at.isoformat(),
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "duration_s": r.duration_s(),
                }
                for r in report.adversary_results
            ],
        }
