"""CALDERA REST API client."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from models import AppSettings

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


class CalderaError(Exception):
    """Raised on CALDERA connectivity or API errors."""


# ── Data classes for API responses ────────────────────────────────────────────

@dataclass
class LiveAgent:
    paw: str
    host: str
    platform: str
    alive: bool
    group: str
    last_seen: str


# ── Client ────────────────────────────────────────────────────────────────────

class CalderaClient:
    def __init__(self, settings: AppSettings) -> None:
        self._base = settings.caldera.base_url
        self._headers = {
            "KEY": settings.caldera.api_key,
            "Content-Type": "application/json",
        }
        self._expected_agents = settings.agents

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=self._headers, timeout=_TIMEOUT)

    # ── Connectivity ──────────────────────────────────────────────────────────

    async def check_connectivity(self) -> dict[str, Any]:
        """
        Call GET /api/v2/health and return the server info dict.
        Raises CalderaError on connection failure or non-2xx response.
        """
        async with self._client() as c:
            try:
                r = await c.get(f"{self._base}/api/v2/health")
                r.raise_for_status()
                return r.json()
            except httpx.ConnectError as exc:
                raise CalderaError(
                    f"Cannot connect to CALDERA at {self._base} — is the server running?"
                ) from exc
            except httpx.HTTPStatusError as exc:
                raise CalderaError(
                    f"CALDERA health check returned HTTP {exc.response.status_code}"
                ) from exc

    # ── Agents ────────────────────────────────────────────────────────────────

    async def list_agents(self) -> list[LiveAgent]:
        """Return all agents currently registered in CALDERA."""
        try:
            async with self._client() as c:
                r = await c.get(f"{self._base}/api/v2/agents")
                r.raise_for_status()
                return [
                    LiveAgent(
                        paw=a["paw"],
                        host=a.get("host", ""),
                        platform=a.get("platform", ""),
                        alive=a.get("trusted", False),   # CALDERA uses "trusted" for liveness
                        group=a.get("group", "red"),
                        last_seen=a.get("last_seen", ""),
                    )
                    for a in r.json()
                ]
        except httpx.RequestError as exc:
            raise CalderaError(f"Connection error listing agents: {exc}") from exc

    async def validate_agents(self) -> dict[str, LiveAgent]:
        """
        Match every agent in settings.agents against live CALDERA agents by hostname.
        Returns {configured_name: LiveAgent}.
        Raises CalderaError if any expected agent is absent from CALDERA.
        """
        live = await self.list_agents()
        # Index by uppercase hostname for case-insensitive matching
        live_by_host = {a.host.upper(): a for a in live}

        matched: dict[str, LiveAgent] = {}
        missing: list[str] = []

        for cfg in self._expected_agents:
            hostname = cfg.hostname.upper()
            agent = live_by_host.get(hostname)
            if agent is None:
                missing.append(cfg.fqdn)
            else:
                matched[cfg.name] = agent
                status = "alive" if agent.alive else "DEAD (not trusted)"
                log.info("Agent found: %-30s  paw=%-10s  group=%-8s  %s",
                         cfg.fqdn, agent.paw, agent.group, status)

        if missing:
            raise CalderaError(
                f"Expected agent(s) not found in CALDERA: {missing}\n"
                f"Live agents: {[a.host for a in live]}"
            )

        return matched

    # ── Adversaries ───────────────────────────────────────────────────────────

    async def list_adversaries(self) -> list[dict[str, Any]]:
        async with self._client() as c:
            r = await c.get(f"{self._base}/api/v2/adversaries")
            r.raise_for_status()
            return r.json()

    # ── Operations ────────────────────────────────────────────────────────────

    async def start_operation(
        self,
        name: str,
        adversary_id: str,
        group: str = "red",
        planner_id: str = "atomic",
    ) -> str:
        """Start a CALDERA operation and return its operation id."""
        payload: dict[str, Any] = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "planner": {"id": planner_id},
            "group": group,
            "state": "running",
            "autonomous": 1,
        }
        try:
            async with self._client() as c:
                r = await c.post(f"{self._base}/api/v2/operations", json=payload)
                r.raise_for_status()
                op = r.json()
                op_id = op["id"]
                log.info("Started CALDERA operation '%s' id=%s", name, op_id)
                return op_id
        except httpx.RequestError as exc:
            raise CalderaError(f"Connection error starting operation '{name}': {exc}") from exc

    async def delete_operation(self, operation_id: str) -> None:
        """Delete a CALDERA operation by id. Ignores 404 (already gone)."""
        try:
            async with self._client() as c:
                r = await c.delete(f"{self._base}/api/v2/operations/{operation_id}")
                if r.status_code == 404:
                    return
                r.raise_for_status()
        except httpx.RequestError as exc:
            raise CalderaError(f"Connection error deleting operation {operation_id[:8]}: {exc}") from exc
        log.debug("Deleted CALDERA operation %s", operation_id[:8])

    async def get_operation(self, operation_id: str) -> dict[str, Any]:
        """Fetch current state of a CALDERA operation."""
        try:
            async with self._client() as c:
                r = await c.get(f"{self._base}/api/v2/operations/{operation_id}")
                r.raise_for_status()
                return r.json()
        except httpx.RequestError as exc:
            raise CalderaError(f"Connection error polling operation {operation_id[:8]}: {exc}") from exc

    async def trust_agent(self, paw: str) -> None:
        """Force-trust an agent by paw via PATCH /api/v2/agents/{paw}."""
        try:
            async with self._client() as c:
                r = await c.patch(
                    f"{self._base}/api/v2/agents/{paw}",
                    json={"trusted": True},
                )
                r.raise_for_status()
        except httpx.RequestError as exc:
            raise CalderaError(f"Connection error trusting agent {paw}: {exc}") from exc
        log.info("Agent paw=%s trusted via API", paw)

    async def wait_for_agent_ready(
        self, hostname: str, timeout_minutes: int = 10
    ) -> bool:
        """
        Poll until the agent matching hostname beacons in.
        If it arrives untrusted (CALDERA's untrusted_timer fired during revert),
        force-trust it via the API and return immediately.
        Returns True on success, False on timeout.
        """
        deadline = time.monotonic() + timeout_minutes * 60
        hostname_upper = hostname.upper()
        log.info("Waiting for agent '%s' to beacon in (timeout=%dm)...",
                 hostname, timeout_minutes)
        while time.monotonic() < deadline:
            try:
                agents = await self.list_agents()
                for agent in agents:
                    if agent.host.upper() == hostname_upper:
                        if agent.alive:
                            log.info("Agent '%s' is trusted and ready (paw=%s)", hostname, agent.paw)
                            return True
                        log.info(
                            "Agent '%s' beaconed in but untrusted (paw=%s) — "
                            "trusting via API", hostname, agent.paw
                        )
                        await self.trust_agent(agent.paw)
                        return True
            except CalderaError as exc:
                log.warning("Error polling agents: %s — retrying", exc)
            await asyncio.sleep(15)
        log.warning("Agent '%s' did not beacon within %d minutes", hostname, timeout_minutes)
        return False

    async def ensure_agents_trusted(self, agents_cfg) -> None:
        """Trust any configured agent that is present but untrusted. No-op if already trusted."""
        live = await self.list_agents()
        live_by_host = {a.host.upper(): a for a in live}
        for cfg in agents_cfg:
            agent = live_by_host.get(cfg.hostname.upper())
            if agent and not agent.alive:
                log.info("Pre-flight: agent '%s' untrusted — trusting now", cfg.name)
                await self.trust_agent(agent.paw)

    async def list_abilities(self) -> list[dict[str, Any]]:
        async with self._client() as c:
            r = await c.get(f"{self._base}/api/v2/abilities")
            r.raise_for_status()
            return r.json()
