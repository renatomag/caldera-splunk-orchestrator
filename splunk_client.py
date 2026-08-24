"""Splunk REST API client."""
from __future__ import annotations

import asyncio
import logging
import time
import urllib.parse
from typing import Any

import httpx

from models import AppSettings

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0, connect=5.0)
_SEARCH_POLL_INTERVAL = 5    # seconds between job-status polls
_SEARCH_POLL_DEADLINE = 120  # seconds before giving up on a search job


class SplunkError(Exception):
    """Raised on Splunk connectivity or API errors."""


class SplunkClient:
    def __init__(self, settings: AppSettings) -> None:
        self._base = settings.splunk.base_url
        # Splunk API tokens use Bearer auth; session keys use "Splunk <key>"
        self._headers = {"Authorization": f"Bearer {settings.splunk.token}"}
        self._verify = settings.splunk.verify_ssl

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self._headers,
            verify=self._verify,
            timeout=_TIMEOUT,
        )

    # ── Connectivity ──────────────────────────────────────────────────────────

    async def check_connectivity(self) -> dict[str, str]:
        """
        Call GET /services/server/info and return version metadata.
        Raises SplunkError on connection failure or non-2xx response.
        """
        async with self._client() as c:
            try:
                r = await c.get(
                    f"{self._base}/services/server/info",
                    params={"output_mode": "json"},
                )
                r.raise_for_status()
                entry = r.json().get("entry", [{}])[0]
                content = entry.get("content", {})
                return {
                    "version": content.get("version", "unknown"),
                    "server_name": content.get("serverName", "unknown"),
                    "product": content.get("product_type", "unknown"),
                }
            except httpx.ConnectError as exc:
                raise SplunkError(
                    f"Cannot connect to Splunk at {self._base} — check host/port and network"
                ) from exc
            except httpx.HTTPStatusError as exc:
                body = exc.response.text[:200]
                raise SplunkError(
                    f"Splunk returned HTTP {exc.response.status_code}: {body}"
                ) from exc

    # ── Search ────────────────────────────────────────────────────────────────

    async def run_search(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
    ) -> list[dict[str, Any]]:
        """
        Dispatch an SPL search job, wait for completion, return result rows.
        `spl` should NOT start with the 'search' keyword — it is prepended automatically
        unless the string already begins with a generating command (|, index=, etc.).
        """
        sid = await self._dispatch(spl, earliest, latest)
        await self._wait(sid)
        return await self._results(sid)

    async def _dispatch(self, spl: str, earliest: str, latest: str) -> str:
        # Prepend 'search' only when needed (not for transforming / generating commands)
        query = spl.strip()
        if not (query.startswith("|") or query.startswith("search ")):
            query = f"search {query}"

        async with self._client() as c:
            r = await c.post(
                f"{self._base}/services/search/jobs",
                data={
                    "search": query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "output_mode": "json",
                },
            )
            r.raise_for_status()
            return r.json()["sid"]

    async def _wait(self, sid: str) -> None:
        deadline = time.monotonic() + _SEARCH_POLL_DEADLINE
        async with self._client() as c:
            while time.monotonic() < deadline:
                r = await c.get(
                    f"{self._base}/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                )
                r.raise_for_status()
                state: str = r.json()["entry"][0]["content"]["dispatchState"]
                if state == "DONE":
                    return
                if state in ("FAILED", "PAUSED"):
                    raise SplunkError(f"Search job {sid} ended in state '{state}'")
                await asyncio.sleep(_SEARCH_POLL_INTERVAL)
        raise SplunkError(
            f"Search job {sid} did not complete within {_SEARCH_POLL_DEADLINE}s"
        )

    async def _results(self, sid: str) -> list[dict[str, Any]]:
        async with self._client() as c:
            r = await c.get(
                f"{self._base}/services/search/jobs/{sid}/results",
                params={"output_mode": "json", "count": 0},
            )
            r.raise_for_status()
            return r.json().get("results", [])

    # ── ESCU detection queries ────────────────────────────────────────────────

    async def fetch_search_spl(self, name: str) -> str:
        """
        Fetch the SPL of a Splunk saved search by exact name.
        Strips `security_content_summariesonly` so tstats scans all data
        without waiting for datamodel acceleration to rebuild.
        """
        encoded = urllib.parse.quote(name, safe="")
        async with self._client() as c:
            try:
                r = await c.get(
                    f"{self._base}/services/saved/searches/{encoded}",
                    params={"output_mode": "json"},
                )
                r.raise_for_status()
                entries = r.json().get("entry", [])
                if not entries:
                    raise SplunkError(f"Saved search not found: '{name}'")
                spl = entries[0]["content"].get("search", "")
                if not spl:
                    raise SplunkError(f"Saved search '{name}' has no SPL")
            except (KeyError, IndexError) as exc:
                raise SplunkError(f"Unexpected response fetching '{name}'") from exc
            except httpx.HTTPStatusError as exc:
                raise SplunkError(
                    f"Failed to fetch '{name}': HTTP {exc.response.status_code}"
                ) from exc

        spl = spl.replace("`security_content_summariesonly`", "")
        return spl.strip()

    # ── Data health ───────────────────────────────────────────────────────────

    async def check_sysmon_freshness(
        self,
        hostname: str,
        max_gap_minutes: int = 15,
    ) -> bool:
        """
        Return True if index=wineventlog received a Sysmon event from `hostname`
        within the last `max_gap_minutes`.
        """
        spl = (
            f'index=wineventlog host="{hostname}" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
            f'| head 1 | eval gap=now()-_time | where gap < {max_gap_minutes * 60} | stats count'
        )
        results = await self.run_search(spl, earliest=f"-{max_gap_minutes + 5}m")
        count = int(results[0].get("count", 0)) if results else 0
        return count > 0

    async def check_risk_freshness(
        self,
        hostname: str,
        max_gap_minutes: int = 60,
    ) -> bool:
        """Return True if index=risk has a recent entry for `hostname`."""
        spl = (
            f'index=risk risk_object="{hostname}" '
            f'| head 1 | eval gap=now()-_time | where gap < {max_gap_minutes * 60} | stats count'
        )
        results = await self.run_search(spl, earliest=f"-{max_gap_minutes + 5}m")
        count = int(results[0].get("count", 0)) if results else 0
        return count > 0
