"""VMware vCenter client — wraps govc for snapshot revert operations."""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path

from models import VMwareSettings

log = logging.getLogger(__name__)

_GOVC_SEARCH_PATHS = [
    Path(__file__).parent / "govc",   # project directory (our install location)
    Path("/usr/local/bin/govc"),
    Path("/usr/bin/govc"),
]


class VMwareError(Exception):
    """Raised on govc execution or VMware API errors."""


def _find_govc() -> str:
    for path in _GOVC_SEARCH_PATHS:
        if path.exists() and os.access(path, os.X_OK):
            return str(path)
    found = shutil.which("govc")
    if found:
        return found
    raise VMwareError(
        "govc binary not found. Expected at: "
        + ", ".join(str(p) for p in _GOVC_SEARCH_PATHS)
    )


class VMwareClient:
    def __init__(self, settings: VMwareSettings) -> None:
        self._settings = settings
        self._govc = _find_govc()
        self._env = {
            **os.environ,
            "GOVC_URL": f"https://{settings.host}",
            "GOVC_USERNAME": settings.username,
            "GOVC_PASSWORD": settings.password,
            "GOVC_INSECURE": "1" if not settings.verify_ssl else "0",
            **({"GOVC_DATACENTER": settings.datacenter} if settings.datacenter else {}),
        }

    _GOVC_TIMEOUT = 120  # seconds before a hung govc call is killed

    async def _run(self, *args: str) -> str:
        """Run a govc command and return stdout. Raises VMwareError on failure."""
        cmd = [self._govc, *args]
        log.debug("govc: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=self._env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._GOVC_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise VMwareError(
                f"govc {args[0]} timed out after {self._GOVC_TIMEOUT}s"
            )
        if proc.returncode != 0:
            raise VMwareError(
                f"govc {args[0]} failed (rc={proc.returncode}): "
                f"{stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace").strip()

    async def check_connectivity(self) -> str:
        """Verify govc can reach vCenter. Returns vCenter version string."""
        out = await self._run("about")
        log.info("vCenter reachable: %s", out.splitlines()[0] if out else "(no output)")
        return out

    async def revert_snapshot(self) -> None:
        """Revert the configured VM to the configured snapshot."""
        vm = self._settings.vm_name
        snap = self._settings.snapshot_name
        log.info("Reverting VM '%s' to snapshot '%s' ...", vm, snap)
        await self._run("snapshot.revert", "-vm", vm, snap)
        log.info("Snapshot revert issued — VM resuming from snapshot state")
