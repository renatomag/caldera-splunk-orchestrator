"""Pydantic v2 models for all YAML configuration schemas."""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator


# ── Settings ──────────────────────────────────────────────────────────────────

class CalderaSettings(BaseModel):
    host: str
    port: int = 8888
    api_key: str

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class SplunkSettings(BaseModel):
    host: str
    port: int = 8089
    token: str
    verify_ssl: bool = False

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class AgentSettings(BaseModel):
    name: str
    fqdn: str
    role: Literal["workstation", "domain_controller"]

    @property
    def hostname(self) -> str:
        return self.fqdn.split(".")[0]


class ScheduleSettings(BaseModel):
    mode: Literal["interval", "cron", "manual"] = "interval"
    interval_hours: int = Field(24, ge=1)
    cron_expression: str = "0 6 * * *"
    operation_timeout_minutes: int = Field(30, ge=5)   # give up polling CALDERA after this long


class ReportingSettings(BaseModel):
    mode: Literal["webhook", "email", "both", "log_only"] = "log_only"
    webhook_url: str = ""
    email_to: str = ""
    min_coverage_threshold: int = Field(80, ge=0, le=100)

    @model_validator(mode="after")
    def _require_destinations(self) -> "ReportingSettings":
        if self.mode in ("webhook", "both") and not self.webhook_url:
            raise ValueError("webhook_url is required when reporting mode includes 'webhook'")
        if self.mode in ("email", "both") and not self.email_to:
            raise ValueError("email_to is required when reporting mode includes 'email'")
        return self


class VMwareSettings(BaseModel):
    host: str
    username: str
    password: str
    vm_name: str
    snapshot_name: str
    datacenter: str = ""
    verify_ssl: bool = False
    agent_ready_timeout_minutes: int = Field(10, ge=1)


class AppSettings(BaseModel):
    caldera: CalderaSettings
    splunk: Optional[SplunkSettings] = None
    vmware: Optional[VMwareSettings] = None
    agents: list[AgentSettings] = Field(min_length=1)   # pre-deployed Sandcat beacons
    targets: list[AgentSettings] = Field(default_factory=list)  # lateral-movement destinations
    schedule: ScheduleSettings = Field(default_factory=ScheduleSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    active_adversaries: list[str] = Field(min_length=1)

    def all_hosts(self) -> list[AgentSettings]:
        """All hosts relevant for Splunk queries: pre-deployed agents + lateral targets."""
        return self.agents + self.targets

    def hosts_by_role(self, role: str) -> list[AgentSettings]:
        """Search both agents and targets by role."""
        return [h for h in self.all_hosts() if h.role == role]


# ── Adversary profiles ────────────────────────────────────────────────────────

class TechniqueConfig(BaseModel):
    id: str                         # MITRE technique ID, e.g. T1003.001
    name: str
    caldera_ability_id: str = ""    # empty → ability skipped or looked up by name
    target_role: str
    expected_detections: list[str] = Field(default_factory=list)
    # detection refs use "namespace.key" format, e.g. "credential_access.lsass_dump"


class TargetRole(BaseModel):
    role: str


class AdversaryProfile(BaseModel):
    name: str
    display_name: str
    description: str = ""
    caldera_adversary_id: str = ""  # empty → auto-create in CALDERA
    targets: list[TargetRole] = Field(default_factory=list)
    techniques: list[TechniqueConfig] = Field(default_factory=list)

    def techniques_for_role(self, role: str) -> list[TechniqueConfig]:
        return [t for t in self.techniques if t.target_role == role]


# ── Detection mappings ────────────────────────────────────────────────────────

class DetectionRule(BaseModel):
    display_name: str
    mitre_technique: str
    splunk_index: str = "notable"
    search_name_pattern: str        # wildcard matched against notable search_name field
    correlation_search_name: str = ""  # exact Splunk saved search name to dispatch before checking notables
    fallback_spl: str = ""          # raw SPL executed if no notable match found
    severity: Literal["critical", "high", "medium", "low"] = "high"
    required: bool = True           # required=True detections count toward coverage threshold


class DetectionNamespace(BaseModel):
    namespace: str
    detections: dict[str, DetectionRule]

    def get(self, key: str) -> DetectionRule | None:
        return self.detections.get(key)

    def required_detections(self) -> dict[str, DetectionRule]:
        return {k: v for k, v in self.detections.items() if v.required}
