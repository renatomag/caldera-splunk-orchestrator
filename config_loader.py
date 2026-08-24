"""Loads and validates all YAML configuration files against Pydantic models."""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

_ENV_RE = re.compile(r"\$\{([^}]+)\}")

from models import AppSettings, AdversaryProfile, DetectionNamespace, DetectionRule

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised for any configuration loading or validation failure."""


# ── Loaded config container ───────────────────────────────────────────────────

@dataclass
class LoadedConfig:
    settings: AppSettings
    adversaries: dict[str, AdversaryProfile] = field(default_factory=dict)
    detections: dict[str, DetectionNamespace] = field(default_factory=dict)

    def active_adversary_profiles(self) -> list[AdversaryProfile]:
        """Return profiles for every name in active_adversaries; raise if any is missing."""
        missing = [n for n in self.settings.active_adversaries if n not in self.adversaries]
        if missing:
            raise ConfigError(
                f"active_adversaries references profiles that were not loaded: {missing}\n"
                f"Available profiles: {sorted(self.adversaries)}"
            )
        return [self.adversaries[n] for n in self.settings.active_adversaries]

    def resolve_detection(self, ref: str) -> tuple[str, DetectionRule] | None:
        """
        Resolve a 'namespace.key' detection reference.
        Returns (ref, DetectionRule) or None if not found.
        """
        parts = ref.split(".", 1)
        if len(parts) != 2:
            return None
        ns_name, key = parts
        ns = self.detections.get(ns_name)
        if ns is None:
            return None
        rule = ns.get(key)
        if rule is None:
            return None
        return (ref, rule)

    def summary(self) -> str:
        adv_names = sorted(self.adversaries)
        ns_detail = {ns: len(obj.detections) for ns, obj in sorted(self.detections.items())}
        return (
            f"adversaries={adv_names}  "
            f"detection_namespaces={ns_detail}  "
            f"active={self.settings.active_adversaries}"
        )


# ── YAML helpers ──────────────────────────────────────────────────────────────

def _expand_env_vars(obj: object, path: Path) -> object:
    """
    Recursively walk a parsed YAML structure and replace every ${VAR_NAME}
    placeholder with the value of the corresponding environment variable.
    Raises ConfigError immediately if a referenced variable is not set,
    so credentials never need to live in the YAML file itself.
    """
    if isinstance(obj, str):
        def _replace(match: re.Match) -> str:
            var = match.group(1)
            val = os.environ.get(var)
            if val is None:
                raise ConfigError(
                    f"{path.name}: environment variable '${{{var}}}' is not set"
                )
            return val
        return _ENV_RE.sub(_replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v, path) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item, path) for item in obj]
    return obj


def _read_yaml(path: Path) -> dict:
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        raw = data or {}
        return _expand_env_vars(raw, path)  # type: ignore[return-value]
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error in {path}: {exc}") from exc


# ── Public loader ─────────────────────────────────────────────────────────────

def load_config(config_dir: Path) -> LoadedConfig:
    """
    Load and validate all YAML files under config_dir.
    Raises ConfigError with a human-readable message on any problem.
    """
    config_dir = config_dir.resolve()

    # ── settings.yaml ─────────────────────────────────────────────────────────
    settings_path = config_dir / "settings.yaml"
    if not settings_path.exists():
        raise ConfigError(f"settings.yaml not found at {settings_path}")

    raw = _read_yaml(settings_path)
    try:
        settings = AppSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"settings.yaml validation failed:\n{exc}") from exc

    log.debug("settings.yaml loaded: %d agent(s)", len(settings.agents))

    # ── adversary profiles ────────────────────────────────────────────────────
    adversaries: dict[str, AdversaryProfile] = {}
    adv_dir = config_dir / "adversaries"
    if adv_dir.exists():
        for yaml_file in sorted(adv_dir.glob("*.yaml")):
            raw = _read_yaml(yaml_file)
            try:
                profile = AdversaryProfile.model_validate(raw)
            except ValidationError as exc:
                raise ConfigError(f"{yaml_file.name} validation failed:\n{exc}") from exc
            adversaries[profile.name] = profile
            log.debug("Loaded adversary: %s (%d techniques)", profile.name, len(profile.techniques))
    else:
        log.warning("No adversaries/ directory found under %s", config_dir)

    # ── detection namespaces ──────────────────────────────────────────────────
    detections: dict[str, DetectionNamespace] = {}
    det_dir = config_dir / "detections"
    if det_dir.exists():
        for yaml_file in sorted(det_dir.glob("*.yaml")):
            raw = _read_yaml(yaml_file)
            try:
                ns = DetectionNamespace.model_validate(raw)
            except ValidationError as exc:
                raise ConfigError(f"{yaml_file.name} validation failed:\n{exc}") from exc
            detections[ns.namespace] = ns
            log.debug("Loaded detection namespace: %s (%d rules)", ns.namespace, len(ns.detections))
    else:
        log.warning("No detections/ directory found under %s", config_dir)

    cfg = LoadedConfig(settings=settings, adversaries=adversaries, detections=detections)

    # Eagerly validate that active_adversaries all exist
    cfg.active_adversary_profiles()

    return cfg
