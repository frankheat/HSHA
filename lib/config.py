import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class HeaderOverride:
    # Skip this header entirely (not checked, not shown in output)
    skip: bool = False
    # Override whether the header is required (None = use OWASP default)
    required: Optional[bool] = None
    # Severity to emit when the header is missing (None = use OWASP default)
    severity_if_missing: Optional[str] = None
    # Severity to emit when the header is present (useful for deprecated headers)
    severity_if_present: Optional[str] = None
    # Assert the header value equals this string (case-insensitive)
    expected_value: Optional[str] = None
    # Assert the header value matches this regex pattern
    expected_pattern: Optional[str] = None
    # Extra key/value pairs forwarded to individual rule checkers
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AppConfig:
    overrides: dict[str, HeaderOverride] = field(default_factory=dict)


_KNOWN_KEYS = {
    'skip', 'required', 'severity_if_missing', 'severity_if_present',
    'expected_value', 'expected_pattern',
}


def _parse_override(data: dict) -> HeaderOverride:
    if not data:
        return HeaderOverride()
    return HeaderOverride(
        skip=bool(data.get('skip', False)),
        required=data.get('required'),
        severity_if_missing=data.get('severity_if_missing'),
        severity_if_present=data.get('severity_if_present'),
        expected_value=data.get('expected_value'),
        expected_pattern=data.get('expected_pattern'),
        extra={k: v for k, v in data.items() if k not in _KNOWN_KEYS},
    )


def load_config(path: Optional[str] = None) -> AppConfig:
    if path is None:
        default = Path(__file__).parent.parent / 'profiles' / 'basic.yaml'
        if not default.exists():
            return AppConfig()
        path = str(default)

    with open(path) as f:
        try:
            raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file '{path}': {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid config file '{path}': top level must be a YAML mapping.")
    headers_section = raw.get('headers') or {}
    if not isinstance(headers_section, dict):
        raise ValueError(f"Invalid config file '{path}': 'headers' must be a mapping of header names.")

    overrides: dict[str, HeaderOverride] = {}
    for name, data in headers_section.items():
        if data is not None and not isinstance(data, dict):
            raise ValueError(
                f"Invalid config for header '{name}': expected a mapping of options, got {type(data).__name__}."
            )
        override = _parse_override(data or {})
        if override.expected_pattern:
            try:
                re.compile(override.expected_pattern)
            except re.error as e:
                raise ValueError(f"Invalid expected_pattern for header '{name}': {e}")
        overrides[str(name).lower()] = override
    return AppConfig(overrides=overrides)


def get_override(config: AppConfig, header_name: str) -> HeaderOverride:
    return config.overrides.get(header_name.lower(), HeaderOverride())
