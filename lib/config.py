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
        raw = yaml.safe_load(f) or {}

    overrides = {
        name.lower(): _parse_override(data or {})
        for name, data in (raw.get('headers') or {}).items()
    }
    return AppConfig(overrides=overrides)


def get_override(config: AppConfig, header_name: str) -> HeaderOverride:
    return config.overrides.get(header_name.lower(), HeaderOverride())
