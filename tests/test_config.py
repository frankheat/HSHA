"""Tests for the YAML config loader (lib/config.py)."""
import pytest

from lib.config import AppConfig, HeaderOverride, get_override, load_config


@pytest.fixture
def yaml_file(tmp_path):
    def write(content: str):
        path = tmp_path / 'config.yaml'
        path.write_text(content)
        return str(path)
    return write


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def test_no_path_loads_the_basic_profile():
    config = load_config(None)
    assert config.overrides['expect-ct'].skip is True


def test_header_names_are_normalised_to_lowercase(yaml_file):
    config = load_config(yaml_file("headers:\n  X-Frame-Options:\n    skip: true\n"))
    assert 'x-frame-options' in config.overrides


def test_header_entry_without_options_yields_an_empty_override(yaml_file):
    config = load_config(yaml_file("headers:\n  X-Frame-Options:\n"))
    assert config.overrides['x-frame-options'] == HeaderOverride(display_name='X-Frame-Options')


def test_the_configured_spelling_is_preserved(yaml_file):
    config = load_config(yaml_file("headers:\n  X-Request-Id:\n    required: true\n"))
    assert config.overrides['x-request-id'].display_name == 'X-Request-Id'


def test_empty_file_yields_no_overrides(yaml_file):
    assert load_config(yaml_file("")).overrides == {}


def test_file_without_headers_section_yields_no_overrides(yaml_file):
    assert load_config(yaml_file("something_else: 1\n")).overrides == {}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_known_options_are_parsed(yaml_file):
    config = load_config(yaml_file(
        "headers:\n"
        "  Cache-Control:\n"
        "    skip: false\n"
        "    required: true\n"
        "    severity_if_missing: medium\n"
        "    severity_if_present: low\n"
        "    expected_value: no-store\n"
        "    expected_pattern: '^no'\n"
    ))
    override = config.overrides['cache-control']
    assert override.required is True
    assert override.severity_if_missing == 'medium'
    assert override.severity_if_present == 'low'
    assert override.expected_value == 'no-store'
    assert override.expected_pattern == '^no'
    assert override.extra == {}


def test_unknown_options_are_collected_into_extra(yaml_file):
    config = load_config(yaml_file(
        "headers:\n  Strict-Transport-Security:\n    min_max_age: 63072000\n"
    ))
    assert config.overrides['strict-transport-security'].extra == {'min_max_age': 63072000}


# ---------------------------------------------------------------------------
# Validation errors (all must surface as ValueError -> exit code 2)
# ---------------------------------------------------------------------------

def test_malformed_yaml_raises(yaml_file):
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(yaml_file("headers:\n  - [unclosed\n"))


def test_non_mapping_top_level_raises(yaml_file):
    with pytest.raises(ValueError, match="top level must be a YAML mapping"):
        load_config(yaml_file("just a string\n"))


def test_non_mapping_headers_section_raises(yaml_file):
    with pytest.raises(ValueError, match="'headers' must be a mapping"):
        load_config(yaml_file("headers:\n  - X-Frame-Options\n"))


def test_non_mapping_header_entry_raises(yaml_file):
    with pytest.raises(ValueError, match="expected a mapping of options"):
        load_config(yaml_file("headers:\n  X-Frame-Options: DENY\n"))


def test_invalid_regex_raises(yaml_file):
    with pytest.raises(ValueError, match="Invalid expected_pattern"):
        load_config(yaml_file("headers:\n  ETag:\n    expected_pattern: '['\n"))


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        load_config(str(tmp_path / 'nope.yaml'))


# ---------------------------------------------------------------------------
# get_override
# ---------------------------------------------------------------------------

def test_get_override_is_case_insensitive():
    config = AppConfig(overrides={'x-frame-options': HeaderOverride(skip=True)})
    assert get_override(config, 'X-Frame-Options').skip is True


def test_get_override_returns_a_neutral_default_when_absent():
    assert get_override(AppConfig(), 'X-Frame-Options') == HeaderOverride()


# ---------------------------------------------------------------------------
# Shipped profiles must stay loadable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ['basic', 'extended'])
def test_shipped_profiles_load(name):
    from conftest import ROOT
    assert load_config(str(ROOT / 'profiles' / f'{name}.yaml')).overrides


# ---------------------------------------------------------------------------
# Unknown options are rejected rather than silently dropped
# ---------------------------------------------------------------------------

def test_unknown_option_is_rejected(yaml_file):
    """A typo used to land in `extra`, be read by nobody, and leave the default
    threshold quietly in force."""
    path = yaml_file("headers:\n  Strict-Transport-Security:\n    min_maxage: 99999999\n")
    with pytest.raises(ValueError, match="min_maxage"):
        load_config(path)


def test_rejection_message_lists_the_valid_options(yaml_file):
    path = yaml_file("headers:\n  Strict-Transport-Security:\n    min_maxage: 1\n")
    with pytest.raises(ValueError, match="min_max_age"):
        load_config(path)


def test_hsts_extra_options_are_accepted(yaml_file):
    path = yaml_file(
        "headers:\n"
        "  Strict-Transport-Security:\n"
        "    min_max_age: 63072000\n"
        "    require_include_subdomains: false\n"
        "    require_preload: true\n"
    )
    assert load_config(path).overrides['strict-transport-security'].extra == {
        'min_max_age': 63072000,
        'require_include_subdomains': False,
        'require_preload': True,
    }


def test_an_extra_option_is_rejected_on_a_header_that_does_not_use_it(yaml_file):
    path = yaml_file("headers:\n  X-Frame-Options:\n    min_max_age: 63072000\n")
    with pytest.raises(ValueError, match="min_max_age"):
        load_config(path)


def test_unknown_option_on_a_custom_header_is_rejected(yaml_file):
    path = yaml_file("headers:\n  X-Request-Id:\n    requiredd: true\n")
    with pytest.raises(ValueError, match="requiredd"):
        load_config(path)
