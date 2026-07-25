"""The Severity ordering is load-bearing: exit codes, issue classification and
worst-severity aggregation all rely on these comparisons."""
import pytest

from lib.models import (
    SEVERITY_COLORS, SEVERITY_LABELS, SEVERITY_SYMBOLS,
    Finding, HeaderResult, Severity,
)


def test_severity_is_ordered_from_ok_to_critical():
    assert (Severity.OK < Severity.NOTE < Severity.INFO < Severity.LOW
            < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL)


def test_note_sits_below_the_exit_code_threshold():
    """check_headers.py exits 0 for `worst <= INFO`; NOTE must fall inside that."""
    assert Severity.NOTE <= Severity.INFO


@pytest.mark.parametrize("mapping", [SEVERITY_COLORS, SEVERITY_LABELS, SEVERITY_SYMBOLS])
def test_display_maps_cover_every_severity(mapping):
    assert set(mapping) == set(Severity)


def test_severity_can_be_looked_up_by_name():
    assert Severity['CRITICAL'] is Severity.CRITICAL
    with pytest.raises(KeyError):
        Severity['CATASTROPHIC']


def test_worst_severity_of_an_empty_result_is_ok():
    result = HeaderResult(name='x', canonical_name='X', value='v')
    assert result.worst_severity == Severity.OK


def test_worst_severity_picks_the_maximum():
    result = HeaderResult(name='x', canonical_name='X', value='v', findings=[
        Finding('X', Severity.INFO, 'a'),
        Finding('X', Severity.HIGH, 'b'),
        Finding('X', Severity.LOW, 'c'),
    ])
    assert result.worst_severity == Severity.HIGH


@pytest.mark.parametrize("value,present", [("v", True), ("", True), (None, False)])
def test_is_present_distinguishes_absent_from_empty(value, present):
    assert HeaderResult(name='x', canonical_name='X', value=value).is_present is present
