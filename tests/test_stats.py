"""Wilson interval must match published reference values."""

from __future__ import annotations

import pytest

from aetg_validate.stats import format_interval, wilson_interval

TOL = 1e-3


def test_zero_of_hundred_matches_reference():
    """0/100 -> [0, 0.0370]. Wald would give a zero-width interval here."""
    interval = wilson_interval(0, 100)
    assert interval.point == 0.0
    assert interval.low == 0.0
    assert interval.high == pytest.approx(0.03699, abs=TOL)


def test_half_of_hundred_matches_reference():
    """50/100 -> (0.4038, 0.5962)."""
    interval = wilson_interval(50, 100)
    assert interval.point == pytest.approx(0.5)
    assert interval.low == pytest.approx(0.40383, abs=TOL)
    assert interval.high == pytest.approx(0.59617, abs=TOL)


def test_all_of_hundred_matches_reference():
    """100/100 -> (0.9630, 1.0)."""
    interval = wilson_interval(100, 100)
    assert interval.low == pytest.approx(0.96301, abs=TOL)
    assert interval.high == 1.0


def test_interval_bounds_are_clamped():
    for k, n in [(0, 1), (1, 1), (1, 3), (999, 1000)]:
        interval = wilson_interval(k, n)
        assert 0.0 <= interval.low <= interval.point <= interval.high <= 1.0


def test_zero_of_many_still_has_nonzero_upper_bound():
    """The whole point: 0/20000 is not certainty."""
    interval = wilson_interval(0, 20000)
    assert interval.high > 0.0
    assert interval.high < 0.001


def test_rejects_invalid_arguments():
    with pytest.raises(ValueError):
        wilson_interval(0, 0)
    with pytest.raises(ValueError):
        wilson_interval(5, 4)
    with pytest.raises(ValueError):
        wilson_interval(-1, 4)


def test_format_interval_shape():
    text = format_interval(wilson_interval(0, 20000))
    assert text.startswith("0.00% [0.00%, ")
    assert "k=0, n=20000" in text
