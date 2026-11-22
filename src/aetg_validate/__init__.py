"""AETG-Validate — Phi-gated IDS evasion validation.

Public API (stable):
    from aetg_validate import wilson_interval, compute, summarize
"""

from __future__ import annotations

__version__ = "0.2.0"
__all__ = [
    "__version__",
    "wilson_interval",
    "format_interval",
    "Interval",
    "FlowRecord",
    "ScanMetrics",
    "compute",
    "summarize",
]

from .models import FlowRecord, ScanMetrics
from .scan import compute, summarize
from .stats import Interval, format_interval, wilson_interval
