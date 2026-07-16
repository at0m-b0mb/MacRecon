"""Collector registry.

Order here is the order of the sidebar and of the exported report: broad
context first (what is this machine), then the specific attack surface, then
the graded judgement that depends on all of it.
"""

from __future__ import annotations

from typing import List

from .base import Collector
from .hardware import HardwareCollector
from .network import NetworkCollector
from .processes import ProcessesCollector
from .security_audit import SecurityAuditCollector
from .software import SoftwareCollector
from .system import SystemCollector
from .users import UsersCollector

ALL_COLLECTORS: List[Collector] = [
    SystemCollector(),
    HardwareCollector(),
    UsersCollector(),
    NetworkCollector(),
    SoftwareCollector(),
    ProcessesCollector(),
    SecurityAuditCollector(),
]

__all__ = ["ALL_COLLECTORS", "Collector"]
