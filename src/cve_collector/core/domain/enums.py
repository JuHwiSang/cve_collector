from __future__ import annotations

from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ReferenceType(Enum):
    ADVISORY = "ADVISORY"
    WEB = "WEB"
    FIX = "FIX"
    PACKAGE = "PACKAGE"
    OTHER = "OTHER"


