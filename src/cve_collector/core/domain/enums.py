from __future__ import annotations

from enum import Enum
from typing import Optional
from cvss import CVSS3


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: str) -> Optional["Severity"]:
        """Parse a severity from a string label or CVSS vector/score.

        - Labels (case-insensitive): critical, high, medium, moderate->MEDIUM, low, unknown
        - CVSS v3 vector (starts with "CVSS:"): compute base score via cvss and map
        - Numeric string: map by standard thresholds
        """
        s = value.strip()
        if not s:
            return None
        u = s.upper()
        # Label mapping
        label_map = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "MODERATE": cls.MEDIUM,
            "LOW": cls.LOW,
            "UNKNOWN": cls.UNKNOWN,
        }
        if u in label_map:
            return label_map[u]

        # CVSS vector
        if u.startswith("CVSS:"):
            try:
                cv = CVSS3(s)
                base: Optional[float] = None
                try:
                    scores = cv.scores()
                    if isinstance(scores, (tuple, list)) and len(scores) >= 1:
                        base = float(scores[0])
                except Exception:
                    pass
                if base is None:
                    try:
                        base_attr = cv.base_score
                        if base_attr is not None:
                            base = float(base_attr)
                    except Exception:
                        base = None
                if base is not None:
                    if base >= 9.0:
                        return cls.CRITICAL
                    if base >= 7.0:
                        return cls.HIGH
                    if base >= 4.0:
                        return cls.MEDIUM
                    if base > 0.0:
                        return cls.LOW
                    return None
            except Exception:
                # If it's a CVSS 4.0 vector, try a lightweight heuristic mapping
                if u.startswith("CVSS:4.0/"):
                    # Parse tokens like AV:N, AC:H, VC:L, VI:N, VA:N, ...
                    try:
                        parts = s.split('/')
                        metrics = {}
                        for part in parts[1:]:
                            if ':' in part:
                                k, v = part.split(':', 1)
                                metrics[k.strip().upper()] = v.strip().upper()
                        vc = metrics.get('VC')  # Confidentiality impact
                        vi = metrics.get('VI')  # Integrity impact
                        va = metrics.get('VA')  # Availability impact
                        impacts = [vc, vi, va]
                        if any(x == 'H' for x in impacts):
                            return cls.HIGH
                        if any(x == 'L' for x in impacts):
                            return cls.LOW
                        # Default when no classic impact metrics present
                        return None
                    except Exception:
                        return None
                return None

        # Numeric string
        try:
            score = float(s)
            if score >= 9.0:
                return cls.CRITICAL
            if score >= 7.0:
                return cls.HIGH
            if score >= 4.0:
                return cls.MEDIUM
            if score > 0.0:
                return cls.LOW
            return None
        except ValueError:
            return None


class ReferenceType(Enum):
    ADVISORY = "ADVISORY"
    WEB = "WEB"
    FIX = "FIX"
    PACKAGE = "PACKAGE"
    OTHER = "OTHER"


