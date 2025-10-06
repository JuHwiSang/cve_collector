from __future__ import annotations

from typing import Optional, Sequence, Any

from ..core.domain.enums import Severity
from cvss import CVSS3


def _severity_rank(level: Severity) -> int:
	order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.UNKNOWN: 0}
	return order.get(level, 0)


def map_score_to_severity(score: float) -> Optional[Severity]:
	if score >= 9.0:
		return Severity.CRITICAL
	if score >= 7.0:
		return Severity.HIGH
	if score >= 4.0:
		return Severity.MEDIUM
	if score > 0.0:
		return Severity.LOW
	return None


def severity_from_osv_score(value: object) -> Optional[Severity]:
	"""Convert an OSV severity 'score' value into a Severity enum.

	Accepts:
	- CVSS v3 vector strings (e.g., "CVSS:3.1/AV:N/..."), computes base score via cvss lib
	- Numeric score strings or floats
	- Explicit labels: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
	"""
	# Vector string
	if isinstance(value, str) and value.upper().startswith("CVSS:"):
		try:
			cvss_obj = CVSS3(value)
			base_score: Optional[float] = None
			if hasattr(cvss_obj, "scores"):
				scores = cvss_obj.scores()
				if isinstance(scores, (tuple, list)) and len(scores) >= 1:
					base_score = float(scores[0])
			if base_score is None and hasattr(cvss_obj, "base_score"):
				base_score = float(getattr(cvss_obj, "base_score"))
			if base_score is not None:
				return map_score_to_severity(base_score)
		except Exception:
			return None

	# Numeric score
	if isinstance(value, (int, float)):
		return map_score_to_severity(float(value))
	if isinstance(value, str):
		try:
			return map_score_to_severity(float(value))
		except ValueError:
			label = value.upper()
			if label in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
				return Severity[label]
	return None


def derive_severity_from_osv_entries(entries: Sequence[Any]) -> Optional[Severity]:
	"""Pick the most severe level from OSV `severity` entries.

	Each entry is expected to have a `score` attribute or key.
	"""
	best: Optional[Severity] = None
	for entry in entries:
		val = getattr(entry, "score", None)
		if val is None and isinstance(entry, dict):
			val = entry.get("score")
		lvl = severity_from_osv_score(val)
		if lvl is None:
			continue
		if best is None or _severity_rank(lvl) > _severity_rank(best):
			best = lvl
	return best


