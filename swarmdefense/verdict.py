from dataclasses import dataclass
from typing import List

from .decision import Decision


@dataclass
class Verdict:
    verdict_id: str
    event_id: str
    decision: Decision
    risk_score: int
    reason: str
    provenance_labels: List[str]
    policy_id: str
