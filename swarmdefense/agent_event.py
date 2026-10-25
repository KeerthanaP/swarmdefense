from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .event_type import EventType


@dataclass
class AgentEvent:
    event_id: str
    timestamp: float
    source_agent: str
    target_agent: str
    event_type: EventType
    payload_summary: str
    provenance_labels: List[str]
    requested_tool: Optional[str] = None
    requested_args: Optional[Dict[str, Any]] = None
    execution_status: str = "PENDING"
