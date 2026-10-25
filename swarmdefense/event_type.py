from enum import Enum


class EventType(str, Enum):
    MESSAGE = "message"
    TOOL_PROPOSAL = "tool_proposal"
    TOOL_EXECUTION = "tool_execution"
    SECURITY_VERDICT = "security_verdict"
    AGENT_QUARANTINE = "agent_quarantine"
