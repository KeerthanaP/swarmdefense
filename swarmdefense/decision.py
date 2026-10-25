from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"
