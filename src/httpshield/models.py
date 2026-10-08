from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NA = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    severity: Severity
    score: int
    evidence: str
    remediation: str
    category: str = "HTTP"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "score": self.score,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
            "metadata": self.metadata,
        }


@dataclass
class HttpResponseData:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    set_cookies: list[str]
    redirects: list[str]
    elapsed_ms: int

    @property
    def is_https(self) -> bool:
        return self.final_url.lower().startswith("https://")
