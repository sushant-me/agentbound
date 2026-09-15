"""Finding dataclass shared by the engine and CLI."""

from dataclasses import dataclass, asdict


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str

    def to_dict(self) -> dict:
        return asdict(self)
