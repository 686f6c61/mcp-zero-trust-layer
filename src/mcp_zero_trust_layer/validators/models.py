from __future__ import annotations

from pydantic import BaseModel, Field


class ValidatorResult(BaseModel):
    passed: bool
    errors: list[str] = Field(default_factory=list)

    @classmethod
    def ok(cls) -> "ValidatorResult":
        return cls(passed=True)

    @classmethod
    def fail(cls, message: str) -> "ValidatorResult":
        return cls(passed=False, errors=[message])

