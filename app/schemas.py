import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from . import resource_validation


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Credentials(Input):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("email")
    @classmethod
    def email_valid(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Valid email required")
        return value


class Project(Input):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    technology: str = Field(default="", max_length=120)
    environment: Literal["development", "staging", "production"] = "development"

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, value):
        return resource_validation.nonblank(value)


class Repository(Input):
    project_id: str = Field(min_length=1, max_length=128)
    url: str = Field(max_length=300)
    branch: str = Field(default="main", min_length=1, max_length=128)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value):
        return resource_validation.repository_url(value)

    @field_validator("branch")
    @classmethod
    def valid_branch(cls, value):
        return resource_validation.repository_branch(value)

    @field_validator("project_id")
    @classmethod
    def nonblank_project(cls, value):
        return resource_validation.nonblank(value)


class Scan(Input):
    repository_id: str
    policy_id: str | None = None


class FindingUpdate(Input):
    status: Literal["open", "resolved", "ignored"]
    reason: str = Field(min_length=3, max_length=2000)


class Policy(Input):
    name: str = Field(min_length=1, max_length=120)
    critical: Literal["BLOCK", "WARN", "ALLOW"] = "BLOCK"
    high: Literal["BLOCK", "WARN", "ALLOW"] = "BLOCK"
    medium: Literal["BLOCK", "WARN", "ALLOW"] = "WARN"
    low: Literal["BLOCK", "WARN", "ALLOW"] = "ALLOW"
    informational: Literal["BLOCK", "WARN", "ALLOW"] = "ALLOW"
    scanner_failure: Literal["BLOCK", "WARN"] = "BLOCK"


class Deployment(Input):
    scan_id: str
    version: str = Field(min_length=1, max_length=120)
    environment: Literal["development", "staging", "production"] = "production"
