from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class KEVItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    cveID: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: date
    dueDate: date | None = None
    requiredAction: str = ""
    knownRansomwareCampaignUse: str | None = None


class KEVFeed(BaseModel):
    vulnerabilities: list[KEVItem]


class Enrichment(BaseModel):
    epss_score: float | None = None
    epss_percentile: float | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    public_poc_links: list[str] = Field(default_factory=list)
    nuclei_available: bool = False
    errors: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    kev: KEVItem
    enrichment: Enrichment
    raw_json: dict[str, Any]
    urgent: bool = False
