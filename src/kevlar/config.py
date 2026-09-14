from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path("data/kevlar.db")
    slack_webhook_url: str | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    nvd_api_key: str | None = None
    github_token: str | None = None
    monitored_assets: tuple[str, ...] = ()
    urgent_due_days: int = 14
    healthcheck_url: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        assets = tuple(x.strip().lower() for x in os.getenv("MONITORED_ASSETS", "").split(",") if x.strip())
        return cls(
            database_path=Path(os.getenv("DATABASE_PATH", "data/kevlar.db")),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
            jira_base_url=os.getenv("JIRA_BASE_URL") or None,
            jira_email=os.getenv("JIRA_EMAIL") or None,
            jira_api_token=os.getenv("JIRA_API_TOKEN") or None,
            jira_project_key=os.getenv("JIRA_PROJECT_KEY") or None,
            nvd_api_key=os.getenv("NVD_API_KEY") or None,
            github_token=os.getenv("GITHUB_TOKEN") or None,
            monitored_assets=assets,
            urgent_due_days=int(os.getenv("URGENT_DUE_DAYS", "14")),
            healthcheck_url=os.getenv("HEALTHCHECK_URL") or None,
        )
