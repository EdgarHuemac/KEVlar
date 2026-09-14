from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import Settings
from .database import Database
from .http import HttpClient
from .models import Finding
from .notifications import send_jira, send_slack
from .services import Enricher, fetch_kev, is_urgent, matches_assets


def log(event: str, **data: object) -> None:
    print(json.dumps({"event": event, **data}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor new CISA KEV vulnerabilities")
    parser.add_argument("--dry-run", action="store_true", help="Do not send notifications or persist data")
    parser.add_argument("--all", action="store_true", help="Process all feed records, not just records new to the database")
    args = parser.parse_args()
    settings, client = Settings.from_env(), HttpClient()
    db = Database(settings.database_path)
    try:
        feed, raw = fetch_kev(client)
        known = db.known_cves()
        candidates = [x for x in feed.vulnerabilities if (args.all or x.cveID not in known) and matches_assets(x, settings.monitored_assets)]
        log("feed_processed", total=len(feed.vulnerabilities), candidates=len(candidates), dry_run=args.dry_run)
        enricher = Enricher(client, settings.nvd_api_key, settings.github_token)
        for item in candidates:
            finding = Finding(kev=item, enrichment=enricher.enrich(item), raw_json=item.model_dump(mode="json"), urgent=is_urgent(item, settings.urgent_due_days))
            if args.dry_run:
                log("finding", cve=item.cveID, urgent=finding.urgent, enrichment=finding.enrichment.model_dump())
                continue
            db.save_finding(finding)
            if settings.slack_webhook_url and not db.notified(item.cveID, "slack"):
                try:
                    send_slack(client, settings.slack_webhook_url, finding); db.log_notification(item.cveID, "slack", "sent")
                except Exception as exc: db.log_notification(item.cveID, "slack", "failed", str(exc)); log("notification_failed", cve=item.cveID, channel="slack", error=str(exc))
            if all((settings.jira_base_url, settings.jira_email, settings.jira_api_token, settings.jira_project_key)) and not db.notified(item.cveID, "jira"):
                try:
                    send_jira(client, settings.jira_base_url, settings.jira_email, settings.jira_api_token, settings.jira_project_key, finding); db.log_notification(item.cveID, "jira", "sent")
                except Exception as exc: db.log_notification(item.cveID, "jira", "failed", str(exc)); log("notification_failed", cve=item.cveID, channel="jira", error=str(exc))
        if settings.healthcheck_url and not args.dry_run:
            client.request("GET", settings.healthcheck_url)
        log("run_complete", processed=len(candidates))
        return 0
    except Exception as exc:
        log("run_failed", error=str(exc)); return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
