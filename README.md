# KEVlar

KEVlar is an automated CISA Known Exploited Vulnerabilities (KEV) monitor. It stores state in SQLite, detects new CISA entries, enriches them with EPSS, NVD CVSS, and public GitHub PoC signals, then sends deduplicated Slack and/or Jira alerts.

## Quick start

Requires Python 3.11+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Configure environment variables in your shell (see .env.example), then:
$env:PYTHONPATH = "src"
python -m kevlar.cli --dry-run --all
```

The application deliberately does not parse `.env` files, keeping secret loading explicit. In PowerShell, for example, use `$env:SLACK_WEBHOOK_URL = "https://hooks.slack.com/..."`. For production, configure secrets in the scheduler rather than storing them in a file.

## Configuration

| Variable | Purpose |
|---|---|
| `DATABASE_PATH` | SQLite state file; defaults to `data/kevlar.db`. |
| `MONITORED_ASSETS` | Comma-separated terms matched against vendor, product, and title. Empty alerts for every new KEV. |
| `URGENT_DUE_DAYS` | Due-date window for urgent alerts; defaults to 14. |
| `SLACK_WEBHOOK_URL` | Enables Slack incoming-webhook alerts. |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Together enable Jira Cloud issue creation. |
| `NVD_API_KEY` | Optional NVD API key to improve rate limits. |
| `GITHUB_TOKEN` | Optional token for GitHub code-search PoC discovery. |
| `HEALTHCHECK_URL` | Optional Healthchecks.io ping endpoint, called after a successful run. |

## Behavior and safety

- Default execution processes only CVEs never persisted in SQLite. `--all` reprocesses every feed record; notification logs still prevent duplicate channel sends.
- `--dry-run` makes no database writes and sends no alerts; it emits structured JSON findings instead.
- Failed EPSS, NVD, or GitHub calls are recorded on the finding and do not prevent CISA remediation alerts. HTTP requests retry three times with exponential backoff.
- Slack and Jira delivery outcomes are stored in `notifications_log`. A previous failed delivery is retried on the next run; a successful channel delivery is not duplicated.

## Automation

`.github/workflows/monitor.yml` runs hourly and commits `data/kevlar.db` back to the repository to preserve state. Add the listed secrets in GitHub Actions and set `MONITORED_ASSETS` as a repository variable. A scheduled GitHub workflow is disabled automatically in repositories with no activity for extended periods; use a durable database/volume plus your preferred scheduler for critical production monitoring.

To run as a container:

```powershell
docker build -t kevlar .
docker run --rm -v "${PWD}/data:/app/data" -e MONITORED_ASSETS="Microsoft,Cisco" kevlar
```

## Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```
