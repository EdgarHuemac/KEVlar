from __future__ import annotations

from .http import HttpClient
from .models import Finding


def _links(cve: str) -> str:
    return f"<https://www.cisa.gov/known-exploited-vulnerabilities-catalog|CISA KEV> · <https://nvd.nist.gov/vuln/detail/{cve}|NVD>"


def slack_payload(finding: Finding) -> dict:
    k, e = finding.kev, finding.enrichment
    urgency = "URGENT" if finding.urgent else "NEW KEV"
    epss = f"{e.epss_score:.1%}" if e.epss_score is not None else "unavailable"
    due = str(k.dueDate) if k.dueDate else "not specified"
    return {"attachments": [{"color": "#d40e0d" if finding.urgent else "#f2c744", "blocks": [
        {"type": "header", "text": {"type": "plain_text", "text": f"{urgency}: {k.cveID}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{k.vendorProject} {k.product}* — {k.vulnerabilityName}\n*EPSS:* {epss}  |  *CVSS:* {e.cvss_score or 'unavailable'}  |  *Due:* {due}\n{_links(k.cveID)}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Required action:* {k.requiredAction}"}},
    ]}]}


def send_slack(client: HttpClient, webhook: str, finding: Finding) -> None:
    client.post_json(webhook, slack_payload(finding))


def jira_payload(finding: Finding, project_key: str) -> dict:
    k, e = finding.kev, finding.enrichment
    return {"fields": {"project": {"key": project_key}, "summary": f"[{k.cveID}] CISA KEV: {k.vendorProject} {k.product}", "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": f"{k.vulnerabilityName}\nRequired action: {k.requiredAction}\nEPSS: {e.epss_score}\nNVD: https://nvd.nist.gov/vuln/detail/{k.cveID}"}]}]}, "labels": ["cisa-kev", "critical-exploit"], "duedate": str(k.dueDate) if k.dueDate else None}}


def send_jira(client: HttpClient, base_url: str, email: str, token: str, project: str, finding: Finding) -> None:
    client.post_json(base_url.rstrip("/") + "/rest/api/3/issue", jira_payload(finding, project), auth=(email, token), headers={"Accept": "application/json"})
