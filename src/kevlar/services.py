from __future__ import annotations

from datetime import date
from urllib.parse import quote

from .http import HttpClient
from .models import Enrichment, KEVFeed, KEVItem

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev(client: HttpClient) -> tuple[KEVFeed, dict]:
    payload = client.get_json(KEV_URL)
    return KEVFeed.model_validate(payload), payload


class Enricher:
    def __init__(self, client: HttpClient, nvd_api_key: str | None = None, github_token: str | None = None) -> None:
        self.client, self.nvd_api_key, self.github_token = client, nvd_api_key, github_token

    def enrich(self, item: KEVItem) -> Enrichment:
        result = Enrichment()
        for operation in (self._epss, self._nvd, self._github):
            try:
                operation(item.cveID, result)
            except Exception as exc:  # Individual enrichments must never stop alerts.
                result.errors.append(f"{operation.__name__[1:]}: {exc}")
        return result

    def _epss(self, cve: str, result: Enrichment) -> None:
        records = self.client.get_json(f"https://api.first.org/data/v1/epss?cve={quote(cve)}").get("data", [])
        if records:
            result.epss_score = float(records[0]["epss"])
            result.epss_percentile = float(records[0]["percentile"])

    def _nvd(self, cve: str, result: Enrichment) -> None:
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        data = self.client.get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve)}", headers=headers)
        metrics = data.get("vulnerabilities", [{}])[0].get("cve", {}).get("metrics", {})
        for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(name):
                cvss = metrics[name][0]["cvssData"]
                result.cvss_score, result.cvss_vector = float(cvss["baseScore"]), cvss["vectorString"]
                break

    def _github(self, cve: str, result: Enrichment) -> None:
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        data = self.client.get_json(f"https://api.github.com/search/code?q={quote(cve)}+in:file", headers=headers)
        result.public_poc_links = [x["html_url"] for x in data.get("items", [])[:5]]
        # Nuclei templates are indexed on GitHub; a CVE hit is an actionable availability signal.
        result.nuclei_available = any("nuclei-templates" in x for x in result.public_poc_links)


def matches_assets(item: KEVItem, keywords: tuple[str, ...]) -> bool:
    if not keywords:
        return True
    searchable = f"{item.vendorProject} {item.product} {item.vulnerabilityName}".lower()
    return any(keyword in searchable for keyword in keywords)


def is_urgent(item: KEVItem, days: int) -> bool:
    return item.dueDate is not None and 0 <= (item.dueDate - date.today()).days <= days
