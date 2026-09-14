import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import Mock

from pydantic import ValidationError

from kevlar.database import Database
from kevlar.models import Enrichment, Finding, KEVFeed, KEVItem
from kevlar.notifications import slack_payload
from kevlar.services import is_urgent, matches_assets


def item(**overrides):
    data = {"cveID": "CVE-2024-12345", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Acme Gateway RCE", "dateAdded": "2024-01-01", "dueDate": str(date.today() + timedelta(days=7)), "requiredAction": "Apply update"}
    data.update(overrides)
    return KEVItem.model_validate(data)


class EngineTests(unittest.TestCase):
    def test_feed_validation_rejects_malformed_cve(self):
        with self.assertRaises(ValidationError):
            KEVFeed.model_validate({"vulnerabilities": [{"cveID": "bad"}]})

    def test_asset_and_due_date_filters(self):
        finding = item()
        self.assertTrue(matches_assets(finding, ("acme",)))
        self.assertFalse(matches_assets(finding, ("microsoft",)))
        self.assertTrue(is_urgent(finding, 14))

    def test_database_tracks_notification_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "state.db")
            finding = Finding(kev=item(), enrichment=Enrichment(epss_score=.9), raw_json={})
            db.save_finding(finding)
            self.assertIn("CVE-2024-12345", db.known_cves())
            self.assertFalse(db.notified(finding.kev.cveID, "slack"))
            db.log_notification(finding.kev.cveID, "slack", "sent")
            self.assertTrue(db.notified(finding.kev.cveID, "slack"))
            db.close()

    def test_slack_message_contains_remediation_and_links(self):
        payload = slack_payload(Finding(kev=item(), enrichment=Enrichment(epss_score=.2), raw_json={}, urgent=True))
        text = str(payload)
        self.assertIn("Apply update", text)
        self.assertIn("nvd.nist.gov", text)

