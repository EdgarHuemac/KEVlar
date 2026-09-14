from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Enrichment, Finding, KEVItem


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def _migrate(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          cve_id TEXT PRIMARY KEY, vendor TEXT NOT NULL, product TEXT NOT NULL,
          vulnerability_name TEXT NOT NULL, cisa_date_added TEXT NOT NULL,
          cisa_due_date TEXT, cisa_action TEXT NOT NULL, raw_json TEXT NOT NULL,
          first_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS enrichment_data (
          cve_id TEXT PRIMARY KEY REFERENCES vulnerabilities(cve_id), epss_score REAL,
          epss_percentile REAL, cvss_score REAL, cvss_vector TEXT, public_poc_links TEXT NOT NULL,
          nuclei_available INTEGER NOT NULL DEFAULT 0, errors TEXT NOT NULL, last_updated TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notifications_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
          channel TEXT NOT NULL, timestamp TEXT NOT NULL, delivery_status TEXT NOT NULL, detail TEXT,
          UNIQUE(cve_id, channel)
        );
        """)
        self.conn.commit()

    def known_cves(self) -> set[str]:
        return {row[0] for row in self.conn.execute("SELECT cve_id FROM vulnerabilities")}

    def save_finding(self, finding: Finding) -> None:
        k, e = finding.kev, finding.enrichment
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""INSERT OR IGNORE INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (k.cveID, k.vendorProject, k.product, k.vulnerabilityName, str(k.dateAdded), str(k.dueDate) if k.dueDate else None, k.requiredAction, json.dumps(finding.raw_json), now))
        self.conn.execute("""INSERT INTO enrichment_data VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(cve_id) DO UPDATE SET epss_score=excluded.epss_score, epss_percentile=excluded.epss_percentile, cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector, public_poc_links=excluded.public_poc_links, nuclei_available=excluded.nuclei_available, errors=excluded.errors, last_updated=excluded.last_updated""",
            (k.cveID, e.epss_score, e.epss_percentile, e.cvss_score, e.cvss_vector, json.dumps(e.public_poc_links), int(e.nuclei_available), json.dumps(e.errors), now))
        self.conn.commit()

    def notified(self, cve_id: str, channel: str) -> bool:
        return self.conn.execute("SELECT 1 FROM notifications_log WHERE cve_id=? AND channel=?", (cve_id, channel)).fetchone() is not None

    def log_notification(self, cve_id: str, channel: str, status: str, detail: str = "") -> None:
        self.conn.execute("INSERT OR REPLACE INTO notifications_log(cve_id,channel,timestamp,delivery_status,detail) VALUES (?, ?, ?, ?, ?)", (cve_id, channel, datetime.now(timezone.utc).isoformat(), status, detail[:1000]))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
