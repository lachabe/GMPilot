"""Tests d'intégration/caractérisation de check_monitored_software (CPE Watch).

On exerce le chemin use_cache=True (réévaluation locale, sans réseau) sur une BDD
SQLite fichier temporaire (partageable entre connexions), en neutralisant
connect_db. Verrouille le comportement end-to-end avant refactor.
"""
import json
import sqlite3

import pytest

from app.db import SCHEMA_SQL
import app.blueprints.cache as C


@pytest.fixture
def cpe_db(tmp_path, monkeypatch):
    """BDD fichier temporaire + connect_db patché. Retourne un opener de connexion."""
    dbpath = str(tmp_path / "cpe.db")
    boot = sqlite3.connect(dbpath)
    boot.executescript(SCHEMA_SQL)
    boot.commit()
    boot.close()

    def _open():
        c = sqlite3.connect(dbpath)
        c.row_factory = sqlite3.Row
        return c

    monkeypatch.setattr("app.db.connect_db", _open)
    return _open


def _add_software(conn, vendor, product, version, host_ip="10.0.0.1"):
    conn.execute(
        "INSERT INTO monitored_software(cpe_type,vendor,product,version,host_ip,created_at) "
        "VALUES('a',?,?,?,?,'2026-01-01T00:00:00')", (vendor, product, version, host_ip))


def _add_cache(conn, vendor, product, entries, complete=1):
    conn.execute(
        "INSERT INTO cpe_watch_cache(vendor,product,complete,fetched_at,data) VALUES(?,?,?,?,?)",
        (vendor, product, complete, "2026-01-01T00:00:00", json.dumps(entries)))


ENTRY = {"cve": "CVE-2024-0001", "ranges": ["0 <2.0"], "score": 9.0, "desc": "bad"}


class TestCheckMonitoredSoftware:
    def test_cree_finding_si_version_affectee(self, cpe_db):
        c = cpe_db()
        _add_software(c, "acme", "widget", "1.0")
        _add_cache(c, "acme", "widget", [ENTRY])
        c.commit(); c.close()

        C.check_monitored_software(use_cache=True)

        chk = cpe_db()
        row = chk.execute("SELECT * FROM findings WHERE vendor='acme' AND product='widget'").fetchone()
        assert row is not None
        assert row["status"] == "active"
        assert row["match_confidence"] == "confirmed"
        assert row["primary_cve"] == "CVE-2024-0001"
        assert row["severity"] == 9.0
        # cache réévalué
        cache = chk.execute("SELECT evaluated_at FROM cpe_watch_cache WHERE vendor='acme'").fetchone()
        assert cache["evaluated_at"] is not None
        chk.close()

    def test_pas_de_finding_si_hors_plage(self, cpe_db):
        c = cpe_db()
        _add_software(c, "acme", "gadget", "3.0")            # 3.0 hors de "0 <2.0"
        _add_cache(c, "acme", "gadget", [ENTRY])
        c.commit(); c.close()

        C.check_monitored_software(use_cache=True)

        chk = cpe_db()
        assert chk.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        chk.close()

    def test_sans_cache_ignore(self, cpe_db):
        # use_cache=True + produit sans entrée cpe_watch_cache → ignoré, pas de finding.
        c = cpe_db()
        _add_software(c, "acme", "nocache", "1.0")
        c.commit(); c.close()

        C.check_monitored_software(use_cache=True)

        chk = cpe_db()
        assert chk.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        chk.close()

    def test_resout_finding_devenu_hors_plage(self, cpe_db):
        # Un finding actif existant, mais la version n'est plus affectée ce cycle → résolu.
        c = cpe_db()
        _add_software(c, "acme", "widget", "3.0")            # désormais hors "0 <2.0"
        _add_cache(c, "acme", "widget", [ENTRY])
        # finding actif pré-existant pour ce produit + la CVE évaluée
        c.execute("INSERT INTO vulnerabilities(oid,name,family,cvss_base,solution) "
                  "VALUES('cpe-watch:CVE-2024-0001:acme:widget','x','CPE Watch',9.0,'')")
        vid = c.execute("SELECT id FROM vulnerabilities WHERE oid LIKE 'cpe-watch:%'").fetchone()[0]
        c.execute("INSERT INTO findings(vuln_id,host_ip,port,severity,status,first_seen,last_seen,primary_cve,vendor,product) "
                  "VALUES(?,?, 'N/A',9.0,'active','2026-01-01','2026-01-01','CVE-2024-0001','acme','widget')",
                  (vid, "10.0.0.1"))
        c.commit(); c.close()

        C.check_monitored_software(use_cache=True)

        chk = cpe_db()
        row = chk.execute("SELECT status FROM findings WHERE vuln_id=?", (vid,)).fetchone()
        assert row["status"] == "resolved"
        chk.close()
