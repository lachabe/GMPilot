"""Tests de app.db.import_gmp_results et resolve_stale_findings.

Logique la plus sensible du cycle de scan :
  - import_gmp_results : upsert vuln/finding/sighting, avec préservation des statuts
    « collants » (sticky) à la réapparition et MAX sur la sévérité.
  - resolve_stale_findings : auto-résolution des findings disparus, uniquement pour
    les statuts « auto-résolution » et si aucune autre tâche ne les voit encore.
"""
import xml.etree.ElementTree as ET


from app.db import import_gmp_results, resolve_stale_findings


def make_results(results):
    """Construit un XML GMP get_results minimal depuis une liste de dicts."""
    parts = []
    for r in results:
        cve_refs = "".join(f'<ref type="cve" id="{c}"/>' for c in r.get("cves", []))
        oid_attr = f' oid="{r["oid"]}"' if r.get("oid") is not None else ""
        parts.append(f"""
        <result>
          <severity>{r.get("severity", 7.5)}</severity>
          <host>{r.get("host", "10.0.0.5")}</host>
          <port>{r.get("port", "443/tcp")}</port>
          <threat>{r.get("threat", "High")}</threat>
          <qod><value>{r.get("qod", 80)}</value></qod>
          <description>{r.get("description", "desc")}</description>
          <nvt{oid_attr}>
            <name>{r.get("name", "Test NVT")}</name>
            <family>{r.get("family", "General")}</family>
            <cvss_base>{r.get("cvss_base", 5.0)}</cvss_base>
            <solution>{r.get("solution", "patch")}</solution>
            <refs>{cve_refs}</refs>
          </nvt>
        </result>""")
    return ET.fromstring(f"<results>{''.join(parts)}</results>")


def _import(conn, results, task_id="A", task_name="Task A", report_id="r1", scan_date="2026-03-01T00:00:00"):
    xml = make_results(results)
    return import_gmp_results(conn, xml, task_id, task_name, report_id, scan_date)


def _finding(conn, oid="1.2.3", host="10.0.0.5", port="443/tcp"):
    return conn.execute(
        "SELECT f.* FROM findings f JOIN vulnerabilities v ON f.vuln_id=v.id "
        "WHERE v.oid=? AND f.host_ip=? AND f.port=?", (oid, host, port),
    ).fetchone()


class TestImport:
    def test_import_de_base(self, mem_db, iso_statuses):
        seen, count = _import(mem_db, [{"oid": "1.2.3", "severity": 7.5, "cves": ["CVE-2024-0001"]}])
        assert count == 1
        assert len(seen) == 1
        f = _finding(mem_db)
        assert f["status"] == "active"
        assert f["severity"] == 7.5
        assert f["primary_cve"] == "CVE-2024-0001"
        # vulnérabilité + sighting + lien CVE créés
        assert mem_db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0] == 1
        assert mem_db.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 1
        assert mem_db.execute(
            "SELECT COUNT(*) FROM vuln_cves WHERE cve_id=?", ("CVE-2024-0001",)
        ).fetchone()[0] == 1

    def test_severite_negligeable_ignoree(self, mem_db, iso_statuses):
        _, count = _import(mem_db, [{"oid": "1.2.3", "severity": 0.0}])
        assert count == 0
        assert mem_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0

    def test_oid_manquant_ignore(self, mem_db, iso_statuses):
        _, count = _import(mem_db, [{"severity": 9.0}])   # pas d'oid
        assert count == 0

    def test_reimport_preserve_statut_collant(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3"}])
        fid = _finding(mem_db)["id"]
        # Simule un finding faux positif (sticky, fermé) avec resolved_at.
        mem_db.execute(
            "UPDATE findings SET status='false_positive', resolved_at='2026-06-01' WHERE id=?", (fid,))
        mem_db.commit()
        # Réapparition au scan suivant.
        _import(mem_db, [{"oid": "1.2.3"}], report_id="r2", scan_date="2026-07-01T00:00:00")
        f = _finding(mem_db)
        assert f["status"] == "false_positive"          # préservé
        assert f["resolved_at"] == "2026-06-01"          # préservé
        assert f["last_seen"] == "2026-07-01T00:00:00"   # mis à jour

    def test_reimport_reactive_statut_non_collant(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3"}])
        fid = _finding(mem_db)["id"]
        mem_db.execute(
            "UPDATE findings SET status='resolved', resolved_at='2026-06-01' WHERE id=?", (fid,))
        mem_db.commit()
        _import(mem_db, [{"oid": "1.2.3"}], report_id="r2")
        f = _finding(mem_db)
        assert f["status"] == "active"        # réactivé
        assert f["resolved_at"] is None       # remis à zéro

    def test_severite_prend_le_max(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3", "severity": 5.0}])
        _import(mem_db, [{"oid": "1.2.3", "severity": 8.0}], report_id="r2")
        assert _finding(mem_db)["severity"] == 8.0
        _import(mem_db, [{"oid": "1.2.3", "severity": 3.0}], report_id="r3")
        assert _finding(mem_db)["severity"] == 8.0   # ne redescend pas


class TestResolveStale:
    def test_finding_disparu_auto_resolu(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3"}])
        n = resolve_stale_findings(mem_db, "A", seen_finding_ids=set(), resolved_at="2026-08-01")
        assert n == 1
        f = _finding(mem_db)
        assert f["status"] == "resolved"
        assert f["resolved_at"] == "2026-08-01"

    def test_statut_non_auto_resolu_preserve(self, mem_db, iso_statuses):
        # Un faux positif disparu ne doit PAS être auto-résolu (non auto_resolve).
        _import(mem_db, [{"oid": "1.2.3"}])
        fid = _finding(mem_db)["id"]
        mem_db.execute("UPDATE findings SET status='false_positive' WHERE id=?", (fid,))
        mem_db.commit()
        resolve_stale_findings(mem_db, "A", seen_finding_ids=set())
        assert _finding(mem_db)["status"] == "false_positive"   # état BDD = autoritaire

    def test_finding_encore_vu_intact(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3"}])
        fid = _finding(mem_db)["id"]
        n = resolve_stale_findings(mem_db, "A", seen_finding_ids={fid})
        assert n == 0
        assert _finding(mem_db)["status"] == "active"

    def test_autre_tache_maintient_le_finding(self, mem_db, iso_statuses):
        _import(mem_db, [{"oid": "1.2.3"}], task_id="A", report_id="rA")
        fid = _finding(mem_db)["id"]
        # Tâche B voit encore ce finding dans son dernier rapport rB.
        mem_db.execute(
            "INSERT INTO scan_imports(task_id,task_name,report_id,scan_date,imported_at,results_count) "
            "VALUES('B','Task B','rB','2026-03-02','2026-03-02T10:00:00',1)")
        mem_db.execute(
            "INSERT INTO sightings(finding_id,task_id,task_name,report_id,scan_date) "
            "VALUES(?,'B','Task B','rB','2026-03-02')", (fid,))
        mem_db.commit()
        n = resolve_stale_findings(mem_db, "A", seen_finding_ids=set())
        assert n == 0
        assert _finding(mem_db)["status"] == "active"   # maintenu par B
