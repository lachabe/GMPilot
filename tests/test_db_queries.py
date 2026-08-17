"""Tests de la couche requêtes/mapping de app.db (avec mem_db).

Couvre : query_active/resolved (+ _row_to_vuln), marquage FP, cache GMP, cache DNS.
"""
import pytest

from app.db import (
    query_active_findings, query_resolved_findings,
    mark_finding_false_positive, unmark_finding_false_positive,
    save_gmp_cache, read_gmp_cache,
    store_dns_results, set_dns_manual, dns_cached_ips, dns_manual_ips, dns_all_entries,
)


def _seed_vuln(mem_db, oid="1.2.3", name="NVT test"):
    mem_db.execute(
        "INSERT INTO vulnerabilities(oid,name,family,cvss_base,solution) VALUES(?,?,?,?,?)",
        (oid, name, "General", 5.0, "patch"))
    return mem_db.execute("SELECT id FROM vulnerabilities WHERE oid=?", (oid,)).fetchone()[0]


class TestQueries:
    def test_active_vs_resolved(self, mem_db, insert_finding, iso_statuses, stub_enrich_maps):
        vid = _seed_vuln(mem_db)
        insert_finding(vuln_id=vid, host_ip="10.0.0.1", port="443/tcp", status="active")
        insert_finding(vuln_id=vid, host_ip="10.0.0.2", port="80/tcp", status="resolved")
        active = query_active_findings(mem_db)
        resolved = query_resolved_findings(mem_db)
        assert {v["host"] if "host" in v else v["host_ip"] for v in active} == {"10.0.0.1"}
        assert len(active) == 1
        assert len(resolved) == 1

    def test_row_to_vuln_expose_statut(self, mem_db, insert_finding, iso_statuses, stub_enrich_maps):
        import json
        vid = _seed_vuln(mem_db)
        insert_finding(vuln_id=vid, status="in_progress",
                       status_data=json.dumps({"ticket_number": "TK9"}), status_at="2026-01-01")
        v = query_active_findings(mem_db)[0]
        assert v["status"] == "in_progress"
        assert v["status_data"]["ticket_number"] == "TK9"
        # rétro-compat exposée par _row_to_vuln
        assert v["ticket_number"] == "TK9"


class TestMarkFalsePositive:
    def test_marquage_et_annulation(self, mem_db, insert_finding):
        fid = insert_finding(status="active")
        assert mark_finding_false_positive(mem_db, fid, by="alice", reason="bénin") is True
        r = mem_db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        assert r["status"] == "false_positive"
        assert r["fp_by"] == "alice" and r["fp_reason"] == "bénin"
        assert r["resolved_at"] is not None
        # ré-appliquer sur un finding déjà FP ne fait rien (WHERE status!='false_positive')
        assert mark_finding_false_positive(mem_db, fid, by="bob") is False
        # annulation → retour à active
        assert unmark_finding_false_positive(mem_db, fid) is True
        r = mem_db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        assert r["status"] == "active" and r["fp_by"] is None


class TestGmpCache:
    def test_roundtrip(self, mem_db):
        save_gmp_cache(mem_db, "tasks", [{"id": "t1"}, {"id": "t2"}])
        assert read_gmp_cache(mem_db, "tasks") == [{"id": "t1"}, {"id": "t2"}]
        assert read_gmp_cache(mem_db, "absent") == []

    def test_replace(self, mem_db):
        save_gmp_cache(mem_db, "k", [1, 2, 3])
        save_gmp_cache(mem_db, "k", [9])
        assert read_gmp_cache(mem_db, "k") == [9]


class TestDnsCache:
    def test_resolution_auto(self, mem_db):
        n = store_dns_results(mem_db, [("10.0.0.1", "srv01"), ("10.0.0.2", None)])
        assert n == 2
        assert dns_cached_ips(mem_db) == {"10.0.0.1", "10.0.0.2"}

    def test_manuel_non_ecrase_par_auto(self, mem_db):
        # Une saisie manuelle ne doit jamais être écrasée par une résolution auto.
        set_dns_manual(mem_db, "10.0.0.5", "manuel.local")
        assert dns_manual_ips(mem_db) == {"10.0.0.5"}
        store_dns_results(mem_db, [("10.0.0.5", "auto.local")])
        entry = [e for e in dns_all_entries(mem_db) if e["ip"] == "10.0.0.5"][0]
        assert entry["hostname"] == "manuel.local"   # préservé
        assert entry["manual"] == 1
