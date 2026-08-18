"""Tests de app.db.set_findings_status et des helpers de clause IN.

Cœur de la feature « partage de valeur entre statuts » : status_data est fusionné
(json_patch) sauf pour le statut de base qui réinitialise le contexte.
"""
import json


from app.db import (
    set_findings_status,
    _status_in_clause,
    _status_in_literal,
)


def _row(mem_db, fid):
    return mem_db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()


class TestSetFindingsStatus:
    def test_report_valeur_vers_statut_ferme(self, mem_db, insert_finding, iso_statuses):
        # En cours (ticket) → Résolu : le ticket doit suivre, resolved_at renseigné.
        fid = insert_finding(status="in_progress",
                             status_data=json.dumps({"ticket_number": "51422"}),
                             status_at="2026-01-01T00:00:00")
        n = set_findings_status(mem_db, [fid], "resolved", data={}, by="tester")
        assert n == 1
        r = _row(mem_db, fid)
        assert r["status"] == "resolved"
        assert json.loads(r["status_data"])["ticket_number"] == "51422"
        assert r["resolved_at"] is not None
        assert r["status_by"] == "tester"

    def test_fusion_ajoute_cle_sans_perdre_lancienne(self, mem_db, insert_finding, iso_statuses):
        fid = insert_finding(status="in_progress",
                             status_data=json.dumps({"ticket_number": "51422"}),
                             status_at="2026-01-01T00:00:00")
        set_findings_status(mem_db, [fid], "false_positive", data={"reason": "bénin"}, by="a")
        data = json.loads(_row(mem_db, fid)["status_data"])
        assert data["ticket_number"] == "51422"   # conservé
        assert data["reason"] == "bénin"           # ajouté

    def test_override_meme_cle(self, mem_db, insert_finding, iso_statuses):
        fid = insert_finding(status="in_progress",
                             status_data=json.dumps({"ticket_number": "1"}),
                             status_at="2026-01-01T00:00:00")
        set_findings_status(mem_db, [fid], "in_progress", data={"ticket_number": "2"}, by="a")
        r = _row(mem_db, fid)
        assert json.loads(r["status_data"])["ticket_number"] == "2"
        assert r["resolved_at"] is None            # scope 'open' → pas de resolved_at

    def test_statut_de_base_reinitialise(self, mem_db, insert_finding, iso_statuses):
        # Réouverture (active = base) : contexte vidé, pas de report de ticket.
        fid = insert_finding(status="in_progress",
                             status_data=json.dumps({"ticket_number": "51422"}),
                             status_at="2026-01-01T00:00:00",
                             resolved_at="2026-02-01T00:00:00")
        set_findings_status(mem_db, [fid], "active", data={}, by="a")
        r = _row(mem_db, fid)
        assert r["status"] == "active"
        assert r["status_data"] is None
        assert r["resolved_at"] is None

    def test_anciennes_colonnes_videes(self, mem_db, insert_finding, iso_statuses):
        fid = insert_finding(status="active", ticket_number="OLD")
        set_findings_status(mem_db, [fid], "resolved", data={}, by="a")
        r = _row(mem_db, fid)
        assert r["ticket_number"] is None
        assert r["fp_reason"] is None

    def test_multi_findings_rowcount(self, mem_db, insert_finding, iso_statuses):
        f1 = insert_finding(port="80/tcp")
        f2 = insert_finding(port="443/tcp")
        assert set_findings_status(mem_db, [f1, f2], "resolved", data={}, by="a") == 2

    def test_ids_vides_renvoie_zero(self, mem_db, iso_statuses):
        assert set_findings_status(mem_db, [], "resolved") == 0

    def test_statut_inconnu_renvoie_zero(self, mem_db, insert_finding, iso_statuses):
        fid = insert_finding()
        assert set_findings_status(mem_db, [fid], "statut_bidon", data={}) == 0
        assert _row(mem_db, fid)["status"] == "active"   # inchangé


class TestClauseHelpers:
    def test_in_clause_vide_ne_matche_rien(self):
        frag, params = _status_in_clause([])
        assert frag == "IN ('__none__')"
        assert params == []

    def test_in_clause_placeholders(self):
        frag, params = _status_in_clause(["active", "in_progress"])
        assert frag == "IN (?,?)"
        assert params == ["active", "in_progress"]

    def test_in_literal_vide(self):
        assert _status_in_literal([]) == "IN ('__none__')"

    def test_in_literal_valeurs(self):
        assert _status_in_literal(["active", "in_progress"]) == "IN ('active','in_progress')"
