"""Tests de app.db._migrate_schema — migration idempotente du schéma findings.

On simule un ancien schéma findings (sans status_data/by/at) portant des données
FP/traitement héritées, puis on vérifie l'ajout des colonnes et la reprise one-shot
vers status_data/status_by/status_at.
"""
import json
import sqlite3

import pytest

from app.db import _migrate_schema


OLD_FINDINGS = """
CREATE TABLE findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    status        TEXT,
    ticket_number TEXT,
    treatment_by  TEXT,
    treatment_at  TEXT,
    fp_reason     TEXT,
    fp_by         TEXT,
    fp_at         TEXT
);
"""


@pytest.fixture
def old_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(OLD_FINDINGS)
    conn.execute(
        "INSERT INTO findings(status, ticket_number, treatment_by, treatment_at) "
        "VALUES('in_progress','TK1','alice','2026-01-01')"
    )
    conn.execute(
        "INSERT INTO findings(status, fp_reason, fp_by, fp_at) "
        "VALUES('false_positive','bénin','bob','2026-02-02')"
    )
    conn.execute("INSERT INTO findings(status) VALUES('active')")
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


def _cols(conn):
    return {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}


def _by_status(conn, status):
    return conn.execute("SELECT * FROM findings WHERE status=?", (status,)).fetchone()


def test_ajoute_colonnes_manquantes(old_db):
    _migrate_schema(old_db)
    for col in ("status_data", "status_by", "status_at", "match_confidence", "match_range"):
        assert col in _cols(old_db)


def test_reprise_in_progress(old_db):
    _migrate_schema(old_db)
    r = _by_status(old_db, "in_progress")
    assert json.loads(r["status_data"]) == {"ticket_number": "TK1"}
    assert r["status_by"] == "alice"
    assert r["status_at"] == "2026-01-01"


def test_reprise_false_positive(old_db):
    _migrate_schema(old_db)
    r = _by_status(old_db, "false_positive")
    assert json.loads(r["status_data"]) == {"reason": "bénin"}
    assert r["status_by"] == "bob"
    assert r["status_at"] == "2026-02-02"


def test_active_non_migre(old_db):
    _migrate_schema(old_db)
    r = _by_status(old_db, "active")
    assert r["status_data"] is None
    assert r["status_at"] is None


def test_idempotent(old_db):
    _migrate_schema(old_db)
    snap = {r["id"]: (r["status_data"], r["status_by"], r["status_at"])
            for r in old_db.execute("SELECT * FROM findings")}
    # Deuxième passe : status_at non NULL → aucune re-migration, valeurs stables.
    _migrate_schema(old_db)
    snap2 = {r["id"]: (r["status_data"], r["status_by"], r["status_at"])
             for r in old_db.execute("SELECT * FROM findings")}
    assert snap == snap2
