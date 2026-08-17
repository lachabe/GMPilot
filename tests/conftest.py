"""Fixtures partagées de la suite de tests GMPilot.

Convention (à réutiliser à chaque nouvelle implémentation) :
  - On teste en priorité la LOGIQUE PURE et les fonctions qui acceptent une
    connexion explicite — sans booter Flask, sans lire le .env, sans GVM/réseau.
  - Une BDD SQLite en mémoire par test via `mem_db` (schéma réel appliqué).
  - La config de statuts est isolée dans un fichier temporaire via `iso_statuses`
    → load/save hermétiques, jamais le vrai config/statuses.json.

Ajouter un test = déposer un fichier tests/test_<domaine>.py qui réutilise ces
fixtures. Voir tests/README.md.
"""
import sqlite3

import pytest

# Neutralise load_dotenv AVANT tout import de app.* : garantit des tests
# hermétiques (aucune dépendance au .env réel) et respecte la règle « ne jamais
# lire le .env ». app.config fait load_dotenv(override=True) à l'import ; on le
# remplace par un no-op pour que la config s'appuie sur os.environ + défauts.
import dotenv as _dotenv
_dotenv.load_dotenv = lambda *a, **k: False

from app.db import SCHEMA_SQL


@pytest.fixture
def mem_db():
    """Connexion SQLite en mémoire avec le schéma complet appliqué.

    Les clés étrangères restent OFF (défaut SQLite) : on peut insérer un finding
    sans ligne vulnerabilities correspondante, ce qui simplifie les tests de statut.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def insert_finding(mem_db):
    """Insère un finding minimal (colonnes NOT NULL renseignées) et renvoie son id."""
    def _insert(**kw):
        row = {
            "vuln_id": kw.get("vuln_id", 1),
            "host_ip": kw.get("host_ip", "10.0.0.1"),
            "port": kw.get("port", "443/tcp"),
            "severity": kw.get("severity", 7.5),
            "first_seen": kw.get("first_seen", "2026-01-01T00:00:00"),
            "last_seen": kw.get("last_seen", "2026-01-01T00:00:00"),
            "status": kw.get("status", "active"),
            "status_data": kw.get("status_data"),
            "status_by": kw.get("status_by"),
            "status_at": kw.get("status_at"),
            "resolved_at": kw.get("resolved_at"),
            "ticket_number": kw.get("ticket_number"),
        }
        cols = ",".join(row.keys())
        ph = ",".join("?" * len(row))
        cur = mem_db.execute(f"INSERT INTO findings({cols}) VALUES({ph})", list(row.values()))
        mem_db.commit()
        return cur.lastrowid
    return _insert


@pytest.fixture
def stub_enrich_maps(monkeypatch):
    """Neutralise les enrichissements de _row_to_vuln (hostname DNS + service IANA).

    hostname_for()/iana_service_for() chargent des maps via connect_db() (→ contexte
    Flask + vraie BDD). On les remplace par des maps vides pour tester les requêtes
    sur mem_db sans booter l'app.
    """
    import app.db as _db
    monkeypatch.setattr(_db, "_load_dns_map", lambda: {})
    monkeypatch.setattr(_db, "_load_iana_map", lambda: {})


@pytest.fixture
def iso_statuses(tmp_path, monkeypatch):
    """Isole la config de statuts dans un fichier temporaire.

    Sans fichier écrit, load_statuses() renvoie les statuts intégrés par défaut
    (active / in_progress / false_positive / resolved), ce qui suffit à la
    plupart des tests. Retourne le chemin pour les cas save→load.
    """
    import app.statuses as st
    path = tmp_path / "statuses.json"
    monkeypatch.setattr(st, "_path", lambda: str(path))
    return path
