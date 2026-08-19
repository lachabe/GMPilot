"""SQLite storage for GMPilot — replaces file-based caches for perf-critical data."""
import os
import json
import logging
from datetime import datetime

from flask import g, current_app

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hosts (
    id        TEXT,
    ip        TEXT PRIMARY KEY,
    name      TEXT,
    os        TEXT,
    severity  REAL DEFAULT 0,
    last_seen TEXT,
    comment   TEXT
);

CREATE TABLE IF NOT EXISTS host_tags (
    host_ip   TEXT NOT NULL,
    tag_name  TEXT NOT NULL,
    PRIMARY KEY (host_ip, tag_name)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    oid       TEXT UNIQUE NOT NULL,
    name      TEXT NOT NULL,
    family    TEXT,
    cvss_base REAL,
    solution  TEXT,
    solution_type TEXT,
    summary   TEXT
);

CREATE TABLE IF NOT EXISTS vuln_cves (
    vuln_id   INTEGER NOT NULL REFERENCES vulnerabilities(id),
    cve_id    TEXT NOT NULL,
    PRIMARY KEY (vuln_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_cves_cve ON vuln_cves(cve_id);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id         INTEGER NOT NULL REFERENCES vulnerabilities(id),
    host_ip         TEXT NOT NULL,
    port            TEXT NOT NULL,
    severity        REAL NOT NULL,
    qod             INTEGER DEFAULT 0,
    threat          TEXT,
    description     TEXT,
    primary_cve     TEXT,
    vendor          TEXT,
    product         TEXT,
    epss            REAL,
    is_exploited    INTEGER DEFAULT 0,
    exploited_since TEXT,
    anssi_level     TEXT DEFAULT 'none',
    ctx_score       REAL DEFAULT 0,
    score_details   TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    resolved_at     TEXT,
    fp_reason       TEXT,
    fp_by           TEXT,
    fp_at           TEXT,
    match_confidence TEXT,
    match_range     TEXT,
    ticket_number   TEXT,
    treatment_by    TEXT,
    treatment_at    TEXT,
    status_data     TEXT,
    status_by       TEXT,
    status_at       TEXT,
    UNIQUE(vuln_id, host_ip, port)
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_host   ON findings(host_ip);
CREATE INDEX IF NOT EXISTS idx_findings_score  ON findings(ctx_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity DESC);

CREATE TABLE IF NOT EXISTS sightings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    task_id     TEXT NOT NULL,
    task_name   TEXT,
    report_id   TEXT NOT NULL,
    scan_date   TEXT NOT NULL,
    UNIQUE(finding_id, report_id)
);
CREATE INDEX IF NOT EXISTS idx_sightings_finding ON sightings(finding_id);
CREATE INDEX IF NOT EXISTS idx_sightings_date    ON sightings(scan_date);

CREATE TABLE IF NOT EXISTS cves (
    cve_id            TEXT PRIMARY KEY,
    -- EUVD (rempli par refresh CVE)
    vendor            TEXT,
    product           TEXT,
    product_version   TEXT,
    epss              REAL,
    base_score        REAL,
    base_score_vector TEXT,
    exploited_since   TEXT,
    description       TEXT,
    published         TEXT,
    raw_json          TEXT,
    euvd_updated_at   TEXT,
    -- KEV (rempli par refresh KEV)
    is_kev            INTEGER DEFAULT 0,
    kev_date_added    TEXT,
    kev_sources       TEXT,
    kev_updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS gmp_cache (
    cache_key   TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    item_count  INTEGER DEFAULT 0,
    updated_at  TEXT
);

-- Cache des plages de version EUVD par produit surveillé (permet une
-- réévaluation locale du matching sans re-télécharger depuis EUVD).
CREATE TABLE IF NOT EXISTS cpe_watch_cache (
    vendor       TEXT NOT NULL,
    product      TEXT NOT NULL,
    complete     INTEGER DEFAULT 0,
    fetched_at   TEXT,
    data         TEXT NOT NULL,
    versions_sig TEXT,
    evaluated_at TEXT,
    PRIMARY KEY (vendor, product)
);

CREATE TABLE IF NOT EXISTS anssi_publications (
    ref        TEXT PRIMARY KEY,
    cert_type  TEXT NOT NULL,
    title      TEXT,
    date       TEXT,
    url        TEXT,
    raw_json   TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS anssi_cves (
    ref       TEXT NOT NULL REFERENCES anssi_publications(ref),
    cve_id    TEXT NOT NULL,
    cert_type TEXT NOT NULL,
    PRIMARY KEY (ref, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_anssi_cves_cve ON anssi_cves(cve_id);

CREATE TABLE IF NOT EXISTS cpe_dictionary (
    cpe_uri     TEXT PRIMARY KEY,
    cpe_type    TEXT NOT NULL,
    vendor      TEXT NOT NULL,
    product     TEXT NOT NULL,
    version     TEXT,
    update_str  TEXT,
    title       TEXT,
    created     TEXT,
    last_modified TEXT
);
CREATE INDEX IF NOT EXISTS idx_cpe_type_vendor ON cpe_dictionary(cpe_type, vendor);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_dictionary(vendor, product);

CREATE TABLE IF NOT EXISTS monitored_software (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cpe_type    TEXT NOT NULL,
    vendor      TEXT NOT NULL,
    product     TEXT NOT NULL,
    version     TEXT,
    host_ip     TEXT,
    comment     TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cpe_cache (
    query_key   TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS task_status (
    task_type TEXT PRIMARY KEY,
    running   INTEGER DEFAULT 0,
    started   TEXT,
    progress  TEXT,
    message   TEXT,
    error     TEXT,
    finished  TEXT
);

CREATE TABLE IF NOT EXISTS scan_imports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id       TEXT NOT NULL,
    task_name     TEXT,
    report_id     TEXT NOT NULL,
    scan_date     TEXT,
    imported_at   TEXT NOT NULL,
    results_count INTEGER DEFAULT 0,
    UNIQUE(task_id, report_id)
);

CREATE TABLE IF NOT EXISTS iana_services (
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    service     TEXT NOT NULL,
    description TEXT,
    updated_at  TEXT,
    PRIMARY KEY (port, protocol)
);

CREATE TABLE IF NOT EXISTS dns_cache (
    ip          TEXT PRIMARY KEY,
    hostname    TEXT,           -- NULL = résolu mais aucun enregistrement PTR
    resolved_at TEXT,           -- horodatage de la dernière tentative
    manual      INTEGER DEFAULT 0  -- 1 = saisi manuellement, protégé des rescans
);
"""

import sqlite3


def _db_path() -> str:
    return os.path.join(current_app.config["CACHE_DIR"], "gmpilot.db")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(_db_path(), timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = connect_db()
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        _migrate_schema(conn)
    finally:
        conn.close()


def _migrate_findings_columns(conn, tables):
    """Ajoute les colonnes FP/traitement/statut + reprise one-shot des anciens champs.

    Reprise idempotente : ne cible que les lignes non encore migrées (status_at NULL)
    des statuts à champs (in_progress/false_positive).
    """
    if "findings" not in tables:
        return
    fcols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col in ("fp_reason", "fp_by", "fp_at", "match_confidence", "match_range",
                "ticket_number", "treatment_by", "treatment_at",
                "status_data", "status_by", "status_at"):
        if col not in fcols:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT")
    conn.commit()

    legacy = conn.execute(
        "SELECT id, status, ticket_number, treatment_by, treatment_at, "
        "       fp_reason, fp_by, fp_at "
        "FROM findings WHERE status_at IS NULL AND status IN ('in_progress','false_positive')"
    ).fetchall()
    for r in legacy:
        if r["status"] == "in_progress":
            data = json.dumps({"ticket_number": r["ticket_number"] or ""}, ensure_ascii=False)
            by, at = r["treatment_by"], r["treatment_at"]
        else:  # false_positive
            data = json.dumps({"reason": r["fp_reason"] or ""}, ensure_ascii=False)
            by, at = r["fp_by"], r["fp_at"]
        conn.execute(
            "UPDATE findings SET status_data=?, status_by=?, status_at=? WHERE id=?",
            (data, by, at, r["id"]),
        )
    if legacy:
        conn.commit()


def _migrate_dns_cache(conn, tables):
    """Colonne `manual` protégeant les résolutions DNS saisies à la main."""
    if "dns_cache" not in tables:
        return
    dcols = {r[1] for r in conn.execute("PRAGMA table_info(dns_cache)").fetchall()}
    if "manual" not in dcols:
        conn.execute("ALTER TABLE dns_cache ADD COLUMN manual INTEGER DEFAULT 0")
    conn.commit()


def _migrate_cpe_watch_cols(conn, tables):
    """Colonnes de suivi version pour la ré-vérification incrémentale CPE Watch."""
    if "cpe_watch_cache" not in tables:
        return
    ccols = {r[1] for r in conn.execute("PRAGMA table_info(cpe_watch_cache)").fetchall()}
    for col in ("versions_sig", "evaluated_at"):
        if col not in ccols:
            conn.execute(f"ALTER TABLE cpe_watch_cache ADD COLUMN {col} TEXT")
    conn.commit()


def _heal_cpe_watch_labels(conn, tables):
    """Réaligne vendor/product des findings CPE Watch sur leur OID (source de vérité).

    Corrige les anciens libellés parasites (CVE multi-produits ayant figé le nom
    EUVD d'un autre logiciel). Idempotent, actifs + résolus.
    """
    if not ("findings" in tables and "vulnerabilities" in tables):
        return
    rows = conn.execute(
        "SELECT f.id, f.vendor, f.product, v.oid FROM findings f "
        "JOIN vulnerabilities v ON f.vuln_id=v.id WHERE v.family='CPE Watch'"
    ).fetchall()
    fixes = []
    for r in rows:
        parts = (r["oid"] or "").split(":")
        if len(parts) == 4 and parts[0] == "cpe-watch":
            ov, op = parts[2], parts[3]
            if (r["vendor"] or "").lower() != ov.lower() or (r["product"] or "").lower() != op.lower():
                fixes.append((ov, op, r["id"]))
    if fixes:
        conn.executemany("UPDATE findings SET vendor=?, product=? WHERE id=?", fixes)
        conn.commit()
        logger.info(f"[DB MIGRATE] {len(fixes)} findings CPE Watch ré-alignés sur leur OID")


def _migrate_cve_data(conn, tables):
    """Ancienne table cve_data (+ kev) → table unifiée cves."""
    if "cve_data" not in tables:
        return
    logger.info("[DB MIGRATE] cve_data + kev → cves")
    conn.execute("""
        INSERT OR IGNORE INTO cves
            (cve_id, vendor, product, product_version, epss, base_score,
             base_score_vector, exploited_since, description, published,
             raw_json, euvd_updated_at)
        SELECT cve_id, vendor, product, product_version, epss, base_score,
               base_score_vector, exploited_since, description, published,
               raw_json, updated_at
        FROM cve_data
    """)
    if "kev" in tables:
        conn.execute("""
            UPDATE cves SET is_kev=1, kev_date_added=(
                SELECT date_added FROM kev WHERE kev.cve_id=cves.cve_id
            ), kev_sources=(
                SELECT sources FROM kev WHERE kev.cve_id=cves.cve_id
            )
            WHERE cve_id IN (SELECT cve_id FROM kev)
        """)
        conn.execute("DROP TABLE kev")
    conn.execute("DROP TABLE cve_data")
    conn.commit()


def _migrate_anssi(conn, tables):
    """Anciennes tables ANSSI : drop `anssi`, migre `anssi_details` → `anssi_publications`."""
    if "anssi" in tables:
        logger.info("[DB MIGRATE] anssi → anssi_cves (via anssi_details)")
        conn.execute("DROP TABLE anssi")
        conn.commit()
    if "anssi_details" in tables and "anssi_publications" not in tables:
        logger.info("[DB MIGRATE] anssi_details → anssi_publications")
        conn.executescript(SCHEMA_SQL)
        conn.execute("""
            INSERT OR IGNORE INTO anssi_publications (ref, cert_type, raw_json, updated_at)
            SELECT ref, cert_type, raw_json, updated_at FROM anssi_details
        """)
        conn.execute("DROP TABLE anssi_details")
        conn.commit()
        _rebuild_anssi_cves(conn)


def _migrate_schema(conn):
    """Migre les anciennes tables vers le nouveau schéma si nécessaire.

    Chaque étape est idempotente et gardée par la présence de ses tables ; l'ordre
    est préservé (colonnes findings avant leur reprise, etc.).
    """
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    _migrate_findings_columns(conn, tables)
    _migrate_dns_cache(conn, tables)
    _migrate_cpe_watch_cols(conn, tables)
    _heal_cpe_watch_labels(conn, tables)
    _migrate_cve_data(conn, tables)
    _migrate_anssi(conn, tables)


def _rebuild_anssi_cves(conn):
    """Reconstruit anssi_cves depuis anssi_publications."""
    import re
    CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    CERTFR_BASE = "https://www.cert.ssi.gouv.fr"

    conn.execute("DELETE FROM anssi_cves")
    rows = conn.execute("SELECT ref, cert_type, raw_json FROM anssi_publications").fetchall()

    for row in rows:
        try:
            data = json.loads(row["raw_json"])
        except (json.JSONDecodeError, TypeError):
            continue

        title = data.get("title", "")
        date_str = ""
        revisions = data.get("revisions", [])
        if revisions:
            date_str = revisions[0].get("revision_date", "")[:10]
        url = f"{CERTFR_BASE}/{row['cert_type']}/{row['ref']}/"

        conn.execute(
            """UPDATE anssi_publications SET title=?, date=?, url=?
               WHERE ref=? AND (title IS NULL OR title='')""",
            (title[:200], date_str, url, row["ref"]),
        )

        for cve_obj in data.get("cves", []):
            cve_name = cve_obj.get("name", "") if isinstance(cve_obj, dict) else str(cve_obj)
            if cve_name and CVE_RE.match(cve_name):
                conn.execute(
                    "INSERT OR IGNORE INTO anssi_cves(ref, cve_id, cert_type) VALUES(?,?,?)",
                    (row["ref"], cve_name.upper(), row["cert_type"]),
                )

    conn.commit()
    logger.info(f"[DB MIGRATE] anssi_cves reconstruit: {conn.execute('SELECT COUNT(*) FROM anssi_cves').fetchone()[0]} entrées")


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()


# ═══════════════════════════════════════════════════════════════════════════
# GMP cache — generic JSON storage for small GMP entities
# ═══════════════════════════════════════════════════════════════════════════

def save_gmp_cache(conn, key: str, items: list):
    conn.execute(
        """INSERT OR REPLACE INTO gmp_cache(cache_key,data,item_count,updated_at)
           VALUES(?,?,?,?)""",
        (key, json.dumps(items, ensure_ascii=False), len(items),
         datetime.now().isoformat()),
    )
    conn.commit()


def read_gmp_cache(db, key: str) -> list:
    row = db.execute("SELECT data FROM gmp_cache WHERE cache_key=?", (key,)).fetchone()
    if row and row["data"]:
        return json.loads(row["data"])
    return []


def get_gmp_cache_meta(db, key: str) -> dict:
    from datetime import datetime as _dt

    if key == "vulns":
        cnt = db.execute(f"SELECT COUNT(*) FROM findings WHERE status {_open_in()}").fetchone()[0] or 0
        last_import = db.execute("SELECT MAX(imported_at) as dt FROM scan_imports").fetchone()
        last_check = db.execute("SELECT updated_at FROM gmp_cache WHERE cache_key='vulns_last_check'").fetchone()
        dt_import = last_import["dt"] if last_import else None
        dt_check = last_check["updated_at"] if last_check else None
        dt = max(dt_import or "", dt_check or "") or None
        if cnt > 0 and dt:
            try:
                age = int((_dt.now() - _dt.fromisoformat(dt)).total_seconds() / 60)
            except Exception:
                age = -1
            return {"exists": True, "count": cnt, "date": dt, "age_minutes": age}
        return {"exists": cnt > 0, "count": cnt, "date": "—", "age_minutes": -1}

    if key == "hosts":
        cnt = db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] or 0
        gmp_row = db.execute(
            "SELECT updated_at FROM gmp_cache WHERE cache_key='hosts'"
        ).fetchone()
        if gmp_row and gmp_row["updated_at"]:
            try:
                mtime = _dt.fromisoformat(gmp_row["updated_at"])
                age = int((_dt.now() - mtime).total_seconds() / 60)
            except Exception:
                age = -1
            return {"exists": cnt > 0, "count": cnt, "date": gmp_row["updated_at"], "age_minutes": age}
        return {"exists": cnt > 0, "count": cnt, "date": "—", "age_minutes": -1}

    row = db.execute(
        "SELECT item_count, updated_at FROM gmp_cache WHERE cache_key=?", (key,)
    ).fetchone()
    if row:
        try:
            mtime = _dt.fromisoformat(row["updated_at"])
            age = int((_dt.now() - mtime).total_seconds() / 60)
        except Exception:
            age = -1
        return {
            "exists": True,
            "count": row["item_count"],
            "date": row["updated_at"],
            "age_minutes": age,
        }
    return {"exists": False, "count": 0, "date": "—", "age_minutes": -1}


# ═══════════════════════════════════════════════════════════════════════════
# Import — write side
# ═══════════════════════════════════════════════════════════════════════════

def is_report_imported(conn, task_id: str, report_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM scan_imports WHERE task_id=? AND report_id=?",
        (task_id, report_id),
    ).fetchone()
    return row is not None


def import_gmp_results(conn, results_xml, task_id, task_name, report_id, scan_date):
    """Parse GMP get_results XML and insert into vulnerabilities/findings/sightings."""
    from app.gvm_client import _text, _safe_float

    now = datetime.now().isoformat()
    ts = scan_date or now
    seen_finding_ids = set()
    count = 0
    _sticky = _sticky_in()  # statuts « collants » préservés à la réapparition (config)

    for result in results_xml.findall(".//result"):
        sev = _safe_float(result.findtext("severity"))
        if sev < 0.1:
            continue

        nvt = result.find("nvt")
        oid = nvt.get("oid", "") if nvt is not None else ""
        if not oid:
            continue

        nvt_name = _text(result, "nvt/name") or _text(result, "name") or "—"
        family = _text(result, "nvt/family") or ""
        cvss_base = _safe_float(_text(result, "nvt/cvss_base"))
        solution = _text(result, "solution") or _text(result, "nvt/solution") or ""

        conn.execute(
            """INSERT INTO vulnerabilities (oid,name,family,cvss_base,solution)
               VALUES (?,?,?,?,?)
               ON CONFLICT(oid) DO UPDATE SET
                 name=excluded.name, family=excluded.family,
                 cvss_base=excluded.cvss_base, solution=excluded.solution""",
            (oid, nvt_name, family, cvss_base, solution),
        )
        vuln_id = conn.execute(
            "SELECT id FROM vulnerabilities WHERE oid=?", (oid,)
        ).fetchone()[0]

        cves = []
        for ref in result.findall(".//ref"):
            if ref.get("type") == "cve":
                cve_id = ref.get("id", "").upper().strip()
                if cve_id:
                    cves.append(cve_id)
                    conn.execute(
                        "INSERT OR IGNORE INTO vuln_cves(vuln_id,cve_id) VALUES(?,?)",
                        (vuln_id, cve_id),
                    )

        host_ip = _text(result, "host") or _text(result, "host/ip") or "—"
        port = _text(result, "port") or "—"
        qod_str = result.findtext("qod/value") or "0"
        qod = int(qod_str) if qod_str.isdigit() else 0
        threat = _text(result, "threat") or "Log"
        description = _text(result, "description") or ""

        conn.execute(
            f"""INSERT INTO findings
                 (vuln_id,host_ip,port,severity,qod,threat,description,
                  primary_cve,status,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?,'active',?,?)
               ON CONFLICT(vuln_id,host_ip,port) DO UPDATE SET
                 severity=MAX(findings.severity,excluded.severity),
                 qod=MAX(findings.qod,excluded.qod),
                 threat=excluded.threat,
                 description=CASE WHEN excluded.severity>=findings.severity
                              THEN excluded.description ELSE findings.description END,
                 status=CASE WHEN findings.status {_sticky}
                              THEN findings.status ELSE 'active' END,
                 last_seen=excluded.last_seen,
                 resolved_at=CASE WHEN findings.status {_sticky}
                              THEN findings.resolved_at ELSE NULL END""",
            (vuln_id, host_ip, port, sev, qod, threat, description,
             cves[0] if cves else None, ts, ts),
        )

        finding_id = conn.execute(
            "SELECT id FROM findings WHERE vuln_id=? AND host_ip=? AND port=?",
            (vuln_id, host_ip, port),
        ).fetchone()[0]
        seen_finding_ids.add(finding_id)

        conn.execute(
            """INSERT OR IGNORE INTO sightings
                 (finding_id,task_id,task_name,report_id,scan_date)
               VALUES (?,?,?,?,?)""",
            (finding_id, task_id, task_name, report_id, ts),
        )
        count += 1

    conn.commit()
    return seen_finding_ids, count


def resolve_stale_findings(conn, task_id, seen_finding_ids, resolved_at=None):
    """Mark findings as resolved if this task no longer reports them
    and no other task still does. resolved_at defaults to now if not provided."""
    now = resolved_at or datetime.now().isoformat()

    rows = conn.execute(
        "SELECT DISTINCT finding_id FROM sightings WHERE task_id=?", (task_id,)
    ).fetchall()
    previously = {r[0] for r in rows}
    stale = previously - seen_finding_ids
    if not stale:
        return 0

    resolved = 0
    _auto = _auto_resolve_in()  # seuls les statuts « auto-résolution » se ferment si absents
    for fid in stale:
        other = conn.execute(
            """SELECT 1 FROM sightings s
               WHERE s.finding_id=? AND s.task_id!=?
                 AND s.report_id=(
                   SELECT si.report_id FROM scan_imports si
                   WHERE si.task_id=s.task_id
                   ORDER BY si.imported_at DESC LIMIT 1)
               LIMIT 1""",
            (fid, task_id),
        ).fetchone()
        if other is None:
            conn.execute(
                f"UPDATE findings SET status='resolved',resolved_at=? WHERE id=? AND status {_auto}",
                (now, fid),
            )
            resolved += 1

    conn.commit()
    return resolved


def mark_finding_false_positive(conn, finding_id, by, reason=None):
    """Marque un finding comme faux positif déclaré manuellement.

    Le statut 'false_positive' est préservé par les upserts CPE Watch / scan GMP,
    donc le finding ne réapparaît pas dans les vues actives aux cycles suivants.
    Retourne True si un finding a été mis à jour, False sinon.
    """
    now = datetime.now().isoformat()
    cur = conn.execute(
        """UPDATE findings
             SET status='false_positive', resolved_at=?, fp_at=?, fp_by=?, fp_reason=?
           WHERE id=? AND status!='false_positive'""",
        (now, now, by, (reason or None), finding_id),
    )
    conn.commit()
    return cur.rowcount > 0


def unmark_finding_false_positive(conn, finding_id):
    """Annule le marquage faux positif : le finding redevient actif.

    On repart de 'active' (et non 'resolved') : si le finding n'est plus détecté,
    le prochain cycle de résolution le repassera en 'resolved' de lui-même.
    Retourne True si un finding a été mis à jour, False sinon.
    """
    cur = conn.execute(
        """UPDATE findings
             SET status='active', resolved_at=NULL, fp_at=NULL, fp_by=NULL, fp_reason=NULL
           WHERE id=? AND status='false_positive'""",
        (finding_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def set_findings_status(conn, finding_ids, status, data=None, by=None) -> int:
    """Applique un statut (config dynamique) à un ou plusieurs findings.

    - status : id de statut (doit exister dans la config).
    - data   : dict des valeurs des champs custom du statut (validé côté route) → status_data.
    - resolved_at = maintenant si le statut est de scope 'closed', sinon NULL.

    Partage de valeurs entre statuts : les valeurs de même clé sont conservées quand on
    change de statut (ex. le N° de ticket suit « En cours » → « Résolu »). Concrètement,
    status_data est FUSIONNÉ (json_patch) dans l'existant — sauf pour le statut de base
    (active/reopen) qui réinitialise le contexte.
    Les anciennes colonnes (ticket_number/treatment_*/fp_*) sont vidées ; l'affichage
    dérive désormais de status_data. Retourne le nombre de findings modifiés.
    """
    from app.statuses import get_status
    ids = [int(i) for i in finding_ids if str(i).lstrip("-").isdigit()]
    if not ids:
        return 0
    sdef = get_status(status)
    if not sdef:
        return 0
    now = datetime.now().isoformat()
    ph = ",".join("?" * len(ids))
    data = data if isinstance(data, dict) else {}
    resolved_at = now if sdef["scope"] == "closed" else None

    if sdef.get("base"):
        # Statut de base (reopen) : contexte réinitialisé, pas de report de valeurs.
        status_data_sql = "?"
        status_data_param = json.dumps(data, ensure_ascii=False) if data else None
    else:
        # Fusion merge-patch : conserve les valeurs de même clé déjà présentes.
        status_data_sql = "json_patch(COALESCE(status_data,'{}'), ?)"
        status_data_param = json.dumps(data, ensure_ascii=False)  # au moins '{}'

    cur = conn.execute(
        f"""UPDATE findings
              SET status=?, status_data={status_data_sql}, status_by=?, status_at=?, resolved_at=?,
                  ticket_number=NULL, treatment_by=NULL, treatment_at=NULL,
                  fp_reason=NULL, fp_by=NULL, fp_at=NULL
            WHERE id IN ({ph})""",
        [status, status_data_param, by, now, resolved_at, *ids],
    )

    conn.commit()
    return cur.rowcount


def mark_report_imported(conn, task_id, task_name, report_id, scan_date, count):
    conn.execute(
        """INSERT OR IGNORE INTO scan_imports
             (task_id,task_name,report_id,scan_date,imported_at,results_count)
           VALUES (?,?,?,?,?,?)""",
        (task_id, task_name, report_id, scan_date,
         datetime.now().isoformat(), count),
    )
    conn.commit()


def import_hosts(conn, xml_root):
    """Populate hosts + host_tags from GMP hosts XML."""
    from app.gvm_client import _safe_float

    for asset in xml_root.findall("asset"):
        host_id = asset.get("id", "")
        ip = asset.findtext("name", "")
        if not host_id or not ip:
            continue

        os_val = "—"
        for detail in asset.findall(".//host/detail"):
            if detail.findtext("name") == "best_os_txt":
                os_val = detail.findtext("value") or "—"
                break

        sev = _safe_float(
            asset.findtext("severity") or asset.findtext("host/severity")
        )
        last_seen = asset.findtext("modification_time", "")
        comment = asset.findtext("comment", "")

        conn.execute(
            """INSERT INTO hosts (id,ip,name,os,severity,last_seen,comment)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(ip) DO UPDATE SET
                 id=excluded.id, name=excluded.name,
                 os=CASE WHEN excluded.os!='—' THEN excluded.os ELSE hosts.os END,
                 severity=MAX(hosts.severity,excluded.severity),
                 last_seen=MAX(hosts.last_seen,excluded.last_seen),
                 comment=CASE WHEN excluded.comment!='' THEN excluded.comment ELSE hosts.comment END""",
            (host_id, ip, ip, os_val, sev, last_seen, comment),
        )

        conn.execute("DELETE FROM host_tags WHERE host_ip=?", (ip,))
        for tag in asset.findall(".//user_tags/tag"):
            tag_name = tag.findtext("name", "")
            if tag_name:
                conn.execute(
                    "INSERT OR IGNORE INTO host_tags(host_ip,tag_name) VALUES(?,?)",
                    (ip, tag_name),
                )

    cnt = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    save_gmp_cache(conn, "hosts", [{"_count": cnt}])


def upsert_cve(conn, cve_id, raw_data):
    """Insert/update EUVD enrichment data for a CVE."""
    _VENDOR_EMPTY = {"—", "n/a", "na", "none", "unknown", ""}
    vendor = ""
    product = ""
    product_version = ""

    vendors = raw_data.get("enisaIdVendor", [])
    if vendors and isinstance(vendors, list):
        v = vendors[0].get("vendor", {})
        vendor = v.get("name", "") if isinstance(v, dict) else ""

    products = raw_data.get("enisaIdProduct", [])
    if products and isinstance(products, list):
        p = products[0]
        prod_obj = p.get("product", {})
        product = prod_obj.get("name", "") if isinstance(prod_obj, dict) else ""
        product_version = p.get("product_version", "")

    if vendor.strip().lower() in _VENDOR_EMPTY:
        vendor = ""
    else:
        vendor = vendor.title()
    if product.strip().lower() in _VENDOR_EMPTY:
        product = ""
    else:
        product = product.title()

    raw_epss = raw_data.get("epss")
    epss = None
    if raw_epss is not None:
        try:
            epss = float(raw_epss)
            if epss > 1:
                epss = epss / 100.0
            epss = min(1.0, max(0.0, epss))
        except (ValueError, TypeError):
            epss = None

    conn.execute(
        """INSERT INTO cves
             (cve_id,vendor,product,product_version,epss,base_score,
              base_score_vector,exploited_since,description,published,
              raw_json,euvd_updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(cve_id) DO UPDATE SET
             vendor=excluded.vendor, product=excluded.product,
             product_version=excluded.product_version, epss=excluded.epss,
             base_score=excluded.base_score, base_score_vector=excluded.base_score_vector,
             exploited_since=excluded.exploited_since, description=excluded.description,
             published=excluded.published, raw_json=excluded.raw_json,
             euvd_updated_at=excluded.euvd_updated_at""",
        (cve_id.upper(), vendor, product, product_version, epss,
         raw_data.get("baseScore"), raw_data.get("baseScoreVector", ""),
         raw_data.get("exploitedSince", ""),
         raw_data.get("description", ""),
         raw_data.get("datePublished") or raw_data.get("published", ""),
         json.dumps(raw_data, ensure_ascii=False),
         datetime.now().isoformat()),
    )


def import_kev_dump(conn, kev_list):
    """Met à jour le flag is_kev sur la table cves depuis le dump KEV.
    Retourne l'ensemble des CVE IDs marqués exploités (pour rescore incrémental)."""
    now = datetime.now().isoformat()
    conn.execute("UPDATE cves SET is_kev=0, kev_date_added=NULL, kev_sources=NULL")
    kev_cve_ids: set[str] = set()
    for entry in kev_list:
        # Préférer cveId, fallback sur aliases (format EUVD utilise aliases)
        cve_id = (entry.get("cveId") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            for alias in (entry.get("aliases") or "").split("\n"):
                alias = alias.strip().upper()
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
        if not cve_id.startswith("CVE-"):
            continue
        kev_cve_ids.add(cve_id)
        sources = json.dumps(entry.get("sources", []))
        conn.execute(
            """INSERT INTO cves (cve_id, is_kev, kev_date_added, kev_sources, kev_updated_at)
               VALUES (?, 1, ?, ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 is_kev=1, kev_date_added=excluded.kev_date_added,
                 kev_sources=excluded.kev_sources, kev_updated_at=excluded.kev_updated_at""",
            (cve_id, entry.get("dateAdded", ""), sources, now),
        )
    conn.commit()
    return kev_cve_ids


def import_anssi_index(conn, index_dict):
    """Reconstruit anssi_cves depuis anssi_publications."""
    _rebuild_anssi_cves(conn)


# ═══════════════════════════════════════════════════════════════════════════
# Enrichment + Scoring
# ═══════════════════════════════════════════════════════════════════════════

def enrich_findings(conn):
    """Update denormalized enrichment columns from cves + anssi_cves."""
    conn.execute("""
        UPDATE findings SET
          primary_cve = COALESCE(
            (SELECT vc.cve_id FROM vuln_cves vc
             JOIN cves c ON vc.cve_id=c.cve_id
             WHERE vc.vuln_id=findings.vuln_id LIMIT 1),
            (SELECT vc.cve_id FROM vuln_cves vc
             WHERE vc.vuln_id=findings.vuln_id LIMIT 1),
            findings.primary_cve
          ),
          vendor = CASE
            WHEN (SELECT COUNT(*) FROM vuln_cves WHERE vuln_id=findings.vuln_id) <= 3
            THEN COALESCE(
              (SELECT c.vendor FROM vuln_cves vc
               JOIN cves c ON vc.cve_id=c.cve_id
               WHERE vc.vuln_id=findings.vuln_id
                 AND c.vendor IS NOT NULL AND c.vendor!=''
               LIMIT 1),
              NULLIF(findings.vendor, ''),
              '')
            ELSE COALESCE(NULLIF(findings.vendor, ''), '')
          END,
          product = CASE
            WHEN (SELECT COUNT(*) FROM vuln_cves WHERE vuln_id=findings.vuln_id) <= 3
            THEN COALESCE(
              (SELECT c.product FROM vuln_cves vc
               JOIN cves c ON vc.cve_id=c.cve_id
               WHERE vc.vuln_id=findings.vuln_id
                 AND c.product IS NOT NULL AND c.product!=''
               LIMIT 1),
              NULLIF(findings.product, ''),
              '')
            ELSE COALESCE(NULLIF(findings.product, ''), '')
          END,
          epss = (
            SELECT MAX(c.epss) FROM vuln_cves vc
            JOIN cves c ON vc.cve_id=c.cve_id
            WHERE vc.vuln_id=findings.vuln_id AND c.epss IS NOT NULL
          ),
          is_exploited = COALESCE(
            (SELECT 1 FROM vuln_cves vc
             JOIN cves c ON vc.cve_id=c.cve_id
             WHERE vc.vuln_id=findings.vuln_id
               AND (c.is_kev=1
                    OR (c.exploited_since IS NOT NULL AND c.exploited_since!=''))
             LIMIT 1),
            0
          ),
          exploited_since = COALESCE(
            (SELECT COALESCE(c.exploited_since, c.kev_date_added)
             FROM vuln_cves vc
             JOIN cves c ON vc.cve_id=c.cve_id
             WHERE vc.vuln_id=findings.vuln_id
               AND (c.is_kev=1
                    OR (c.exploited_since IS NOT NULL AND c.exploited_since!=''))
             LIMIT 1),
            ''
          ),
          anssi_level = COALESCE(
            (SELECT ac.cert_type FROM vuln_cves vc
             JOIN anssi_cves ac ON vc.cve_id=ac.cve_id
             WHERE vc.vuln_id=findings.vuln_id
             ORDER BY CASE ac.cert_type WHEN 'alerte' THEN 0 WHEN 'avis' THEN 1 ELSE 2 END
             LIMIT 1),
            'none'
          )
        WHERE status IN ('active','in_progress')
    """.replace("IN ('active','in_progress')", _open_in()))
    conn.commit()
    logger.info("[DB] Enrichment terminé")


def recalculate_scores(conn, finding_ids: set[int] | None = None):
    """Recalcule ctx_score pour les findings actifs.

    finding_ids=None  → rescore complet de tous les findings actifs.
    finding_ids={...} → rescore incrémental : uniquement les IDs fournis.
    """
    from app.scoring import load_scoring_config, _get_criterion_value, _safe_eval

    config = load_scoring_config()
    criteria = config.get("scoring", {}).get("criteria", [])
    formula = config.get("scoring", {}).get("formula", "0")

    if not criteria:
        if finding_ids is not None:
            if finding_ids:
                conn.executemany(
                    "UPDATE findings SET ctx_score=0, score_details='{}' WHERE id=?",
                    [(fid,) for fid in finding_ids],
                )
        else:
            conn.execute("UPDATE findings SET ctx_score=0, score_details='{}' WHERE status IN ('active','in_progress')".replace("IN ('active','in_progress')", _open_in()))
        conn.commit()
        return

    kev_data = {r["cve_id"]: {"dateAdded": r["kev_date_added"]}
                for r in conn.execute("SELECT cve_id,kev_date_added FROM cves WHERE is_kev=1")}
    anssi_data = {r["cve_id"]: {"type": r["cert_type"], "ref": r["ref"]}
                  for r in conn.execute("SELECT cve_id, cert_type, ref FROM anssi_cves")}
    host_tags_map = {}
    for r in conn.execute("SELECT host_ip, GROUP_CONCAT(tag_name) as t FROM host_tags GROUP BY host_ip"):
        host_tags_map[r["host_ip"]] = r["t"].split(",") if r["t"] else []

    if finding_ids is not None:
        if not finding_ids:
            logger.info("[DB] Scores incrémentaux : aucun finding à rescorer")
            return
        ph = ",".join("?" * len(finding_ids))
        rows = conn.execute(
            f"""SELECT f.id, f.severity, f.qod, f.host_ip, f.epss,
                       GROUP_CONCAT(vc.cve_id) as cves
                FROM findings f
                LEFT JOIN vuln_cves vc ON f.vuln_id=vc.vuln_id
                WHERE f.id IN ({ph})
                GROUP BY f.id""",
            list(finding_ids),
        ).fetchall()
        mode = f"incrémental ({len(finding_ids)} IDs)"
    else:
        rows = conn.execute("""
            SELECT f.id, f.severity, f.qod, f.host_ip, f.epss,
                   GROUP_CONCAT(vc.cve_id) as cves
            FROM findings f
            LEFT JOIN vuln_cves vc ON f.vuln_id=vc.vuln_id
            WHERE f.status IN ('active','in_progress')
            GROUP BY f.id
        """.replace("IN ('active','in_progress')", _open_in())).fetchall()
        mode = "complet"

    updates = []
    for r in rows:
        cves = r["cves"].split(",") if r["cves"] else []
        vuln = {
            "severity": r["severity"],
            "qod": str(r["qod"] or 0),
            "euvd_epss": r["epss"],
            "all_cves": cves,
            "cve": cves[0] if cves else "—",
        }
        host_tags = host_tags_map.get(r["host_ip"], [])

        details = {}
        for c in criteria:
            cid = c.get("id", "")
            if cid:
                details[cid] = round(
                    _get_criterion_value(c, vuln, host_tags, kev_data, anssi_data), 4
                )

        try:
            fe = formula
            for cid, val in details.items():
                fe = fe.replace(f"{{{cid}}}", str(val))
            score = min(100, max(0, round(_safe_eval(fe), 1)))
        except Exception:
            score = 0

        updates.append((score, json.dumps(details), r["id"]))

    conn.executemany(
        "UPDATE findings SET ctx_score=?, score_details=? WHERE id=?", updates
    )
    conn.commit()
    logger.info(f"[DB] Scores recalculés ({mode}) pour {len(updates)} findings")


def enrich_and_score(conn, finding_ids: set[int] | None = None):
    """Enrichissement + recalcul des scores.
    finding_ids=None → tout rescorer ; fourni → rescore incrémental."""
    enrich_findings(conn)
    recalculate_scores(conn, finding_ids=finding_ids)


# ═══════════════════════════════════════════════════════════════════════════
# Read — query side (used by blueprints)
# ═══════════════════════════════════════════════════════════════════════════

EUVD_WEB_BASE = "https://euvd.enisa.europa.eu/vulnerability"

_FINDING_SELECT = """
    SELECT f.id, f.host_ip, f.port, f.severity, f.qod, f.threat,
           f.description, f.primary_cve, f.vendor, f.product, f.epss,
           f.is_exploited, f.exploited_since, f.anssi_level,
           f.ctx_score, f.score_details,
           f.status, f.first_seen, f.last_seen, f.resolved_at,
           f.fp_reason, f.fp_by, f.fp_at, f.match_confidence, f.match_range,
           f.ticket_number, f.treatment_by, f.treatment_at,
           f.status_data, f.status_by, f.status_at,
           v.name as vuln_name, v.oid, v.family, v.cvss_base, v.solution,
           GROUP_CONCAT(DISTINCT vc.cve_id) as all_cves,
           GROUP_CONCAT(DISTINCT s.task_name) as task_names,
           GROUP_CONCAT(DISTINCT s.task_id) as task_ids,
           (SELECT c.product_version FROM cves c
            WHERE c.cve_id = f.primary_cve LIMIT 1) as primary_version_range,
           (SELECT ms.version FROM monitored_software ms
            WHERE v.family = 'CPE Watch'
              AND LOWER(f.vendor) LIKE '%' || LOWER(ms.vendor) || '%'
              AND LOWER(f.product) LIKE '%' || LOWER(ms.product) || '%'
              AND COALESCE(ms.host_ip, 'monitored') = COALESCE(f.host_ip, 'monitored')
            LIMIT 1) as monitored_version
    FROM findings f
    JOIN vulnerabilities v ON f.vuln_id=v.id
    LEFT JOIN vuln_cves vc ON v.id=vc.vuln_id
    LEFT JOIN sightings s ON f.id=s.finding_id
"""


# ── Référentiel IANA port → service ─────────────────────────────────────────
# Chargé une fois par process (le référentiel change rarement) ; réinitialisé
# par la tâche de rafraîchissement via reset_iana_cache().
_IANA_MAP: dict | None = None  # {(port:int, protocol:str): service:str}


def _load_iana_map() -> dict:
    global _IANA_MAP
    if _IANA_MAP is not None:
        return _IANA_MAP
    m: dict = {}
    try:
        conn = connect_db()
        try:
            for row in conn.execute("SELECT port, protocol, service FROM iana_services"):
                m[(row[0], (row[1] or "").lower())] = row[2]
        finally:
            conn.close()
    except sqlite3.Error:
        m = {}
    _IANA_MAP = m
    return _IANA_MAP


def reset_iana_cache():
    """Invalide le cache en mémoire (à appeler après un import IANA)."""
    global _IANA_MAP
    _IANA_MAP = None


def iana_service_for(port_str) -> str:
    """'443/tcp' -> 'https' ; chaîne vide si port non numérique ou inconnu."""
    if not port_str or "/" not in str(port_str):
        return ""
    num, _, proto = str(port_str).partition("/")
    num = num.strip()
    if not num.isdigit():
        return ""
    return _load_iana_map().get((int(num), proto.strip().lower()), "")


def import_iana_services(conn, records, updated_at=None) -> int:
    """Remplace intégralement la table iana_services.

    records : itérable de tuples (port:int, protocol:str, service:str, description:str).
    Retourne le nombre de lignes importées.
    """
    ts = updated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = [(int(p), (proto or "").lower(), svc, desc or "", ts)
            for (p, proto, svc, desc) in records if svc]
    conn.execute("DELETE FROM iana_services")
    # OR IGNORE : conserve la 1re entrée de chaque (port, protocole) — l'IANA liste
    # le nom canonique en premier (ex. 80/tcp → 'http' avant 'www', 'www-http').
    conn.executemany(
        "INSERT OR IGNORE INTO iana_services(port, protocol, service, description, updated_at)"
        " VALUES(?,?,?,?,?)",
        rows,
    )
    conn.commit()
    reset_iana_cache()
    return conn.execute("SELECT COUNT(*) FROM iana_services").fetchone()[0]


# ── Cache DNS inverse (IP → hostname) ───────────────────────────────────────
# Même principe que le référentiel IANA : chargé une fois par process, invalidé
# par la tâche de résolution via reset_dns_cache().
_DNS_MAP: dict | None = None  # {ip: hostname}  (n'inclut que les IP AVEC hostname)


def _load_dns_map() -> dict:
    global _DNS_MAP
    if _DNS_MAP is not None:
        return _DNS_MAP
    m: dict = {}
    try:
        conn = connect_db()
        try:
            for row in conn.execute(
                "SELECT ip, hostname FROM dns_cache WHERE hostname IS NOT NULL AND hostname != ''"
            ):
                m[row[0]] = row[1]
        finally:
            conn.close()
    except sqlite3.Error:
        m = {}
    _DNS_MAP = m
    return _DNS_MAP


def reset_dns_cache():
    """Invalide le cache DNS en mémoire (à appeler après une résolution)."""
    global _DNS_MAP
    _DNS_MAP = None


def hostname_for(ip) -> str:
    """Retourne le hostname connu pour une IP, ou '' si inconnu/non résolu."""
    if not ip:
        return ""
    return _load_dns_map().get(str(ip), "")


# Périmètre de résolution DNS : on ne résout que les IP des findings ouverts
# (actifs / faux positifs) ou clos depuis moins de DNS_HISTORY_DAYS jours. Le
# hostname ne s'affiche que sur les findings ; inutile de résoudre l'inventaire
# GVM complet (hôtes sans finding) ni les findings clos de longue date (hôtes
# probablement décommissionnés).
DNS_HISTORY_DAYS = 30


def dns_scan_ips(conn) -> list[str]:
    """IP distinctes des findings ouverts ou clos récemment (cf. DNS_HISTORY_DAYS)."""
    rows = conn.execute(
        f"""SELECT DISTINCT host_ip AS ip FROM findings
            WHERE host_ip IS NOT NULL AND host_ip != ''
              AND (status != 'resolved'
                   OR resolved_at >= datetime('now', '-{DNS_HISTORY_DAYS} days'))"""
    ).fetchall()
    return [r["ip"] for r in rows]


def dns_cached_ips(conn) -> set:
    """IP déjà présentes dans le cache DNS (déjà tentées)."""
    return {r[0] for r in conn.execute("SELECT ip FROM dns_cache")}


def store_dns_results(conn, results) -> int:
    """Enregistre des résolutions automatiques.

    results : itérable de tuples (ip, hostname|None). hostname None → PTR absent.
    Écrit resolved_at=maintenant. Les entrées saisies à la main (manual=1) ne sont
    JAMAIS écrasées. Retourne le nombre de lignes traitées.
    """
    rows = list(results)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.executemany(
        "INSERT INTO dns_cache(ip, hostname, resolved_at, manual) VALUES(?,?,?,0) "
        "ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, resolved_at=excluded.resolved_at "
        "WHERE dns_cache.manual=0",
        [(ip, (hn or None), ts) for (ip, hn) in rows],
    )
    conn.commit()
    reset_dns_cache()
    return len(rows)


def dns_manual_ips(conn) -> set:
    """IP dont la résolution a été saisie manuellement (à ne pas re-scanner)."""
    return {r[0] for r in conn.execute("SELECT ip FROM dns_cache WHERE manual=1")}


def dns_all_entries(conn) -> list[dict]:
    """Toutes les entrées du cache DNS (page d'administration). Vides d'abord."""
    return [dict(r) for r in conn.execute(
        "SELECT ip, hostname, resolved_at, manual FROM dns_cache "
        "ORDER BY (hostname IS NULL OR hostname='') DESC, ip"
    )]


def set_dns_manual(conn, ip: str, hostname: str) -> None:
    """Fixe (ou vide) manuellement le hostname d'une IP ; marque manual=1."""
    hn = (hostname or "").strip() or None
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO dns_cache(ip, hostname, resolved_at, manual) VALUES(?,?,?,1) "
        "ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, "
        "resolved_at=excluded.resolved_at, manual=1",
        (ip, hn, ts),
    )
    conn.commit()
    reset_dns_cache()


def reset_dns_entry(conn, ip: str) -> None:
    """Supprime une entrée : elle sera re-résolue au prochain scan incrémental."""
    conn.execute("DELETE FROM dns_cache WHERE ip=?", (ip,))
    conn.commit()
    reset_dns_cache()


def import_dns_manual(conn, pairs) -> int:
    """Import en masse de résolutions manuelles.

    pairs : itérable de (ip, hostname). Upsert avec manual=1 (écrase l'auto).
    Retourne le nombre de lignes importées.
    """
    rows = [(ip, (hn or "").strip() or None) for ip, hn in pairs]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.executemany(
        "INSERT INTO dns_cache(ip, hostname, resolved_at, manual) VALUES(?,?,?,1) "
        "ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, "
        "resolved_at=excluded.resolved_at, manual=1",
        [(ip, hn, ts) for ip, hn in rows],
    )
    conn.commit()
    reset_dns_cache()
    return len(rows)


def _row_to_vuln(r) -> dict:
    """Convert a SQLite Row to the dict format templates expect."""
    from app.gvm_client import severity_class

    cves = r["all_cves"].split(",") if r["all_cves"] else []
    task_names = list(dict.fromkeys(r["task_names"].split(","))) if r["task_names"] else ["—"]
    task_ids = list(dict.fromkeys(r["task_ids"].split(","))) if r["task_ids"] else []
    primary_cve = r["primary_cve"] or (cves[0] if cves else "—")
    _v = (r["vendor"] or "").strip()
    _p = (r["product"] or "").strip()
    # CPE Watch : le vendor/produit SURVEILLÉ (dans l'OID) fait foi pour l'affichage
    # et le regroupement — le libellé EUVD du CVE peut varier pour un même produit
    # (ex. "Wireshark" vs "Wireshark Foundation"), ce qui scinderait le groupe à tort.
    _oid = r["oid"] or ""
    if r["family"] == "CPE Watch" and _oid.startswith("cpe-watch:"):
        _parts = _oid.split(":")
        if len(_parts) == 4:
            _v, _p = _parts[2].strip(), _parts[3].strip()
    vendor = _v.title() if _v else "—"
    product = _p.lower() if _p else "—"

    _sid = r["status"] or "active"
    try:
        _sdata = json.loads(r["status_data"]) if r["status_data"] else {}
    except Exception:
        _sdata = {}
    if not isinstance(_sdata, dict):
        _sdata = {}

    return {
        "id": r["id"],
        "name": r["vuln_name"],
        "host": r["host_ip"],
        "hostname": hostname_for(r["host_ip"]),
        "port": r["port"],
        "port_service": iana_service_for(r["port"]),
        "severity": r["severity"],
        "sev_class": severity_class(r["severity"]),
        "qod": str(r["qod"] or 0),
        "threat": r["threat"] or "Log",
        "description": r["description"] or "",
        "solution": r["solution"] or "",
        "nvt_name": r["vuln_name"],
        "cvss_base": str(r["cvss_base"] or "—"),
        "family": r["family"] or "—",
        "cve": primary_cve,
        "cves": cves,
        "all_cves": cves,
        "euvd_vendor": vendor,
        "euvd_product": product,
        "euvd_epss": r["epss"],
        "euvd_exploited": bool(r["is_exploited"]),
        "euvd_exploited_since": r["exploited_since"] or "",
        "euvd_url": f"{EUVD_WEB_BASE}/{primary_cve}" if primary_cve != "—" else "",
        "euvd_data": bool(r["vendor"]),
        "anssi_level": r["anssi_level"] or "none",
        "ctx_score": r["ctx_score"] or 0,
        "ctx_score_details": json.loads(r["score_details"]) if r["score_details"] else {},
        "task_name": ", ".join(t for t in task_names if t and t != "—") or "—",
        "task_names": task_names,
        "task_id": task_ids[0] if task_ids else "",
        "task_ids": task_ids,
        "first_seen": r["first_seen"] or "",
        "last_seen": r["last_seen"] or "",
        # match_range = plage(s) du produit SURVEILLÉ (fiable pour les CVE multi-produits) ;
        # repli sur cves.product_version (générique) pour les findings non-CPE.
        "version_range": r["match_range"] or r["primary_version_range"] or "",
        "monitored_version": r["monitored_version"] or "",
        "status": _sid,
        "status_data": _sdata,
        "status_by": r["status_by"] or "",
        "status_at": r["status_at"] or "",
        # Rétro-compat (dérivés du statut / status_data) — utilisés par les vues actuelles
        "is_false_positive": (_sid == "false_positive"),
        "is_in_progress": (_sid == "in_progress"),
        "fp_reason": _sdata.get("reason") or r["fp_reason"] or "",
        "fp_by": r["status_by"] or r["fp_by"] or "",
        "fp_at": r["status_at"] or r["fp_at"] or "",
        "ticket_number": _sdata.get("ticket_number") or r["ticket_number"] or "",
        "treatment_by": r["status_by"] or r["treatment_by"] or "",
        "treatment_at": r["status_at"] or r["treatment_at"] or "",
        "match_confidence": r["match_confidence"] or "",
    }


def _status_in_clause(ids):
    """Retourne (fragment SQL "IN (?,?,…)", liste d'ids) pour filtrer par statuts.
    Liste vide → clause qui ne matche rien (sécurité)."""
    ids = list(ids)
    if not ids:
        return "IN ('__none__')", []
    return "IN (" + ",".join("?" * len(ids)) + ")", ids


def _status_in_literal(ids):
    """Fragment "IN ('a','b',…)" avec ids en littéraux. Sûr : les ids sont slugifiés
    (a-z 0-9 _) par app.statuses.slug — aucun risque d'injection."""
    ids = list(ids)
    if not ids:
        return "IN ('__none__')"
    return "IN (" + ",".join("'" + i + "'" for i in ids) + ")"


def _open_in():
    from app.statuses import open_status_ids
    return _status_in_literal(open_status_ids())


def _closed_in():
    from app.statuses import closed_status_ids
    return _status_in_literal(closed_status_ids())


def _sticky_in():
    from app.statuses import sticky_status_ids
    return _status_in_literal(sticky_status_ids())


def _auto_resolve_in():
    from app.statuses import auto_resolve_status_ids
    return _status_in_literal(auto_resolve_status_ids())


def query_active_findings(db, task_ids=None) -> list[dict]:
    """Return all OPEN findings as vuln dicts (non paginé — pour Synthèse et dropdowns).
    « Ouvert » = statuts de scope 'open' (config dynamique)."""
    from app.statuses import open_status_ids
    _inc, _sids = _status_in_clause(open_status_ids())
    sql = _FINDING_SELECT + f" WHERE f.status {_inc}"
    params = list(_sids)

    if task_ids:
        placeholders = ",".join("?" * len(task_ids))
        sql += f" AND f.id IN (SELECT DISTINCT finding_id FROM sightings WHERE task_id IN ({placeholders}))"
        params.extend(task_ids)

    sql += " GROUP BY f.id"
    rows = db.execute(sql, params).fetchall()
    return [_row_to_vuln(r) for r in rows]


def query_active_findings_page(
    db,
    *,
    task_ids=None,
    search: str = "",
    min_sev: float | None = None,
    max_sev: float | None = None,
    min_score: float | None = None,
    exploited_only: bool = False,
    sort_field: str = "ctx_score",
    sort_order: str = "desc",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int, int, int, float]:
    """Filtrage, tri et pagination entièrement en SQL.

    Retourne (vulns, total, exploited_count, with_euvd_count, avg_score).
    vulns = la page demandée seulement (pas la liste complète).
    """
    from app.statuses import open_status_ids
    _inc, _sids = _status_in_clause(open_status_ids())
    where_parts: list[str] = [f"f.status {_inc}"]
    params: list = list(_sids)

    if task_ids:
        ph = ",".join("?" * len(task_ids))
        where_parts.append(
            f"f.id IN (SELECT DISTINCT finding_id FROM sightings WHERE task_id IN ({ph}))"
        )
        params.extend(task_ids)

    if search:
        # Échapper les wildcards SQLite pour une recherche littérale
        s = search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pat = f"%{s}%"
        where_parts.append(
            r"""(LOWER(v.name) LIKE ? ESCAPE '\'
               OR LOWER(f.host_ip) LIKE ? ESCAPE '\'
               OR LOWER(COALESCE(f.primary_cve,'')) LIKE ? ESCAPE '\'
               OR EXISTS (
                   SELECT 1 FROM vuln_cves vc2
                   WHERE vc2.vuln_id=v.id AND LOWER(vc2.cve_id) LIKE ? ESCAPE '\'
               )
               OR LOWER(COALESCE(f.vendor,'')) LIKE ? ESCAPE '\'
               OR LOWER(COALESCE(f.product,'')) LIKE ? ESCAPE '\')"""
        )
        params.extend([pat] * 6)

    if min_sev is not None:
        where_parts.append("f.severity >= ?")
        params.append(min_sev)
    if max_sev is not None:
        where_parts.append("f.severity <= ?")
        params.append(max_sev)
    if min_score is not None:
        where_parts.append("f.ctx_score >= ?")
        params.append(min_score)
    if exploited_only:
        where_parts.append("f.is_exploited = 1")

    where = " AND ".join(where_parts)

    # Stats agrégées en une requête (sans GROUP BY → O(1) avec les index)
    stats = db.execute(
        f"""SELECT
               COUNT(DISTINCT f.id)                                               AS total,
               SUM(f.is_exploited)                                                AS exploited,
               SUM(CASE WHEN f.vendor IS NOT NULL AND f.vendor!='' THEN 1 ELSE 0 END) AS with_euvd,
               AVG(f.ctx_score)                                                   AS avg_score
            FROM findings f
            JOIN vulnerabilities v ON f.vuln_id=v.id
            WHERE {where}""",
        params,
    ).fetchone()

    total       = stats["total"] or 0
    exploited_c = int(stats["exploited"] or 0)
    with_euvd_c = int(stats["with_euvd"] or 0)
    avg_score   = round(float(stats["avg_score"] or 0), 1)

    if total == 0:
        return [], 0, 0, 0, 0.0

    # Colonnes SQL pour le tri (toutes dans f.* ou v.name — pas d'agrégat)
    _sort_col = {
        "severity": "f.severity", "name": "v.name",   "host": "f.host_ip",
        "port":     "f.port",     "threat": "f.threat", "cve": "f.primary_cve",
        "vendor":   "f.vendor",   "product": "f.product", "epss": "f.epss",
        "score":    "f.ctx_score",
    }
    col       = _sort_col.get(sort_field, "f.ctx_score")
    direction = "DESC" if sort_order == "desc" else "ASC"
    offset    = (page - 1) * per_page

    data_rows = db.execute(
        f"{_FINDING_SELECT} WHERE {where}"
        f" GROUP BY f.id ORDER BY {col} {direction} NULLS LAST"
        f" LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    return [_row_to_vuln(r) for r in data_rows], total, exploited_c, with_euvd_c, avg_score


def query_resolved_findings(db) -> list[dict]:
    """Return all CLOSED findings (scope 'closed') with remediation metrics."""
    from app.statuses import closed_status_ids
    _inc, _sids = _status_in_clause(closed_status_ids())
    sql = (_FINDING_SELECT
           + f" WHERE f.status {_inc}"
           + " GROUP BY f.id ORDER BY f.resolved_at DESC")
    rows = db.execute(sql, list(_sids)).fetchall()
    results = []
    for r in rows:
        v = _row_to_vuln(r)
        v["resolved_at"] = r["resolved_at"] or ""
        days = None
        if r["first_seen"] and r["resolved_at"]:
            try:
                from datetime import datetime as _dt
                t0 = _dt.fromisoformat(r["first_seen"].split("T")[0])
                t1 = _dt.fromisoformat(r["resolved_at"].split("T")[0])
                days = (t1 - t0).days
            except Exception:
                pass
        v["remediation_days"] = days
        sighting_count = db.execute(
            "SELECT COUNT(*) FROM sightings WHERE finding_id=?", (r["id"],)
        ).fetchone()[0]
        v["sighting_count"] = sighting_count
        results.append(v)
    return results


def get_finding_detail(db, finding_id) -> dict | None:
    """Full finding detail with EUVD/ANSSI/KEV data for the modal."""
    row = db.execute(
        _FINDING_SELECT + " WHERE f.id=? GROUP BY f.id", (finding_id,)
    ).fetchone()
    if not row:
        return None

    vuln = _row_to_vuln(row)
    cves = vuln["all_cves"]

    # EUVD raw data + KEV (from unified cves table)
    for cve in cves:
        r = db.execute("SELECT raw_json, is_kev, kev_date_added, kev_sources FROM cves WHERE cve_id=?", (cve,)).fetchone()
        if r and r["raw_json"]:
            vuln["euvd_data"] = json.loads(r["raw_json"])
            vuln["euvd_description"] = vuln["euvd_data"].get("description", "")
            vuln["euvd_references"] = (vuln["euvd_data"].get("references") or "").split("\n")
            break

    # Host tags
    tags = [r["tag_name"] for r in db.execute(
        "SELECT tag_name FROM host_tags WHERE host_ip=?", (vuln["host"],)
    )]
    vuln["host_tags"] = tags

    # ANSSI entries (n:n via anssi_cves + anssi_publications)
    vuln["anssi_entries"] = [dict(r) for r in db.execute("""
        SELECT ac.cve_id, ac.cert_type as type, ap.ref, ap.title, ap.date, ap.url
        FROM anssi_cves ac
        JOIN anssi_publications ap ON ac.ref=ap.ref
        WHERE ac.cve_id IN ({})
        ORDER BY CASE ac.cert_type WHEN 'alerte' THEN 0 ELSE 1 END
    """.format(",".join("?" * len(cves))), cves)] if cves else []

    # KEV entries (from unified cves table)
    vuln["kev_entries"] = []
    for cve in cves:
        r = db.execute("SELECT kev_date_added, kev_sources FROM cves WHERE cve_id=? AND is_kev=1", (cve,)).fetchone()
        if r:
            vuln["kev_entries"].append({
                "cve": cve, "date_added": r["kev_date_added"] or "",
                "sources": json.loads(r["kev_sources"]) if r["kev_sources"] else [],
            })

    # Sightings history
    vuln["sightings"] = [dict(r) for r in db.execute(
        "SELECT task_name, task_id, report_id, scan_date FROM sightings WHERE finding_id=? ORDER BY scan_date DESC",
        (finding_id,)
    )]

    return vuln


_KPIS_SQL_ACTIVE = """
    SELECT COUNT(*) as total,
           SUM(CASE WHEN severity>=9.0 THEN 1 ELSE 0 END) as critical,
           SUM(CASE WHEN severity>=7.0 AND severity<9.0 THEN 1 ELSE 0 END) as high,
           SUM(CASE WHEN severity>=4.0 AND severity<7.0 THEN 1 ELSE 0 END) as medium,
           SUM(CASE WHEN severity>=0.1 AND severity<4.0 THEN 1 ELSE 0 END) as low,
           SUM(is_exploited) as exploited, AVG(ctx_score) as avg_score,
           SUM(CASE WHEN anssi_level='alerte' THEN 1 ELSE 0 END) as anssi_alertes,
           SUM(CASE WHEN anssi_level='avis' THEN 1 ELSE 0 END) as anssi_avis
    FROM findings f WHERE f.status IN ('active','in_progress')
"""
_KPIS_SQL_AT_DATE = """
    SELECT COUNT(*) as total,
           SUM(CASE WHEN severity>=9.0 THEN 1 ELSE 0 END) as critical,
           SUM(CASE WHEN severity>=7.0 AND severity<9.0 THEN 1 ELSE 0 END) as high,
           SUM(CASE WHEN severity>=4.0 AND severity<7.0 THEN 1 ELSE 0 END) as medium,
           SUM(CASE WHEN severity>=0.1 AND severity<4.0 THEN 1 ELSE 0 END) as low,
           SUM(is_exploited) as exploited, AVG(ctx_score) as avg_score,
           SUM(CASE WHEN anssi_level='alerte' THEN 1 ELSE 0 END) as anssi_alertes,
           SUM(CASE WHEN anssi_level='avis' THEN 1 ELSE 0 END) as anssi_avis
    FROM findings f WHERE f.first_seen <= ? AND (f.resolved_at IS NULL OR f.resolved_at > ?)
"""
_HOSTS_SQL_ACTIVE = """
    SELECT f.host_ip,
           SUM(CASE WHEN f.severity>=9.0 THEN 1 ELSE 0 END) as critical,
           SUM(CASE WHEN f.severity>=7.0 AND f.severity<9.0 THEN 1 ELSE 0 END) as high,
           SUM(CASE WHEN f.severity>=4.0 AND f.severity<7.0 THEN 1 ELSE 0 END) as medium,
           SUM(CASE WHEN f.severity>=0.1 AND f.severity<4.0 THEN 1 ELSE 0 END) as low
    FROM findings f WHERE f.status IN ('active','in_progress')
    GROUP BY f.host_ip ORDER BY critical DESC, high DESC, medium DESC LIMIT 10
"""
_HOSTS_SQL_AT_DATE = """
    SELECT f.host_ip,
           SUM(CASE WHEN f.severity>=9.0 THEN 1 ELSE 0 END) as critical,
           SUM(CASE WHEN f.severity>=7.0 AND f.severity<9.0 THEN 1 ELSE 0 END) as high,
           SUM(CASE WHEN f.severity>=4.0 AND f.severity<7.0 THEN 1 ELSE 0 END) as medium,
           SUM(CASE WHEN f.severity>=0.1 AND f.severity<4.0 THEN 1 ELSE 0 END) as low
    FROM findings f WHERE f.first_seen <= ? AND (f.resolved_at IS NULL OR f.resolved_at > ?)
    GROUP BY f.host_ip ORDER BY critical DESC, high DESC, medium DESC LIMIT 10
"""
_PRODS_SQL_ACTIVE = """
    SELECT CASE WHEN f.product!='' THEN f.vendor||' — '||f.product ELSE f.vendor END as label,
           COUNT(*) as cnt, MAX(f.severity) as max_sev, SUM(f.is_exploited) as exploited
    FROM findings f WHERE f.status IN ('active','in_progress') AND f.vendor!='' AND f.vendor IS NOT NULL
    GROUP BY label ORDER BY cnt DESC, max_sev DESC LIMIT 10
"""
_PRODS_SQL_AT_DATE = """
    SELECT CASE WHEN f.product!='' THEN f.vendor||' — '||f.product ELSE f.vendor END as label,
           COUNT(*) as cnt, MAX(f.severity) as max_sev, SUM(f.is_exploited) as exploited
    FROM findings f WHERE f.first_seen <= ? AND (f.resolved_at IS NULL OR f.resolved_at > ?)
           AND f.vendor!='' AND f.vendor IS NOT NULL
    GROUP BY label ORDER BY cnt DESC, max_sev DESC LIMIT 10
"""
_TOP_VULNS_ACTIVE = _FINDING_SELECT + " WHERE f.status IN ('active','in_progress') GROUP BY f.id ORDER BY f.ctx_score DESC, f.severity DESC LIMIT 10"
_TOP_VULNS_AT_DATE = _FINDING_SELECT + " WHERE f.first_seen <= ? AND (f.resolved_at IS NULL OR f.resolved_at > ?) GROUP BY f.id ORDER BY f.ctx_score DESC, f.severity DESC LIMIT 10"


def _validate_date(at_date: str) -> str | None:
    """Valide un format YYYY-MM-DD strict. Retourne None si invalide."""
    import re
    if at_date and re.match(r"^\d{4}-\d{2}-\d{2}$", at_date):
        return at_date
    return None


def get_dashboard_stats(db, at_date: str = None) -> dict:
    """Compute dashboard KPIs and chart data. Si at_date fourni, simule l'état à cette date."""
    at_date = _validate_date(at_date)

    if at_date:
        p = [at_date, at_date]
        row = db.execute(_KPIS_SQL_AT_DATE, p).fetchone()
        top_hosts_rows = db.execute(_HOSTS_SQL_AT_DATE, p).fetchall()
        top_prod_rows = db.execute(_PRODS_SQL_AT_DATE, p).fetchall()
        top_rows = db.execute(_TOP_VULNS_AT_DATE, p).fetchall()
    else:
        _o, _old = _open_in(), "IN ('active','in_progress')"
        row = db.execute(_KPIS_SQL_ACTIVE.replace(_old, _o)).fetchone()
        top_hosts_rows = db.execute(_HOSTS_SQL_ACTIVE.replace(_old, _o)).fetchall()
        top_prod_rows = db.execute(_PRODS_SQL_ACTIVE.replace(_old, _o)).fetchall()
        top_rows = db.execute(_TOP_VULNS_ACTIVE.replace(_old, _o)).fetchall()

    total = row["total"] or 0
    hosts_count = db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] or 0

    tasks = read_gmp_cache(db, "tasks")
    active_scans = sum(1 for t in tasks if t.get("status") in ("Running", "Requested"))

    severity_dist = {
        "critical": row["critical"] or 0, "high": row["high"] or 0,
        "medium": row["medium"] or 0, "low": row["low"] or 0,
    }

    top_hosts = [(r["host_ip"], {"critical": r["critical"], "high": r["high"],
                                  "medium": r["medium"], "low": r["low"],
                                  "hostname": hostname_for(r["host_ip"])})
                 for r in top_hosts_rows]

    top_products = [(r["label"], {"count": r["cnt"], "max_sev": r["max_sev"],
                                   "exploited": r["exploited"] or 0})
                    for r in top_prod_rows]

    top_vulns = [_row_to_vuln(r) for r in top_rows]

    # Plage de dates pour le slider
    date_range = db.execute(
        "SELECT MIN(date(first_seen)) as min_date, MAX(date(first_seen)) as max_date FROM findings"
    ).fetchone()

    return {
        "total_vulns": total,
        "critical_count": row["critical"] or 0,
        "high_count": row["high"] or 0,
        "medium_count": row["medium"] or 0,
        "low_count": row["low"] or 0,
        "exploited_count": row["exploited"] or 0,
        "avg_score": round(row["avg_score"] or 0, 1),
        "anssi_alertes": row["anssi_alertes"] or 0,
        "anssi_avis": row["anssi_avis"] or 0,
        "hosts_count": hosts_count,
        "active_scans": active_scans,
        "severity_dist": severity_dist,
        "top_hosts": top_hosts,
        "top_products": top_products,
        "top_vulns": top_vulns,
        "at_date": at_date,
        "date_min": date_range["min_date"] or "",
        "date_max": date_range["max_date"] or "",
        "date_today": datetime.now().strftime("%Y-%m-%d"),
    }


def get_timeline_data(db, date_from: str, date_to: str) -> dict:
    """Compute time series data for the Tendances tab."""

    # Tous les événements (first_seen, resolved_at) dans la plage
    events = db.execute("""
        SELECT substr(first_seen,1,10) as d, 'new' as type, COUNT(*) as cnt
        FROM findings WHERE substr(first_seen,1,10) BETWEEN ? AND ?
        GROUP BY d
        UNION ALL
        SELECT substr(resolved_at,1,10) as d, 'resolved' as type, COUNT(*) as cnt
        FROM findings WHERE resolved_at IS NOT NULL AND substr(resolved_at,1,10) BETWEEN ? AND ?
        GROUP BY d
        ORDER BY d
    """, (date_from, date_to, date_from, date_to)).fetchall()

    new_by_date = {}
    resolved_by_date = {}
    for e in events:
        if e["type"] == "new":
            new_by_date[e["d"]] = e["cnt"]
        else:
            resolved_by_date[e["d"]] = e["cnt"]

    # Active count par semaine (échantillonné)
    from datetime import date as _date, timedelta
    d0 = _date.fromisoformat(date_from)
    d1 = _date.fromisoformat(date_to)
    span = (d1 - d0).days
    step = max(1, span // 60)

    active_series = []
    d = d0
    while d <= d1:
        ds = d.isoformat()
        cnt = db.execute("""
            SELECT COUNT(*) FROM findings
            WHERE substr(first_seen,1,10) <= ? AND (resolved_at IS NULL OR substr(resolved_at,1,10) > ?)
        """, (ds, ds)).fetchone()[0]
        active_series.append({"date": ds, "count": cnt})
        d += timedelta(days=step)

    # Sévérité par semaine
    severity_series = []
    d = d0
    while d <= d1:
        ds = d.isoformat()
        row = db.execute("""
            SELECT SUM(CASE WHEN severity>=9.0 THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN severity>=7.0 AND severity<9.0 THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN severity>=4.0 AND severity<7.0 THEN 1 ELSE 0 END) as medium,
                   SUM(CASE WHEN severity>=0.1 AND severity<4.0 THEN 1 ELSE 0 END) as low
            FROM findings
            WHERE substr(first_seen,1,10) <= ? AND (resolved_at IS NULL OR substr(resolved_at,1,10) > ?)
        """, (ds, ds)).fetchone()
        severity_series.append({
            "date": ds, "critical": row["critical"] or 0, "high": row["high"] or 0,
            "medium": row["medium"] or 0, "low": row["low"] or 0,
        })
        d += timedelta(days=step)

    # Remédiation mensuelle — durée MÉDIANE (robuste : la moyenne est tirée vers
    # le haut par les findings anciens). On exclut le churn transitoire (résolu
    # le jour même de sa 1re apparition = artefact de scan, pas un cycle réel).
    rem_rows = db.execute("""
        SELECT strftime('%Y-%m', substr(resolved_at,1,10)) as month,
               CAST(julianday(substr(resolved_at,1,10))
                    - julianday(substr(first_seen,1,10)) AS INTEGER) as days
        FROM findings
        WHERE resolved_at IS NOT NULL
          AND substr(resolved_at,1,10) BETWEEN ? AND ?
          AND substr(resolved_at,1,10) != substr(first_seen,1,10)
    """, (date_from, date_to)).fetchall()

    def _median(vals):
        s = sorted(vals)
        n = len(s)
        if n == 0:
            return 0
        mid = n // 2
        return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2

    _rem_by_month: dict = {}
    for r in rem_rows:
        if r["days"] is not None and r["days"] >= 0:
            _rem_by_month.setdefault(r["month"], []).append(r["days"])
    remediation = [{"month": m, "count": len(v), "median_days": round(_median(v))}
                   for m, v in sorted(_rem_by_month.items())]

    return {
        "active_series": active_series,
        "severity_series": severity_series,
        "new_by_date": new_by_date,
        "resolved_by_date": resolved_by_date,
        "remediation": remediation,
    }


def get_scan_imports(db) -> dict:
    """Return {task_id: {task_name, report_id, scan_date, ...}} for task selector."""
    rows = db.execute("""
        SELECT task_id, task_name, report_id, scan_date, imported_at, results_count
        FROM scan_imports ORDER BY imported_at DESC
    """).fetchall()
    meta = {}
    for r in rows:
        if r["task_id"] not in meta:
            meta[r["task_id"]] = {
                "task_name": r["task_name"],
                "report_id": r["report_id"],
                "scan_date": r["scan_date"],
                "date": r["imported_at"],
                "results_count": r["results_count"],
            }
    return meta
