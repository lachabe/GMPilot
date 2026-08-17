"""
Module de scoring contextualisé des vulnérabilités.
Gère le cache ANSSI, le chargement de la config et le calcul des scores.
"""
import os
import re
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Callable

import yaml
from flask import current_app

logger = logging.getLogger(__name__)

# Pattern CVE
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# URLs CERT-FR (endpoints JSON)
CERTFR_JSON_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/json/"
CERTFR_JSON_AVIS = "https://www.cert.ssi.gouv.fr/avis/json/"
CERTFR_BASE_URL = "https://www.cert.ssi.gouv.fr"


# ══════════════════════════════════════════════════════════════════════════════
# Cache ANSSI (CERT-FR) - Structure fichiers
# ══════════════════════════════════════════════════════════════════════════════

def read_anssi_cache() -> dict:
    """Lit l'index ANSSI depuis SQLite. {CVE_ID: {type, ref, title, date, url}}."""
    try:
        from app.db import get_db
        db = get_db()
        return {r["cve_id"]: {"type": r["cert_type"], "ref": r["ref"]}
                for r in db.execute("SELECT cve_id, cert_type, ref FROM anssi_cves")}
    except Exception:
        return {}


def _fetch_json(url: str, timeout: int = 30) -> dict | list | None:
    """Récupère et parse un JSON depuis une URL."""
    import urllib.request
    import urllib.error

    try:
        logger.info(f"Fetching: {url}")
        req = urllib.request.Request(url, headers={
            "User-Agent": "GMPILOT-ANSSI-Cache/1.0",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            data = json.loads(resp.read().decode("utf-8"))
            logger.info(f"Fetched OK: {url} ({len(data) if isinstance(data, list) else 'dict'})")
            return data
    except urllib.error.URLError as e:
        logger.error(f"Erreur URL fetch {url}: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Erreur JSON fetch {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur inattendue fetch {url}: {e}")
        return None


def _get_existing_refs(conn, cert_type: str) -> set:
    """Retourne les références déjà téléchargées depuis SQLite."""
    rows = conn.execute(
        "SELECT ref FROM anssi_publications WHERE cert_type=?", (cert_type,)
    ).fetchall()
    return {r[0] for r in rows}


def _download_anssi_publications(cert_type: str, items_to_download: list,
                            rate_limit: float = 0.1,
                            progress_callback: Callable = None) -> tuple[int, int]:
    """Télécharge les détails manquants et les stocke en SQLite par batch."""
    import time
    from app.db import connect_db

    downloaded = 0
    errors = 0
    total = len(items_to_download)
    now = datetime.now().isoformat()
    batch = []
    BATCH_SIZE = 20

    logger.info(f"ANSSI: début téléchargement {total} {cert_type}s")

    for i, item in enumerate(items_to_download):
        ref = item.get("reference", "")
        json_url = item.get("json_url", "")
        if not ref or not json_url:
            continue

        if progress_callback:
            try:
                progress_callback(i + 1, total, f"Téléchargement {ref}...")
            except Exception:
                pass

        if json_url.startswith("/"):
            json_url = CERTFR_BASE_URL + json_url

        if downloaded > 0:
            time.sleep(rate_limit)

        detail = _fetch_json(json_url, timeout=15)
        if not detail:
            errors += 1
            continue

        batch.append((ref, cert_type, json.dumps(detail, ensure_ascii=False), now))
        downloaded += 1

        if len(batch) >= BATCH_SIZE:
            conn = connect_db()
            conn.executemany(
                "INSERT OR REPLACE INTO anssi_publications (ref, cert_type, raw_json, updated_at) VALUES (?,?,?,?)",
                batch,
            )
            conn.commit()
            conn.close()
            batch = []
            logger.info(f"CERT-FR {cert_type}: {downloaded}/{total} téléchargés...")

    if batch:
        conn = connect_db()
        conn.executemany(
            "INSERT OR REPLACE INTO anssi_publications (ref, cert_type, raw_json, updated_at) VALUES (?,?,?,?)",
            batch,
        )
        conn.commit()
        conn.close()

    return downloaded, errors


def _build_anssi_index(conn) -> dict:
    """Reconstruit l'index CVE depuis anssi_publications en SQLite."""
    index = {}

    for cert_type in ["alerte", "avis"]:
        rows = conn.execute(
            "SELECT ref, raw_json FROM anssi_publications WHERE cert_type=?", (cert_type,)
        ).fetchall()

        for row in rows:
            ref = row[0]
            try:
                detail = json.loads(row[1])
            except (json.JSONDecodeError, TypeError):
                continue

            title = detail.get("title", "")
            date = ""
            revisions = detail.get("revisions", [])
            if revisions:
                date = revisions[0].get("revision_date", "")[:10]

            page_url = f"{CERTFR_BASE_URL}/{cert_type}/{ref}/"

            cves_list = detail.get("cves", [])
            for cve_obj in cves_list:
                cve_name = ""
                if isinstance(cve_obj, dict):
                    cve_name = cve_obj.get("name", "") or cve_obj.get("cve", "")
                elif isinstance(cve_obj, str):
                    cve_name = cve_obj

                if not cve_name or not CVE_PATTERN.match(cve_name):
                    continue

                cve_upper = cve_name.upper().strip()

                if cve_upper in index and index[cve_upper]["type"] == "alerte" and cert_type == "avis":
                    continue

                index[cve_upper] = {
                    "type": cert_type,
                    "ref": ref,
                    "title": title[:200],
                    "date": date,
                    "url": page_url,
                }

    return index


def fetch_anssi_cache(full_refresh: bool = False, progress_callback: Callable = None) -> tuple[dict, str | None]:
    """Télécharge/met à jour le cache ANSSI depuis les endpoints JSON CERT-FR.
    Stocke les détails en SQLite (anssi_publications), reconstruit l'index (anssi_cves)."""
    from app.db import connect_db, import_anssi_index as _import_index

    logger.info(f"=== ANSSI cache refresh START (full={full_refresh}) ===")

    errors = []
    total_downloaded = 0

    for cert_type, list_url in [("alerte", CERTFR_JSON_ALERTES), ("avis", CERTFR_JSON_AVIS)]:
        if progress_callback:
            try:
                progress_callback(None, f"Téléchargement liste {cert_type}s...")
            except Exception:
                pass

        logger.info(f"CERT-FR: téléchargement liste {cert_type}s...")
        items = _fetch_json(list_url, timeout=60)

        if not items or not isinstance(items, list):
            logger.error(f"CERT-FR: échec récupération liste {cert_type}s")
            errors.append(f"Impossible de récupérer la liste {cert_type}s")
            continue

        logger.info(f"CERT-FR {cert_type}: {len(items)} entrées dans la liste")

        conn = connect_db()
        existing_refs = _get_existing_refs(conn, cert_type)
        conn.close()

        items_to_download = [
            item for item in items
            if item.get("reference") and item.get("reference") not in existing_refs
        ]

        logger.info(f"CERT-FR {cert_type}: {len(existing_refs)} existants, {len(items_to_download)} à télécharger")

        if items_to_download:
            current_cert_type = cert_type

            def detail_callback(current, total, msg, ct=current_cert_type):
                if progress_callback:
                    try:
                        progress_callback(f"{current}/{total}", f"{ct.capitalize()}s: {msg}")
                    except Exception:
                        pass

            downloaded, err_count = _download_anssi_publications(
                cert_type, items_to_download, progress_callback=detail_callback
            )
            total_downloaded += downloaded
            if err_count > 0:
                errors.append(f"{cert_type}s: {err_count} erreurs")

    if progress_callback:
        try:
            progress_callback(None, "Reconstruction de l'index CVE...")
        except Exception:
            pass

    logger.info("CERT-FR: reconstruction de l'index CVE...")
    conn = connect_db()
    try:
        index = _build_anssi_index(conn)
        _import_index(conn, index)
    finally:
        conn.close()

    logger.info(f"=== ANSSI cache refresh END: {len(index)} CVE, {total_downloaded} téléchargés ===")

    error_msg = "; ".join(errors) if errors else None
    return index, error_msg


def get_anssi_cache_stats() -> dict:
    """Retourne les stats du cache ANSSI depuis SQLite."""
    try:
        from app.db import get_db
        db = get_db()
        pubs = db.execute("""
            SELECT cert_type, COUNT(*) as cnt FROM anssi_publications GROUP BY cert_type
        """).fetchall()
        alertes_pubs = sum(r["cnt"] for r in pubs if r["cert_type"] == "alerte")
        avis_pubs = sum(r["cnt"] for r in pubs if r["cert_type"] == "avis")

        row = db.execute("""
            SELECT COUNT(DISTINCT cve_id) as cnt, MAX(ap.updated_at) as dt,
                   SUM(CASE WHEN ac.cert_type='alerte' THEN 1 ELSE 0 END) as alertes,
                   SUM(CASE WHEN ac.cert_type='avis' THEN 1 ELSE 0 END) as avis
            FROM anssi_cves ac
            JOIN anssi_publications ap ON ac.ref=ap.ref
        """).fetchone()

        return {
            "exists": (row["cnt"] or 0) > 0,
            "count": row["cnt"] or 0,
            "alertes": row["alertes"] or 0,
            "avis": row["avis"] or 0,
            "alertes_files": alertes_pubs,
            "avis_files": avis_pubs,
            "date": row["dt"] or "—",
        }
    except Exception:
        return {"exists": False, "count": 0, "alertes": 0, "avis": 0,
                "alertes_files": 0, "avis_files": 0, "date": "—"}


# ══════════════════════════════════════════════════════════════════════════════
# Configuration du scoring
# ══════════════════════════════════════════════════════════════════════════════

def _scoring_config_path() -> str:
    """Chemin du fichier de configuration scoring."""
    # Chercher dans config/ à la racine du projet
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_dir, "config", "scoring.yaml")


def load_scoring_config() -> dict:
    """Charge la configuration du scoring depuis le YAML."""
    path = _scoring_config_path()
    if not os.path.exists(path):
        logger.warning(f"Fichier scoring.yaml introuvable: {path}")
        return {"scoring": {"name": "Score contextualisé", "criteria": [], "formula": "0"}}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logger.error(f"Erreur parsing scoring.yaml: {e}")
        return {"scoring": {"name": "Score contextualisé", "criteria": [], "formula": "0"}}


def save_scoring_config(config: dict) -> tuple[bool, str | None]:
    """Sauvegarde la configuration du scoring."""
    path = _scoring_config_path()
    try:
        # Créer le dossier si nécessaire
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        return True, None
    except Exception as e:
        logger.error(f"Erreur sauvegarde scoring.yaml: {e}")
        return False, str(e)


def generate_formula_from_criteria(criteria: list) -> str:
    """
    Génère automatiquement la formule depuis les critères.
    Format: (({id1} * weight1) + ({id2} * weight2) + ...) / total_weight * 100
    """
    if not criteria:
        return "0"

    parts = []
    total_weight = 0
    for c in criteria:
        cid = c.get("id", "")
        weight = c.get("weight", 1)
        if cid:
            parts.append(f"({{{{ {cid} }}}} * {weight})")
            total_weight += weight

    if not parts or total_weight == 0:
        return "0"

    return f"({' + '.join(parts)}) / {total_weight} * 100"


# ══════════════════════════════════════════════════════════════════════════════
# Calcul du score
# ══════════════════════════════════════════════════════════════════════════════

def _get_criterion_value(criterion: dict, vuln: dict, host_tags: list[str],
                         kev_data: dict, anssi_data: dict) -> float:
    """
    Calcule la valeur d'un critère pour une vulnérabilité donnée.
    
    Args:
        criterion: Définition du critère depuis la config
        vuln: Dict de la vulnérabilité enrichie
        host_tags: Liste des tags de l'hôte
        kev_data: Cache KEV
        anssi_data: Cache ANSSI
    
    Returns:
        Valeur entre 0 et 1
    """
    source = criterion.get("source", "")
    values = criterion.get("values", [])
    normalize = criterion.get("normalize", "")

    # Trouver la valeur par défaut
    default_value = 0.0
    for v in values:
        if "default" in v:
            default_value = v.get("default", 0.0)
            break

    # === Source: severity (CVSS) ===
    if source == "severity":
        sev = vuln.get("severity", 0.0)
        if normalize == "scale_0_1":
            return min(1.0, max(0.0, sev / 10.0))
        elif normalize == "threshold":
            # Chercher le seuil correspondant
            for v in values:
                threshold = v.get("threshold")
                if threshold is not None and sev >= threshold:
                    return v.get("value", default_value)
            return default_value
        return min(1.0, max(0.0, sev / 10.0))  # Par défaut scale_0_1

    # === Source: epss ===
    if source == "epss":
        epss = vuln.get("euvd_epss")
        if epss is None:
            return default_value
        if normalize == "scale_0_1":
            return min(1.0, max(0.0, float(epss)))
        elif normalize == "threshold":
            for v in values:
                threshold = v.get("threshold")
                if threshold is not None and epss >= threshold:
                    return v.get("value", default_value)
            return default_value
        return min(1.0, max(0.0, float(epss)))

    # === Source: qod ===
    if source == "qod":
        qod_str = vuln.get("qod", "0")
        try:
            qod = float(qod_str.replace("%", "")) if isinstance(qod_str, str) else float(qod_str)
        except (ValueError, TypeError):
            qod = 0.0
        if normalize == "scale_0_1":
            return min(1.0, max(0.0, qod / 100.0))
        return min(1.0, max(0.0, qod / 100.0))

    # === Source: kev ===
    if source == "kev":
        cves = vuln.get("all_cves", [])
        if not cves:
            cve = vuln.get("cve", "")
            cves = [cve] if cve and cve != "—" else []

        is_in_kev = any(c.upper() in kev_data for c in cves) if kev_data else False

        for v in values:
            match = v.get("match")
            if match is True and is_in_kev:
                return v.get("value", 1.0)
            elif match is False and not is_in_kev:
                return v.get("value", 0.0)
        return default_value

    # === Source: anssi ===
    if source == "anssi":
        cves = vuln.get("all_cves", [])
        if not cves:
            cve = vuln.get("cve", "")
            cves = [cve] if cve and cve != "—" else []

        # Chercher le type ANSSI le plus prioritaire (alerte > avis)
        anssi_type = None
        for c in cves:
            entry = anssi_data.get(c.upper())
            if entry:
                entry_type = entry.get("type", "")
                if entry_type == "alerte":
                    anssi_type = "alerte"
                    break  # Priorité max
                elif entry_type == "avis" and anssi_type != "alerte":
                    anssi_type = "avis"

        if anssi_type:
            for v in values:
                if v.get("match") == anssi_type:
                    return v.get("value", 0.5)
        return default_value

    # === Source: host_tag ===
    if source == "host_tag":
        tag_name = criterion.get("tag_name", "")
        if not tag_name:
            return default_value

        # Chercher si le tag existe parmi les tags de l'hôte
        # Format GVM: le tag complet est dans le champ name (ex: "host:exposed")
        tag_exists = tag_name in host_tags

        for v in values:
            match = v.get("match")
            if match is True and tag_exists:
                return v.get("value", 1.0)
            elif match is False and not tag_exists:
                return v.get("value", 0.0)
        
        return default_value

    # Source inconnue
    logger.warning(f"Source de critère inconnue: {source}")
    return default_value


def calculate_score(vuln: dict, host_tags: list[str] = None,
                    kev_data: dict = None, anssi_data: dict = None,
                    config: dict = None) -> dict:
    """
    Calcule le score contextualisé d'une vulnérabilité.
    
    Args:
        vuln: Dict de la vulnérabilité enrichie
        host_tags: Liste des tags de l'hôte (optionnel)
        kev_data: Cache KEV (chargé automatiquement si None)
        anssi_data: Cache ANSSI (chargé automatiquement si None)
        config: Config scoring (chargée automatiquement si None)
    
    Returns:
        Dict avec score et détails: {score, details: {criterion_id: value}}
    """
    from app.blueprints.cache import read_kev_cache

    # Charger les données si non fournies
    if config is None:
        config = load_scoring_config()
    if kev_data is None:
        kev_data = read_kev_cache() or {}
    if anssi_data is None:
        anssi_data = read_anssi_cache()
    if host_tags is None:
        host_tags = []

    scoring = config.get("scoring", {})
    criteria = scoring.get("criteria", [])
    formula = scoring.get("formula", "0")

    if not criteria:
        return {"score": 0, "details": {}}

    # Calculer la valeur de chaque critère
    details = {}
    for criterion in criteria:
        cid = criterion.get("id", "")
        if cid:
            value = _get_criterion_value(criterion, vuln, host_tags, kev_data, anssi_data)
            details[cid] = round(value, 4)

    # Évaluer la formule
    try:
        # Remplacer les {variables} par les valeurs
        formula_eval = formula
        for cid, value in details.items():
            formula_eval = formula_eval.replace(f"{{{cid}}}", str(value))

        # Évaluer l'expression mathématique (sécurisé)
        score = _safe_eval(formula_eval)
        score = min(100, max(0, round(score, 1)))
    except Exception as e:
        logger.error(f"Erreur évaluation formule: {e} | Formule: {formula_eval}")
        score = 0

    return {"score": score, "details": details}


def _safe_eval(expression: str) -> float:
    """
    Évalue une expression mathématique via AST Python — sans eval().
    Autorise uniquement : constantes numériques et opérateurs +-*/.
    Toute tentative d'injection de code lève ValueError.
    """
    import ast as _ast
    import operator as _op

    _ALLOWED_OPS = {
        _ast.Add:  _op.add,
        _ast.Sub:  _op.sub,
        _ast.Mult: _op.mul,
        _ast.Div:  _op.truediv,
        _ast.Pow:  _op.pow,
        _ast.USub: _op.neg,
        _ast.UAdd: _op.pos,
    }

    def _eval(node):
        if isinstance(node, _ast.Constant):
            if not isinstance(node.value, (int, float)):
                raise ValueError(f"Type non autorisé: {type(node.value)}")
            return float(node.value)
        if isinstance(node, _ast.BinOp):
            op_type = type(node.op)
            if op_type not in _ALLOWED_OPS:
                raise ValueError(f"Opérateur non autorisé: {op_type}")
            return _ALLOWED_OPS[op_type](_eval(node.left), _eval(node.right))
        if isinstance(node, _ast.UnaryOp):
            op_type = type(node.op)
            if op_type not in _ALLOWED_OPS:
                raise ValueError(f"Opérateur unaire non autorisé: {op_type}")
            return _ALLOWED_OPS[op_type](_eval(node.operand))
        raise ValueError(f"Nœud AST non autorisé: {_ast.dump(node)}")

    tree = _ast.parse(expression.strip(), mode="eval")
    return float(_eval(tree.body))


def calculate_scores_batch(vulns: list, host_tags_map: dict = None) -> list:
    """
    Calcule les scores pour une liste de vulnérabilités.
    Optimisé pour éviter de recharger les caches à chaque fois.
    
    Args:
        vulns: Liste de vulnérabilités enrichies
        host_tags_map: Dict {host_ip: [tags]} pour les tags par hôte
    
    Returns:
        Liste des vulns avec score ajouté
    """
    from app.blueprints.cache import read_kev_cache

    # Charger les données une seule fois
    config = load_scoring_config()
    kev_data = read_kev_cache() or {}
    anssi_data = read_anssi_cache()

    if host_tags_map is None:
        host_tags_map = {}

    for vuln in vulns:
        host = vuln.get("host", "")
        host_tags = host_tags_map.get(host, [])

        result = calculate_score(vuln, host_tags, kev_data, anssi_data, config)
        vuln["ctx_score"] = result["score"]
        vuln["ctx_score_details"] = result["details"]

    return vulns
