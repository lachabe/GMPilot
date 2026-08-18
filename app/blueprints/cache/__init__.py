from app.auth.permissions import require_perm
"""
Cache blueprint — télécharge et gère les XML GMP en cache local.
Page d'accueil de l'application.
Inclut le cache CVE (EUVD) pour enrichissement des vulnérabilités.
"""
import os
import json
import time
import threading
import logging
import re
from datetime import datetime
from xml.etree import ElementTree as ET
try:
    import defusedxml.ElementTree as _safe_ET
    _ET_parse = _safe_ET.parse
except ImportError:
    import logging as _log
    _log.getLogger(__name__).warning(
        "defusedxml non installé (pip install defusedxml) — "
        "parsing XML potentiellement vulnérable aux XXE"
    )
    _ET_parse = ET.parse
except Exception:
    _ET_parse = ET.parse
from flask import Blueprint, render_template, redirect, url_for, flash, current_app, request
from flask_login import login_required, current_user
from app.gvm_client import (gmp_session, gmp_get_hosts)

cache_bp = Blueprint("cache", __name__, url_prefix="/sync")
logger = logging.getLogger(__name__)

# ── Définition des caches XML ────────────────────────────────────────────────
CACHE_DEFS = {
    "tasks":       {"label": "Tâches de scan",     "filter": "rows=-1 first=1"},
    "targets":     {"label": "Cibles",             "filter": "rows=-1 first=1"},
    "schedules":   {"label": "Planifications",     "filter": "rows=-1 first=1"},
    "hosts":       {"label": "Hôtes",              "filter": "rows=-1 first=1"},
    "tags":        {"label": "Tags",               "filter": "rows=-1 first=1"},
    "port_lists":  {"label": "Listes de ports",    "filter": ""},
    "scanners":    {"label": "Scanners",           "filter": ""},
    "feeds":       {"label": "Flux de données",    "filter": ""},
    "scan_configs":{"label": "Configurations",     "filter": ""},
}

# Filtre résultats par rapport (levels=mhc exclut les logs)
VULNS_RESULTS_FILTER = "rows=-1 min_qod=70 apply_overrides=1 levels=mhc sort-reverse=severity"

# ── Configuration EUVD ───────────────────────────────────────────────────────
EUVD_API_BASE = "https://euvdservices.enisa.europa.eu/api/enisaid"
EUVD_KEV_DUMP = "https://euvdservices.enisa.europa.eu/api/kev/dump"
EUVD_WEB_BASE = "https://euvd.enisa.europa.eu/vulnerability"
EUVD_TIMEOUT = 10  # timeout requête HTTP

# Référentiel IANA Service Name / Port Number (XML)
IANA_SERVICES_XML = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml"
IANA_NS = "http://www.iana.org/assignments"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _get_rate_limit() -> float:
    """Délai minimal (secondes) entre deux requêtes EUVD.

    Source : Config.EUVD_RATE_LIMIT (app/config.py), qui lit elle-même l'env
    EUVD_RATE_LIMIT. EUVD limite à ~1 requête / 6 secondes → défaut 6.0s.
    Fallback env/défaut si appelé hors contexte applicatif.
    """
    default = 6.0
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            return max(0.0, float(current_app.config.get("EUVD_RATE_LIMIT", default)))
    except Exception:
        pass
    try:
        return max(0.0, float(os.environ.get("EUVD_RATE_LIMIT", str(default))))
    except (TypeError, ValueError):
        return default


# Throttle GLOBAL des requêtes EUVD — partagé entre TOUS les threads/tâches.
# EUVD limite à ~1 requête / 6s par IP : cpe_watch, cve_update et le refresh CVE
# pouvant tourner en parallèle, un espacement par-tâche ne suffit pas (le débit
# cumulé dépasse la limite → 429). Ce verrou sérialise l'accès à EUVD globalement.
_euvd_throttle_lock = threading.Lock()
_euvd_last_ts = 0.0  # time.monotonic() de la dernière requête EUVD


def _euvd_wait_slot() -> None:
    """Bloque jusqu'à ce qu'au moins EUVD_RATE_LIMIT secondes se soient écoulées
    depuis la dernière requête EUVD, tous threads confondus."""
    global _euvd_last_ts
    delay = _get_rate_limit()
    with _euvd_throttle_lock:
        wait = delay - (time.monotonic() - _euvd_last_ts)
        if wait > 0:
            time.sleep(wait)
        _euvd_last_ts = time.monotonic()


def _get_page_size() -> int:
    """Taille de page de la recherche EUVD (Config.EUVD_PAGE_SIZE, défaut 100).

    Augmenter réduit le nombre de requêtes (donc les 429). Repli env/défaut si
    appelé hors contexte applicatif. Borné à [1, 2000].
    """
    default = 100
    val = default
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            val = current_app.config.get("EUVD_PAGE_SIZE", default)
        else:
            val = os.environ.get("EUVD_PAGE_SIZE", default)
    except Exception:
        val = os.environ.get("EUVD_PAGE_SIZE", default)
    try:
        return max(1, min(2000, int(val)))
    except (TypeError, ValueError):
        return default


def _api_get_json(url: str, *, timeout: int = EUVD_TIMEOUT,
                  max_attempts: int = 4, label: str = "",
                  throttle: bool = True) -> tuple[dict | None, str | None]:
    """GET JSON partagé pour tous les appels EUVD/MITRE.

    Gestion unifiée du rate-limit et des erreurs, gouvernée par _get_rate_limit() :
      - throttle global : chaque requête EUVD attend un créneau libre (1 req/6s
                          tous threads confondus). throttle=False pour MITRE
                          (service tiers, hors budget EUVD).
      - 429       : respect de Retry-After si fourni, sinon backoff exponentiel
                    (5 → 10 → 20 → 40 → 60s), puis réessai.
      - 400/404   : définitif (le CVE/produit n'existe pas) → pas de réessai.
      - 5xx/réseau: réessai avec backoff = rate-limit × tentative.

    Retourne (data, None) en cas de succès, sinon (None, message_erreur).
    """
    import urllib.request
    import urllib.error

    base_delay = _get_rate_limit()
    last_err = "inconnu"
    for attempt in range(max_attempts):
        if throttle:
            _euvd_wait_slot()  # créneau global partagé entre tâches
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/json", "User-Agent": "GMPilot/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8")), None
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}"
            if e.code == 429:
                ra = e.headers.get("Retry-After") if e.headers else None
                try:
                    wait = float(ra) if ra else 0.0
                except (TypeError, ValueError):
                    wait = 0.0
                if wait <= 0:
                    wait = min(60.0, 5.0 * (2 ** attempt))
                logger.warning(
                    f"[EUVD] 429 (rate limit){' ' + label if label else ''} "
                    f"→ pause {wait:.0f}s (tentative {attempt + 1}/{max_attempts})")
                time.sleep(wait)
            elif e.code in (400, 404):
                return None, last_err  # ressource absente → inutile de réessayer
            else:
                time.sleep(base_delay * (attempt + 1))
        except Exception as e:
            last_err = str(e)
            time.sleep(base_delay * (attempt + 1))
    return None, last_err


def _cache_path(key):
    return os.path.join(current_app.config["CACHE_DIR"], f"{key}.xml")


def _vulns_dir() -> str:
    """Retourne le chemin du sous-dossier cache/vulns/, le crée si nécessaire."""
    d = os.path.join(current_app.config["CACHE_DIR"], "vulns")
    os.makedirs(d, exist_ok=True)
    return d


def _vulns_meta_path() -> str:
    return os.path.join(current_app.config["CACHE_DIR"], "vulns_meta.json")


def read_vulns_meta() -> dict:
    """Lit le meta JSON des vulns {task_id: {report_id, task_name, date, size_kb}}."""
    path = _vulns_meta_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def write_vulns_meta(meta: dict):
    with open(_vulns_meta_path(), "w") as f:
        json.dump(meta, f, indent=2)


def get_vulns_cache_meta() -> dict:
    """Métadonnées agrégées du cache vulns (pour la page cache)."""
    d = _vulns_dir()
    files = [f for f in os.listdir(d) if f.endswith(".xml")]
    if not files:
        return {"exists": False, "date": "—", "age_minutes": -1, "size_kb": 0, "tasks": 0}
    total_kb = sum(os.path.getsize(os.path.join(d, f)) for f in files) / 1024

    # Utiliser _last_refresh si disponible, sinon fallback sur mtime des fichiers
    meta = read_vulns_meta()
    last_refresh_str = meta.get("_last_refresh")
    if last_refresh_str:
        try:
            ref_dt = datetime.fromisoformat(last_refresh_str)
        except Exception:
            ref_dt = None
    else:
        ref_dt = None

    if ref_dt is None:
        mtimes = [os.path.getmtime(os.path.join(d, f)) for f in files]
        ref_dt = datetime.fromtimestamp(max(mtimes))

    return {
        "exists": True,
        "date": ref_dt.strftime("%d/%m/%Y %H:%M:%S"),
        "age_minutes": int((datetime.now() - ref_dt).total_seconds() / 60),
        "size_kb": round(total_kb, 1),
        "tasks": len(files),
    }


def get_cache_meta(key):
    """Retourne les métadonnées d'un cache."""
    path = _cache_path(key)
    if os.path.exists(path):
        stat = os.stat(path)
        mtime = datetime.fromtimestamp(stat.st_mtime)
        return {
            "exists": True,
            "date": mtime.strftime("%d/%m/%Y %H:%M:%S"),
            "age_minutes": int((datetime.now() - mtime).total_seconds() / 60),
            "size_kb": round(stat.st_size / 1024, 1),
        }
    return {"exists": False, "date": "—", "age_minutes": -1, "size_kb": 0}


def read_cache_xml(key, **kwargs):
    """Lit et parse un fichier cache XML. Retourne l'élément racine ou None.
    Pour 'vulns', agrège tous les cache/vulns/{task_id}.xml en mémoire.
    """
    if key == "vulns":
        return _read_vulns_cache_xml(task_ids=kwargs.get("task_ids"))
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        return _ET_parse(path).getroot()
    except ET.ParseError:
        return None


def _read_vulns_cache_xml(task_ids: list = None):
    """Agrège les cache/vulns/{task_id}.xml en un seul arbre XML.
    Si task_ids est fourni, seuls les fichiers correspondants sont lus.
    """
    d = _vulns_dir()
    all_files = sorted(f for f in os.listdir(d) if f.endswith(".xml"))
    if not all_files:
        return None
    # Filtrer par task_ids si fourni
    if task_ids:
        files = [f for f in all_files if f.replace(".xml", "") in task_ids]
        if not files:
            files = all_files  # fallback si aucun match
    else:
        files = all_files
    root = ET.Element("get_results_response", status="200", status_text="OK")
    for fname in files:
        fpath = os.path.join(d, fname)
        task_id = fname.replace(".xml", "")
        try:
            tree = _ET_parse(fpath).getroot()
            for result in tree.findall(".//result"):
                # Annoter avec le task_id source pour filtrage et affichage
                result.set("_task_id", task_id)
                root.append(result)
        except ET.ParseError as e:
            logger.warning(f"[VULNS CACHE] Erreur parsing {fname}: {e}")
    return root


def _fetch_and_save(gmp, key, filter_str=""):
    """Appelle GMP, parse et stocke en SQLite (gmp_cache)."""
    xml = None
    if key == "tasks":
        xml = gmp.get_tasks(filter_string=filter_str) if filter_str else gmp.get_tasks()
    elif key == "targets":
        xml = gmp.get_targets(filter_string=filter_str) if filter_str else gmp.get_targets()
    elif key == "schedules":
        xml = gmp.get_schedules(filter_string=filter_str) if filter_str else gmp.get_schedules()
    elif key == "hosts":
        xml = gmp_get_hosts(gmp, filter_string=filter_str) if filter_str else gmp_get_hosts(gmp)
    elif key == "tags":
        xml = gmp.get_tags(filter_string=filter_str) if filter_str else gmp.get_tags()
    elif key == "port_lists":
        xml = gmp.get_port_lists()
    elif key == "scanners":
        xml = gmp.get_scanners()
    elif key == "feeds":
        xml = gmp.get_feeds()
    elif key == "scan_configs":
        xml = gmp.get_scan_configs()
    else:
        raise ValueError(f"Cache inconnu : {key}")

    items = _parse_for_cache(key, xml)
    from app.db import connect_db, save_gmp_cache
    conn = connect_db()
    try:
        save_gmp_cache(conn, key, items)
    finally:
        conn.close()
    return xml


_SCANNER_TYPES = {"1": "OSP", "2": "OpenVAS", "3": "CVE", "4": "GVM"}


def _parse_for_cache(key, xml):
    """Parse GMP XML en liste de dicts pour stockage JSON."""
    from app.gvm_client import parse_tasks, parse_targets, parse_tags, parse_port_lists, parse_scan_configs

    if key == "tasks":     return parse_tasks(xml)
    if key == "targets":   return parse_targets(xml)
    if key == "tags":      return parse_tags(xml)
    if key == "port_lists": return parse_port_lists(xml)
    if key == "scan_configs": return parse_scan_configs(xml)

    if key == "feeds":
        return [{"type": f.findtext("type") or "—", "name": f.findtext("name") or "—",
                 "version": f.findtext("version") or "—",
                 "description": f.findtext("description") or "",
                 "syncing": f.find("currently_syncing") is not None}
                for f in xml.findall("feed")]

    if key == "scanners":
        return [{"id": s.get("id", ""), "name": s.findtext("name") or "—",
                 "host": s.findtext("host") or "local", "port": s.findtext("port") or "—",
                 "type": _SCANNER_TYPES.get(s.findtext("type") or "", s.findtext("type") or "—"),
                 "comment": s.findtext("comment") or ""}
                for s in xml.findall("scanner")]

    if key == "schedules":
        import re as _re

        def _ical_next(ical):
            if not ical: return "—"
            m = _re.search(r"DTSTART[^:]*:([0-9T]+Z?)", ical)
            if m:
                raw = m.group(1)
                try: return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]} {raw[9:11]}:{raw[11:13]} UTC"
                except Exception: return raw
            return "Voir iCalendar"

        def _ical_freq(ical):
            if not ical: return "Unique"
            m = _re.search(r"FREQ=([A-Z]+)", ical)
            if m:
                return {"DAILY": "Quotidien", "WEEKLY": "Hebdomadaire", "MONTHLY": "Mensuel",
                        "YEARLY": "Annuel", "HOURLY": "Horaire"}.get(m.group(1), m.group(1))
            return "Unique"

        return [{"id": s.get("id", ""), "name": s.findtext("name") or "—",
                 "comment": s.findtext("comment") or "", "timezone": s.findtext("timezone") or "UTC",
                 "tasks": s.findtext("tasks/count") or "0",
                 "icalendar": s.findtext("icalendar") or "",
                 "next_time": _ical_next(s.findtext("icalendar") or ""),
                 "frequency": _ical_freq(s.findtext("icalendar") or "")}
                for s in xml.findall("schedule")]

    return []


# ── Cache CVE (EUVD) ─────────────────────────────────────────────────────────

def _cve_cache_dir():
    """Retourne le chemin du sous-dossier cache/cve/, le crée si nécessaire."""
    cve_dir = os.path.join(current_app.config["CACHE_DIR"], "cve")
    os.makedirs(cve_dir, exist_ok=True)
    return cve_dir


def _cve_cache_path(cve_id: str) -> str:
    """Chemin du fichier JSON pour une CVE."""
    # Normaliser le format CVE-YYYY-NNNNN
    cve_id = cve_id.upper().strip()
    return os.path.join(_cve_cache_dir(), f"{cve_id}.json")


def read_cve_cache(cve_id: str) -> dict | None:
    """Lit le cache JSON d'une CVE. Retourne le dict ou None."""
    path = _cve_cache_path(cve_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


MITRE_CVE_API = "https://cveawg.mitre.org/api/cve"


def fetch_cve_from_euvd(cve_id: str) -> tuple[dict | None, str | None]:
    """
    Appelle l'API EUVD pour une CVE, avec fallback MITRE si EUVD échoue.
    Rate-limit et gestion 429 unifiés via _api_get_json(). Retourne (data, error).
    """
    import urllib.error

    cve_id = cve_id.upper().strip()

    # Tentative EUVD
    data, euvd_err = _api_get_json(f"{EUVD_API_BASE}?id={cve_id}", label=f"CVE {cve_id}")
    if data is not None:
        return data, None
    logger.debug(f"EUVD miss for {cve_id}: {euvd_err}")

    # Fallback MITRE (service tiers → hors budget/throttle EUVD)
    raw, mitre_err = _api_get_json(f"{MITRE_CVE_API}/{cve_id}", label=f"MITRE {cve_id}", throttle=False)
    if raw is None:
        return None, f"EUVD+MITRE: {mitre_err}"
    try:
        state = raw.get("cveMetadata", {}).get("state", "")

        desc = ""
        base_score = None
        base_vector = ""

        if state == "PUBLISHED":
            cna = raw.get("containers", {}).get("cna", {})
            for d in cna.get("descriptions", []):
                if d.get("lang", "en").startswith("en"):
                    desc = d.get("value", "")
                    break
            if not desc and cna.get("descriptions"):
                desc = cna["descriptions"][0].get("value", "")

            for m in cna.get("metrics", []):
                for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if key in m:
                        base_score = m[key].get("baseScore")
                        base_vector = m[key].get("vectorString", "")
                        break
                if base_score is not None:
                    break

        data = {
            "id": cve_id,
            "description": desc or f"CVE {state}",
            "baseScore": base_score,
            "baseScoreVector": base_vector,
            "datePublished": raw.get("cveMetadata", {}).get("datePublished", ""),
            "_source": "mitre",
            "_state": state,
        }
        logger.info(f"CVE {cve_id}: récupérée depuis MITRE ({state})")
        return data, None

    except urllib.error.HTTPError as e:
        return None, f"EUVD+MITRE: HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"EUVD+MITRE: {e.reason}"
    except Exception as e:
        return None, f"EUVD+MITRE: {e}"


def extract_cves_from_vulns_cache() -> set[str]:
    """Extrait toutes les CVE uniques du cache vulns XML."""
    xml = read_cache_xml("vulns")
    if xml is None:
        return set()

    cves = set()
    for result in xml.findall(".//result"):
        for ref in result.findall(".//ref"):
            if ref.get("type") == "cve":
                cve_id = ref.get("id", "")
                if CVE_PATTERN.match(cve_id):
                    cves.add(cve_id.upper())
    return cves


def get_cve_cache_stats() -> dict:
    """Retourne les stats du cache CVE."""
    cve_dir = _cve_cache_dir()
    files = [f for f in os.listdir(cve_dir) if f.endswith(".json")]
    total_size = sum(os.path.getsize(os.path.join(cve_dir, f)) for f in files)

    oldest_mtime = None
    newest_mtime = None
    for f in files:
        mtime = os.path.getmtime(os.path.join(cve_dir, f))
        if oldest_mtime is None or mtime < oldest_mtime:
            oldest_mtime = mtime
        if newest_mtime is None or mtime > newest_mtime:
            newest_mtime = mtime

    return {
        "count": len(files),
        "size_kb": round(total_size / 1024, 1),
        "oldest_date": datetime.fromtimestamp(oldest_mtime).strftime("%d/%m/%Y %H:%M") if oldest_mtime else "—",
        "newest_date": datetime.fromtimestamp(newest_mtime).strftime("%d/%m/%Y %H:%M") if newest_mtime else "—",
    }


def cleanup_cve_cache(cves_needed: set) -> dict:
    """
    Supprime les fichiers CVE du cache qui ne sont plus dans les résultats de scan.
    Retourne {deleted, kept}.
    """
    cve_dir = _cve_cache_dir()
    if not os.path.isdir(cve_dir):
        return {"deleted": 0, "kept": 0}

    deleted = 0
    kept = 0
    for filename in os.listdir(cve_dir):
        if not filename.endswith(".json"):
            continue
        cve_id = filename.replace(".json", "").upper()
        if cve_id not in {c.upper() for c in cves_needed}:
            try:
                os.remove(os.path.join(cve_dir, filename))
                deleted += 1
                logger.info(f"[CVE cleanup] Supprimé : {cve_id}")
            except Exception as e:
                logger.warning(f"[CVE cleanup] Erreur suppression {cve_id}: {e}")
        else:
            kept += 1

    logger.info(f"[CVE cleanup] {deleted} supprimées, {kept} conservées")
    return {"deleted": deleted, "kept": kept}


def refresh_cve_cache_from_vulns(progress_callback=None) -> dict:
    """
    Télécharge les CVE manquantes depuis EUVD pour toutes les CVE du cache vulns.
    Nettoie automatiquement les CVE obsolètes avant le téléchargement.
    Retourne un résumé : {downloaded, skipped, errors, error_details, cleaned}.
    """
    cves_needed = extract_cves_from_vulns_cache()

    # Cleanup des CVE obsolètes
    cleanup = cleanup_cve_cache(cves_needed)
    results = {"downloaded": 0, "skipped": 0, "errors": 0, "error_details": [], "total": len(cves_needed), "cleaned": cleanup["deleted"]}

    for i, cve_id in enumerate(sorted(cves_needed)):
        # Callback pour progression
        if progress_callback:
            progress_callback(i + 1, len(cves_needed), cve_id)

        # Vérifier si déjà en cache
        if read_cve_cache(cve_id) is not None:
            results["skipped"] += 1
            continue

        # Rate limiting
        if results["downloaded"] > 0 or results["errors"] > 0:
            time.sleep(_get_rate_limit())

        # Télécharger depuis EUVD
        data, error = fetch_cve_from_euvd(cve_id)
        if error:
            results["errors"] += 1
            results["error_details"].append(f"{cve_id}: {error}")
            logger.warning(f"EUVD fetch failed for {cve_id}: {error}")
        else:
            results["downloaded"] += 1

    return results


def refresh_existing_cve_cache(progress_callback=None) -> dict:
    """
    Met à jour tous les JSON CVE déjà en cache (re-télécharge depuis EUVD).
    Retourne un résumé.
    """
    cve_dir = _cve_cache_dir()
    files = [f for f in os.listdir(cve_dir) if f.endswith(".json")]
    results = {"updated": 0, "errors": 0, "error_details": [], "total": len(files)}

    for i, filename in enumerate(sorted(files)):
        cve_id = filename.replace(".json", "")

        if progress_callback:
            progress_callback(i + 1, len(files), cve_id)

        # Rate limiting
        if i > 0:
            time.sleep(_get_rate_limit())

        data, error = fetch_cve_from_euvd(cve_id)
        if error:
            results["errors"] += 1
            results["error_details"].append(f"{cve_id}: {error}")
        else:
            results["updated"] += 1

    return results


def enrich_vuln_with_euvd(vuln: dict) -> dict:
    """
    Enrichit un dict vulnérabilité avec les données EUVD depuis le cache.
    Gère les CVE multiples : utilise la première CVE trouvée en cache.
    Ajoute : euvd_vendor, euvd_product, euvd_epss, euvd_exploited, euvd_url, euvd_data.
    """
    # Récupérer toutes les CVE de la vuln
    cves = vuln.get("cves", [])
    if not cves:
        # Fallback sur cve unique pour compatibilité
        single_cve = vuln.get("cve", "")
        if single_cve and single_cve != "—":
            cves = [single_cve]

    if not cves:
        vuln["euvd_data"] = None
        vuln["all_cves"] = []
        vuln["euvd_vendor"] = "—"
        vuln["euvd_product"] = "—"
        vuln["euvd_epss"] = None
        vuln["euvd_exploited"] = False
        vuln["euvd_exploited_since"] = ""
        return vuln

    vuln["all_cves"] = cves

    # Chercher la première CVE avec données EUVD en cache
    euvd = None
    cve_id = None
    for c in cves:
        if CVE_PATTERN.match(c):
            data = read_cve_cache(c)
            if data is not None:
                euvd = data
                cve_id = c.upper()
                break

    # Si aucune CVE en cache, prendre la première pour le lien
    if cve_id is None and cves:
        cve_id = cves[0].upper() if CVE_PATTERN.match(cves[0]) else None

    if euvd is None:
        vuln["euvd_data"] = None
        vuln["cve"] = cve_id or "—"
        vuln["euvd_vendor"] = "—"
        vuln["euvd_product"] = "—"
        vuln["euvd_epss"] = None
        vuln["euvd_exploited"] = False
        vuln["euvd_exploited_since"] = ""
        vuln["euvd_url"] = f"{EUVD_WEB_BASE}/{cve_id}" if cve_id else ""
        return vuln

    # Extraire vendor/product
    vendor = "—"
    product = "—"
    product_version = ""

    vendors = euvd.get("enisaIdVendor", [])
    if vendors and isinstance(vendors, list) and len(vendors) > 0:
        v = vendors[0].get("vendor", {})
        vendor = v.get("name", "—") if isinstance(v, dict) else "—"

    products = euvd.get("enisaIdProduct", [])
    if products and isinstance(products, list) and len(products) > 0:
        p = products[0]
        prod_obj = p.get("product", {})
        product = prod_obj.get("name", "—") if isinstance(prod_obj, dict) else "—"
        product_version = p.get("product_version", "")

    # Vérifier exploitation via cache KEV
    kev_data = read_kev_cache()
    is_exploited = False
    exploited_since = ""

    # D'abord vérifier dans EUVD
    if euvd.get("exploitedSince"):
        is_exploited = True
        exploited_since = euvd.get("exploitedSince", "")
    # Sinon vérifier dans KEV pour toutes les CVE
    elif kev_data:
        for c in cves:
            if c.upper() in kev_data:
                is_exploited = True
                kev_entry = kev_data[c.upper()]
                exploited_since = kev_entry.get("dateAdded", "")
                break

    vuln["cve"] = cve_id
    # Normaliser les valeurs absentes/invalides du vendor
    _VENDOR_EMPTY = {"—", "n/a", "na", "none", "unknown", ""}
    if vendor.strip().lower() in _VENDOR_EMPTY:
        vendor = "—"
    vuln["euvd_vendor"] = vendor.title() if vendor != "—" else "—"
    vuln["euvd_product"] = product.title() if product != "—" else "—"
    vuln["euvd_product_version"] = product_version
    
    # Normaliser EPSS (doit être entre 0 et 1)
    raw_epss = euvd.get("epss")
    if raw_epss is not None:
        try:
            epss_val = float(raw_epss)
            # Si > 1, c'est probablement en pourcentage (0-100), normaliser
            if epss_val > 1:
                epss_val = epss_val / 100.0
            vuln["euvd_epss"] = min(1.0, max(0.0, epss_val))
        except (ValueError, TypeError):
            vuln["euvd_epss"] = None
    else:
        vuln["euvd_epss"] = None
    
    vuln["euvd_exploited"] = is_exploited
    vuln["euvd_exploited_since"] = exploited_since
    vuln["euvd_url"] = f"{EUVD_WEB_BASE}/{cve_id}"
    vuln["euvd_id"] = euvd.get("id", "")
    vuln["euvd_description"] = euvd.get("description", "")
    vuln["euvd_base_score"] = euvd.get("baseScore")
    vuln["euvd_base_score_vector"] = euvd.get("baseScoreVector", "")
    vuln["euvd_references"] = euvd.get("references", "").split("\n") if euvd.get("references") else []
    vuln["euvd_aliases"] = euvd.get("aliases", "").split("\n") if euvd.get("aliases") else []
    vuln["euvd_assigner"] = euvd.get("assigner", "")
    vuln["euvd_published"] = euvd.get("datePublished") or euvd.get("published", "")
    vuln["euvd_data"] = euvd  # Données complètes pour la modale

    return vuln


# ── Cache KEV (Known Exploited Vulnerabilities) ──────────────────────────────

def _kev_cache_path() -> str:
    """Chemin du fichier JSON pour le cache KEV."""
    return os.path.join(current_app.config["CACHE_DIR"], "kev.json")


def _kev_entry_cve_id(entry: dict) -> str:
    """Extrait l'identifiant CVE d'une entrée KEV (champ cveId ou aliases)."""
    cve = (entry.get("cveId") or "").strip().upper()
    if cve.startswith("CVE-"):
        return cve
    for alias in (entry.get("aliases") or "").split("\n"):
        alias = alias.strip().upper()
        if alias.startswith("CVE-"):
            return alias
    return ""


def read_kev_cache() -> dict | None:
    """
    Lit le cache KEV. Retourne un dict {CVE_ID: entry} ou None.
    Supporte les formats avec champ cveId ou aliases (format EUVD).
    """
    path = _kev_cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            result = {}
            for entry in data:
                cve_id = _kev_entry_cve_id(entry)
                if cve_id:
                    result[cve_id] = entry
            return result or None
        return data
    except (json.JSONDecodeError, IOError):
        return None


def fetch_kev_dump() -> tuple[dict | None, str | None]:
    """
    Télécharge le dump KEV depuis EUVD, sauvegarde en cache.
    Retourne (data_dict indexé par CVE, error_message).
    """
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(EUVD_KEV_DUMP, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            raw_data = json.loads(resp.read().decode("utf-8"))

        # Sauvegarder en cache (liste brute)
        path = _kev_cache_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(raw_data, f, ensure_ascii=False, indent=2)

        # Indexer par CVE (cohérent avec read_kev_cache)
        if isinstance(raw_data, list):
            indexed = {}
            for entry in raw_data:
                cve_id = _kev_entry_cve_id(entry)
                if cve_id:
                    indexed[cve_id] = entry
            return indexed, None
        return raw_data, None

    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"Réseau: {e.reason}"
    except json.JSONDecodeError:
        return None, "JSON invalide"
    except Exception as e:
        return None, str(e)


def fetch_iana_services() -> tuple[list, str | None, str | None]:
    """Télécharge et parse le registre IANA port→service (XML).

    Retourne (records, registry_date, error) où records est une liste de tuples
    (port:int, protocol:str, service:str, description:str) pour les ports uniques
    nommés, et registry_date la date <updated> du registre (str ou None).
    """
    import urllib.request
    import urllib.error
    import xml.etree.ElementTree as ET

    def q(tag: str) -> str:
        return f"{{{IANA_NS}}}{tag}"

    try:
        req = urllib.request.Request(IANA_SERVICES_XML, headers={"Accept": "application/xml"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status != 200:
                return [], None, f"HTTP {resp.status}"
            raw = resp.read()

        root = ET.fromstring(raw)
        registry_date = root.findtext(q("updated"))

        records = []
        for rec in root.findall(".//" + q("record")):
            num = (rec.findtext(q("number")) or "").strip()
            proto = (rec.findtext(q("protocol")) or "").strip().lower()
            name = (rec.findtext(q("name")) or "").strip()
            # On ne garde que les ports uniques (pas de plages "1024-65535") nommés + protocole
            if not num.isdigit() or not proto or not name:
                continue
            desc = (rec.findtext(q("description")) or "").strip()
            records.append((int(num), proto, name, desc))

        if not records:
            return [], registry_date, "Aucun enregistrement exploitable"
        return records, registry_date, None

    except urllib.error.HTTPError as e:
        return [], None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return [], None, f"Réseau: {e.reason}"
    except ET.ParseError as e:
        return [], None, f"XML invalide: {e}"
    except Exception as e:
        return [], None, str(e)


def get_kev_cache_stats() -> dict:
    """Retourne les stats du cache KEV."""
    path = _kev_cache_path()
    if not os.path.exists(path):
        return {"exists": False, "count": 0, "size_kb": 0, "date": "—"}

    stat = os.stat(path)
    mtime = datetime.fromtimestamp(stat.st_mtime)

    # Compter les entrées
    count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            count = len(data)
        elif isinstance(data, dict):
            count = len(data)
    except (json.JSONDecodeError, IOError):
        pass

    return {
        "exists": True,
        "count": count,
        "size_kb": round(stat.st_size / 1024, 1),
        "date": mtime.strftime("%d/%m/%Y %H:%M"),
        "age_minutes": int((datetime.now() - mtime).total_seconds() / 60),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@cache_bp.route("/")
@login_required
@require_perm("cache.read")
def index():
    """Page d'accueil — état de tous les caches (depuis SQLite)."""
    from app.db import get_db, get_gmp_cache_meta, get_scan_imports

    db = get_db()

    from app.auth.roles import app_settings
    settings = app_settings()
    schedules = settings.get("schedules", {})

    caches = []
    for key, defn in CACHE_DEFS.items():
        meta = get_gmp_cache_meta(db, key)
        interval_h = schedules.get(key, {}).get("interval_hours", 0)
        meta["threshold_ok"] = interval_h * 60 if interval_h > 0 else 60
        meta["threshold_warn"] = interval_h * 60 * 2 if interval_h > 0 else 1440
        caches.append({"name": key, "label": defn["label"], "filter": defn["filter"], **meta})

    # Vulns meta
    scan_imports = get_scan_imports(db)
    vulns_cache_meta = get_gmp_cache_meta(db, "vulns")
    vulns_interval_h = schedules.get("vulns", {}).get("interval_hours", 0)
    vulns_meta = {
        "exists": vulns_cache_meta.get("exists", False),
        "date": vulns_cache_meta.get("date", "—"),
        "tasks": len(scan_imports),
        "findings": vulns_cache_meta.get("count", 0),
        "detail": scan_imports,
        "age_minutes": vulns_cache_meta.get("age_minutes"),
        "threshold_ok": vulns_interval_h * 60 if vulns_interval_h > 0 else 60,
        "threshold_warn": vulns_interval_h * 60 * 2 if vulns_interval_h > 0 else 1440,
    }

    from datetime import datetime as _dt

    def _age_minutes(dt_str):
        if not dt_str or dt_str == "—":
            return None
        try:
            return int((_dt.now() - _dt.fromisoformat(dt_str)).total_seconds() / 60)
        except Exception:
            return None

    def _thresholds(key):
        interval_h = schedules.get(key, {}).get("interval_hours", 0)
        return (interval_h * 60 if interval_h > 0 else 60,
                interval_h * 60 * 2 if interval_h > 0 else 1440)

    # Stats CVE depuis SQLite
    cve_count = db.execute("SELECT COUNT(*) FROM cves WHERE euvd_updated_at IS NOT NULL").fetchone()[0]
    cves_needed = db.execute("SELECT COUNT(DISTINCT cve_id) FROM vuln_cves").fetchone()[0]
    cve_meta = db.execute("SELECT updated_at FROM gmp_cache WHERE cache_key='cve'").fetchone()
    cve_date = (cve_meta["updated_at"] if cve_meta else None) or db.execute("SELECT MAX(euvd_updated_at) FROM cves").fetchone()[0] or "—"
    cve_tok, cve_twarn = _thresholds("cve")
    cve_stats = {
        "count": cve_count,
        "in_vulns": cves_needed,
        "missing": max(0, cves_needed - cve_count),
        "date": cve_date,
        "age_minutes": _age_minutes(cve_date),
        "threshold_ok": cve_tok,
        "threshold_warn": cve_twarn,
    }

    # Stats KEV depuis SQLite
    kev_row = db.execute("SELECT COUNT(*) as cnt, MAX(kev_updated_at) as dt FROM cves WHERE is_kev=1").fetchone()
    kev_date = kev_row["dt"] or "—"
    kev_tok, kev_twarn = _thresholds("kev")
    kev_stats = {
        "exists": (kev_row["cnt"] or 0) > 0,
        "count": kev_row["cnt"] or 0,
        "date": kev_date,
        "age_minutes": _age_minutes(kev_date),
        "threshold_ok": kev_tok,
        "threshold_warn": kev_twarn,
    }

    # Stats ANSSI depuis SQLite
    anssi_row = db.execute("""
        SELECT COUNT(DISTINCT ac.cve_id) as cnt, MAX(ap.updated_at) as dt,
               SUM(CASE WHEN ac.cert_type='alerte' THEN 1 ELSE 0 END) as alertes,
               SUM(CASE WHEN ac.cert_type='avis' THEN 1 ELSE 0 END) as avis
        FROM anssi_cves ac
        JOIN anssi_publications ap ON ac.ref=ap.ref
    """).fetchone()
    anssi_date = anssi_row["dt"] or "—"
    anssi_tok, anssi_twarn = _thresholds("anssi")
    anssi_stats = {
        "exists": (anssi_row["cnt"] or 0) > 0,
        "count": anssi_row["cnt"] or 0,
        "alertes": anssi_row["alertes"] or 0,
        "avis": anssi_row["avis"] or 0,
        "date": anssi_date,
        "age_minutes": _age_minutes(anssi_date),
        "threshold_ok": anssi_tok,
        "threshold_warn": anssi_twarn,
    }

    # Stats CPE dictionary
    cpe_row = db.execute("SELECT COUNT(*) as cnt, MAX(last_modified) as dt FROM cpe_dictionary").fetchone()
    cpe_vendors = db.execute("SELECT COUNT(DISTINCT vendor) FROM cpe_dictionary").fetchone()[0]
    cpe_products = db.execute("SELECT COUNT(DISTINCT vendor || '/' || product) FROM cpe_dictionary").fetchone()[0]
    cpe_date = cpe_row["dt"] or "—"
    cpe_tok, cpe_twarn = _thresholds("cpe_dict")
    cpe_dict_stats = {
        "exists": (cpe_row["cnt"] or 0) > 0,
        "count": cpe_row["cnt"] or 0,
        "vendors": cpe_vendors,
        "products": cpe_products,
        "date": cpe_date,
        "age_minutes": _age_minutes(cpe_date),
        "threshold_ok": cpe_tok,
        "threshold_warn": cpe_twarn,
    }

    # Stats CPE watch
    cpe_watch_meta = get_gmp_cache_meta(db, "cpe_watch")
    cpe_watch_stats = {
        "exists": cpe_watch_meta.get("exists", False),
        "date": cpe_watch_meta.get("date", "—"),
        "age_minutes": cpe_watch_meta.get("age_minutes"),
        "threshold_ok": schedules.get("cpe_watch", {}).get("interval_hours", 0) * 60 or 60,
        "threshold_warn": schedules.get("cpe_watch", {}).get("interval_hours", 0) * 60 * 2 or 1440,
    }

    # Stats référentiel IANA port→service
    iana_row = db.execute("SELECT COUNT(*) as cnt, MAX(updated_at) as dt FROM iana_services").fetchone()
    iana_date = iana_row["dt"] or "—"
    iana_tok, iana_twarn = _thresholds("iana")
    iana_stats = {
        "exists": (iana_row["cnt"] or 0) > 0,
        "count": iana_row["cnt"] or 0,
        "date": iana_date,
        "age_minutes": _age_minutes(iana_date),
        "threshold_ok": iana_tok,
        "threshold_warn": iana_twarn,
    }

    # Stats résolution DNS inverse
    dns_row = db.execute(
        "SELECT COUNT(*) as cnt, "
        "SUM(CASE WHEN hostname IS NOT NULL AND hostname != '' THEN 1 ELSE 0 END) as resolved, "
        "MAX(resolved_at) as dt FROM dns_cache"
    ).fetchone()
    dns_date = dns_row["dt"] or "—"
    dns_tok, dns_twarn = _thresholds("dns")
    dns_stats = {
        "exists": (dns_row["cnt"] or 0) > 0,
        "count": dns_row["cnt"] or 0,
        "resolved": dns_row["resolved"] or 0,
        "date": dns_date,
        "age_minutes": _age_minutes(dns_date),
        "threshold_ok": dns_tok,
        "threshold_warn": dns_twarn,
    }

    # Liste des logiciels surveillés + date de dernière surveillance (cache CPE)
    cpe_watch_items = [dict(r) for r in db.execute(
        """SELECT ms.id, ms.vendor, ms.product, ms.version,
                  COALESCE(cwc.evaluated_at, cwc.fetched_at) AS last_checked, cwc.complete AS last_complete
           FROM monitored_software ms
           LEFT JOIN cpe_watch_cache cwc
             ON cwc.vendor = ms.vendor AND cwc.product = ms.product
           ORDER BY ms.vendor, ms.product"""
    ).fetchall()]

    return render_template("cache/index.html", caches=caches, cve_stats=cve_stats,
                           kev_stats=kev_stats, anssi_stats=anssi_stats, vulns_meta=vulns_meta,
                           cpe_dict_stats=cpe_dict_stats, cpe_watch_stats=cpe_watch_stats,
                           iana_stats=iana_stats, dns_stats=dns_stats,
                           cpe_watch_items=cpe_watch_items)


def _is_ajax():
    """Vérifie si c'est une requête AJAX."""
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


@cache_bp.route("/meta")
@login_required
@require_perm("cache.read")
def cache_meta_json():
    """Retourne les métadonnées de toutes les cards en JSON (depuis SQLite)."""
    from flask import jsonify
    from app.db import get_db, get_gmp_cache_meta

    db = get_db()

    from app.auth.roles import app_settings
    settings = app_settings()
    schedules = settings.get("schedules", {})

    def _age_min(dt_str):
        if not dt_str or dt_str == "—":
            return None
        try:
            from datetime import datetime as _dtm
            return int((_dtm.now() - _dtm.fromisoformat(dt_str)).total_seconds() / 60)
        except Exception:
            return None

    def age_badge(age_minutes, cache_key=None):
        if age_minutes is None or age_minutes < 0:
            return {"cls": "bg-secondary-lt", "icon": "ti-file-off", "text": "Absent"}
        interval_h = schedules.get(cache_key, {}).get("interval_hours", 0) if cache_key else 0
        if interval_h > 0:
            threshold_ok = interval_h * 60
            threshold_warn = interval_h * 60 * 2
        else:
            threshold_ok = 60
            threshold_warn = 1440
        if age_minutes < threshold_ok:
            return {"cls": "bg-green-lt", "icon": "ti-circle-check", "text": "À jour"}
        if age_minutes < threshold_warn:
            return {"cls": "bg-yellow-lt", "icon": "ti-clock", "text": f"{int(age_minutes // 60)}h"}
        return {"cls": "bg-red-lt", "icon": "ti-alert-triangle", "text": f"{int(age_minutes // 1440)}j"}

    cards = {}

    for key in CACHE_DEFS:
        meta = get_gmp_cache_meta(db, key)
        am = meta["age_minutes"] if meta["exists"] else None
        cards[f"gmp_{key}"] = {
            "date": meta.get("date") or "—",
            "count": meta.get("count", 0),
            "badge": age_badge(am, key),
        }

    # Vulns — utiliser le même calcul que get_gmp_cache_meta
    from app.db import get_gmp_cache_meta as _meta
    vulns_meta = _meta(db, "vulns")
    cards["gmp_vulns"] = {
        "date": vulns_meta.get("date") or "—",
        "count": vulns_meta.get("count", 0),
        "badge": age_badge(vulns_meta.get("age_minutes"), "vulns"),
    }

    # CVE
    cve_count = db.execute("SELECT COUNT(*) FROM cves WHERE euvd_updated_at IS NOT NULL").fetchone()[0]
    cves_needed = db.execute("SELECT COUNT(DISTINCT cve_id) FROM vuln_cves").fetchone()[0]
    cve_meta = db.execute("SELECT updated_at FROM gmp_cache WHERE cache_key='cve'").fetchone()
    cve_date = (cve_meta["updated_at"] if cve_meta else None) or db.execute("SELECT MAX(euvd_updated_at) FROM cves").fetchone()[0]
    cards["cve"] = {
        "count": cve_count,
        "in_vulns": cves_needed,
        "missing": max(0, cves_needed - cve_count),
        "badge": age_badge(_age_min(cve_date), "cve"),
    }

    # KEV
    kev_row = db.execute("SELECT COUNT(*) as cnt, MAX(kev_updated_at) as dt FROM cves WHERE is_kev=1").fetchone()
    cards["kev"] = {
        "count": kev_row["cnt"] or 0,
        "date": kev_row["dt"] or "—",
        "badge": age_badge(_age_min(kev_row["dt"]), "kev"),
    }

    # ANSSI
    anssi_row = db.execute("""
        SELECT COUNT(DISTINCT ac.cve_id) as cnt, MAX(ap.updated_at) as dt,
               SUM(CASE WHEN ac.cert_type='alerte' THEN 1 ELSE 0 END) as alertes,
               SUM(CASE WHEN ac.cert_type='avis' THEN 1 ELSE 0 END) as avis
        FROM anssi_cves ac JOIN anssi_publications ap ON ac.ref=ap.ref
    """).fetchone()
    cards["anssi"] = {
        "count": anssi_row["cnt"] or 0,
        "alertes": anssi_row["alertes"] or 0,
        "avis": anssi_row["avis"] or 0,
        "date": anssi_row["dt"] or "—",
        "badge": age_badge(_age_min(anssi_row["dt"]), "anssi"),
    }

    # CPE dictionary
    cpe_row = db.execute("SELECT COUNT(*) as cnt, MAX(last_modified) as dt FROM cpe_dictionary").fetchone()
    cards["cpe_dict"] = {
        "count": cpe_row["cnt"] or 0,
        "vendors": db.execute("SELECT COUNT(DISTINCT vendor) FROM cpe_dictionary").fetchone()[0],
        "date": cpe_row["dt"] or "—",
        "badge": age_badge(_age_min(cpe_row["dt"]), "cpe_dict"),
    }

    # CPE watch
    cpe_watch_row = db.execute("SELECT updated_at FROM gmp_cache WHERE cache_key='cpe_watch'").fetchone()
    cpe_watch_dt = cpe_watch_row["updated_at"] if cpe_watch_row else None
    cards["cpe_watch"] = {
        "date": cpe_watch_dt or "—",
        "badge": age_badge(_age_min(cpe_watch_dt), "cpe_watch"),
    }

    # IANA port→service
    iana_row = db.execute("SELECT COUNT(*) as cnt, MAX(updated_at) as dt FROM iana_services").fetchone()
    cards["iana"] = {
        "count": iana_row["cnt"] or 0,
        "date": iana_row["dt"] or "—",
        "badge": age_badge(_age_min(iana_row["dt"]), "iana"),
    }

    # DNS inverse
    dns_row = db.execute(
        "SELECT COUNT(*) as cnt, "
        "SUM(CASE WHEN hostname IS NOT NULL AND hostname != '' THEN 1 ELSE 0 END) as resolved, "
        "MAX(resolved_at) as dt FROM dns_cache"
    ).fetchone()
    cards["dns"] = {
        "count": dns_row["cnt"] or 0,
        "resolved": dns_row["resolved"] or 0,
        "date": dns_row["dt"] or "—",
        "badge": age_badge(_age_min(dns_row["dt"]), "dns"),
    }

    return jsonify(cards)


@cache_bp.route("/refresh/vulns", methods=["POST"])
@login_required
@require_perm("cache.refresh_vulns")
def refresh_vulns():
    """Rafraîchit le cache vulns depuis les derniers rapports de chaque tâche."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("gmp_vulns"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour vulns déjà en cours"})
        flash("Une mise à jour des vulnérabilités est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    gmp_username, gmp_password = current_user.get_gmp_credentials()
    success, message = start_background_task("gmp_vulns", _task_refresh_vulns, gmp_username, gmp_password)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "gmp_vulns", "message": "Mise à jour vulnérabilités démarrée"})
    if success:
        flash("Mise à jour des vulnérabilités démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")
    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh/<cache_name>", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_one(cache_name):
    """Rafraîchit un cache GMP spécifique en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    # Vulns a sa propre route
    if cache_name == "vulns":
        return refresh_vulns()

    task_type = f"gmp_{cache_name}"

    if cache_name not in CACHE_DEFS:
        if _is_ajax():
            return jsonify({"success": False, "error": f"Cache inconnu : {cache_name}"})
        flash(f"Cache inconnu : {cache_name}", "danger")
        return redirect(url_for("cache.index"))

    if is_task_running(task_type):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour déjà en cours"})
        flash(f"Une mise à jour de {cache_name} est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    gmp_username, gmp_password = current_user.get_gmp_credentials()
    success, message = start_background_task(
        task_type, _task_refresh_gmp,
        cache_name, gmp_username, gmp_password
    )

    if _is_ajax():
        return jsonify({"success": success, "task_type": task_type, "message": f"Mise à jour {CACHE_DEFS[cache_name]['label']} démarrée"})
    if success:
        flash(f"Mise à jour {CACHE_DEFS[cache_name]['label']} démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")
    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-all", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_all():
    """Rafraîchit tous les caches GMP en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("gmp_all"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour déjà en cours"})
        flash("Une mise à jour globale est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    # Récupérer les credentials GMP (compatible multi-backend)
    gmp_username, gmp_password = current_user.get_gmp_credentials()
    
    success, message = start_background_task(
        "gmp_all", _task_refresh_gmp_all,
        gmp_username, gmp_password
    )

    if _is_ajax():
        return jsonify({"success": success, "task_type": "gmp_all", "message": "Mise à jour de tous les caches GMP démarrée"})

    if success:
        flash("Mise à jour de tous les caches GMP démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-cve", methods=["POST"])
@login_required
@require_perm("cache.refresh_cve")
def refresh_cve():
    """Lance le téléchargement des CVE manquantes en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("cve"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour CVE déjà en cours"})
        flash("Une mise à jour CVE est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("cve", _task_refresh_cve)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "cve", "message": "Téléchargement des CVE démarré"})

    if success:
        flash("Téléchargement des CVE démarré.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/update-cve", methods=["POST"])
@login_required
@require_perm("cache.refresh_cve")
def update_cve():
    """Lance la mise à jour des CVE existantes en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("cve"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour CVE déjà en cours"})
        flash("Une mise à jour CVE est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("cve", _task_update_cve)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "cve", "message": "Mise à jour des CVE démarrée"})

    if success:
        flash("Mise à jour des CVE démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-kev", methods=["POST"])
@login_required
@require_perm("cache.refresh_kev")
def refresh_kev():
    """Lance le téléchargement du dump KEV en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("kev"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour KEV déjà en cours"})
        flash("Une mise à jour KEV est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("kev", _task_refresh_kev)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "kev", "message": "Téléchargement KEV démarré"})

    if success:
        flash("Téléchargement KEV démarré.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-iana", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_iana():
    """Lance le téléchargement du registre IANA port→service en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("iana"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour IANA déjà en cours"})
        flash("Une mise à jour IANA est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("iana", _task_refresh_iana)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "iana", "message": "Téléchargement IANA démarré"})

    if success:
        flash("Téléchargement du référentiel IANA démarré.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-dns", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_dns():
    """Lance la résolution DNS inverse en arrière-plan.

    ?full=1 (form) → rescan complet de toutes les IP ; sinon incrémental.
    """
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    full = request.form.get("full") in ("1", "true", "on", "yes")

    if is_task_running("dns"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Résolution DNS déjà en cours"})
        flash("Une résolution DNS est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("dns", _task_refresh_dns, full)

    msg = "Rescan DNS complet démarré" if full else "Résolution DNS démarrée"
    if _is_ajax():
        return jsonify({"success": success, "task_type": "dns", "message": msg})

    if success:
        flash(msg + ".", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-cpe", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_cpe():
    """Lance la synchronisation incrémentale du dictionnaire CPE."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("cpe_dict"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Synchro CPE déjà en cours"})
        flash("Une synchronisation CPE est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("cpe_dict", _task_refresh_cpe_dict)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "cpe_dict", "message": "Synchronisation CPE démarrée"})

    if success:
        flash("Synchronisation CPE démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


# ══════════════════════════════════════════════════════════════════════════════
# Surveillance logicielle (CPE watch)
# ══════════════════════════════════════════════════════════════════════════════

EUVD_SEARCH_API = "https://euvdservices.enisa.europa.eu/api/search"


# Regexes pré-compilés pour _version_in_range (évite la recompilation à chaque appel)
_VIR_CONSTRAINT_RE  = re.compile(r'^(<=|<|>=|>|=)\s*(.+)$')
_VIR_HIGH_TOK_RE    = re.compile(r'^(<=|<|>=|>)(.+)$')
# Borne basse en branche wildcard : "8.2.*", "7.3.x", "8.0.X" → normalise en "8.2.0" etc.
_VIR_LOW_BRANCH_RE  = re.compile(r'^(\d+(?:\.\d+)*)\.([xX*])$')
# Contrainte à opérateur n'importe où dans un fragment ("… and < v3.8.0b1")
_VIR_EMBEDDED_OP_RE = re.compile(r'(<=|<|>=|>)\s*v?(\d[0-9.]*)')
# Version nue (non collée à un mot) : "2.7", "3.5", "v1.2.3"
_VIR_BARE_VER_RE    = re.compile(r'(?<![\w.])v?(\d+(?:\.\d+)*)')
# Parenthèses : "(revision 2)", "(rev. 3)" → bruit à retirer
_VIR_PAREN_RE       = re.compile(r'\([^)]*\)')

# États de correspondance de version (retour de _version_in_range)
MATCH_AFFECTED     = "affected"      # version prouvée dans la plage vulnérable
MATCH_NOT_AFFECTED = "not_affected"  # version prouvée hors de la plage
MATCH_UNKNOWN      = "unknown"       # format non interprété → doute (conservé par précaution)


def _in_series(v, series: str) -> bool:
    """v appartient-il à la série numérique `series` (ex. '10', '9.6', '2.10') ?

    Compare composant par composant : '10' → v.major==10 ; '9.6' → 9.6.x.
    Sert à écarter les CVE d'une autre branche majeure (PostgreSQL 18 vs 10.x).
    """
    comps = [v.major, v.minor, v.micro]
    parts = series.split(".")
    for i, p in enumerate(parts[:3]):
        try:
            if int(p) != comps[i]:
                return False
        except ValueError:
            return False
    return True


def _clean_version_qualifiers(s: str) -> str:
    """Normalise les qualificatifs de version non standard, en dernier recours.

    Appelé UNIQUEMENT en fallback quand _version_in_range a déjà répondu UNKNOWN
    (ne peut donc pas altérer un résultat déjà décidé). Rattrape :
      "unspecified <ESR68.5"   → "unspecified <68.5"     (piste ESR Firefox/TB)
      "2023.1 <2024.2 EAP2"    → "2023.1 <2024.2"        (tag build JetBrains)
      "3.2.0 to < 3.2.9"       → "3.2.0 <3.2.9"          (séparateur 'to')
      "11.x prior to 11.3"     → "all 11.x before 11.3"  (série + borne)
    """
    out = re.sub(r'(?i)\bESR(?=\d)', '', s)
    out = re.sub(r'(?i)(?<=[\d.])\s+(?:EAP|RC|beta|alpha|preview|dev|nightly|snapshot)\s*\d*\b', '', out)
    out = re.sub(r'(?i)\bto\s*(<=|<)\s*', r'\1', out)
    out = re.sub(r'(?i)\b(\d+(?:\.\d+)*\.[xX*])\s+prior\s+to\s+', r'all \1 before ', out)
    return re.sub(r'\s{2,}', ' ', out).strip()


def _version_in_range_raw(version: str, range_str: str) -> str:
    """Détermine l'état d'affectation de `version` par le range EUVD `range_str`.

    Retourne l'une des trois constantes :
      MATCH_AFFECTED      version prouvée dans la plage vulnérable
      MATCH_NOT_AFFECTED  version prouvée hors de la plage
      MATCH_UNKNOWN       format non interprété / donnée manquante → doute

    Le doute (UNKNOWN) est conservateur : l'appelant crée quand même le finding
    (pas de faux négatif) mais peut signaler la faible confiance à l'utilisateur.

    Formats couverts (analyse sur 11 310 entrées EUVD réelles) :
      RANGE_<          "0 <26.2.47"           deux tokens espace-délimités
      EXACT            "4.1.0"                version exacte
      RANGE_≤          "9.0 ≤9.0.5400.0"      idem avec ≤ (Unicode)
      UPPER_BOUND_ONLY "< 0.3.2"              borne haute seule
      COMMA/ENUM       ">= 10.0.0, < 11.0.0"  bornes OU énumération de séries
      "prior to X" / "X and earlier" / "all X.x before Y" / "Éditeur X.Y.Z"
    """
    from packaging.version import Version, InvalidVersion

    if not version:
        return MATCH_UNKNOWN  # pas de version déclarée → indéterminé

    range_str = (range_str or "").strip()
    if not range_str or range_str in ("-", "—"):
        return MATCH_UNKNOWN  # NULL_FIELD / NO_VERSION → indéterminé

    try:
        v = Version(version)
    except InvalidVersion:
        return MATCH_UNKNOWN  # version non parseable → indéterminé

    # Normaliser les opérateurs Unicode (≤ ≥) — le mojibake PowerShell est évité
    # en amont par notre décodage explicite UTF-8 de la réponse HTTP.
    range_str = range_str.replace("≤", "<=").replace("≥", ">=")

    # Retirer les parenthèses de bruit : "GIMP 2.10.34 (revision 2)" → "GIMP 2.10.34"
    if "(" in range_str:
        range_str = _VIR_PAREN_RE.sub("", range_str).strip()
        range_str = re.sub(r"\s{2,}", " ", range_str)

    def _parse_v(s: str):
        try:
            return Version(s.strip())
        except InvalidVersion:
            return None

    def _check_op(op: str, bound_str: str):
        """Évalue v OP bound → bool, ou None si bound non parseable."""
        b = _parse_v(bound_str)
        if b is None:
            return None
        return {"<": v < b, "<=": v <= b, ">=": v >= b, ">": v > b, "=": v == b}.get(op)

    def _state(r) -> str:
        """bool/None d'une contrainte → état ; None (non parseable) → UNKNOWN."""
        if r is True:
            return MATCH_AFFECTED
        if r is False:
            return MATCH_NOT_AFFECTED
        return MATCH_UNKNOWN

    # ── Format virgule / énumération ─────────────────────────────────────────
    # Deux sémantiques cohabitent dans EUVD :
    #   - bornes explicites : ">= 10.0.0, < 11.0.0"        → contraintes ET
    #   - énumération        : "affects 2.7, 3.5, 3.6, 3.7" → v doit matcher une série
    # (souvent mixte : "affects 2.7, 3.5, …, v3.8.0a4 and < v3.8.0b1")
    if "," in range_str:
        enum: list[str] = []  # versions énumérées = séries affectées
        any_definite = False  # au moins une borne explicite satisfaite
        for part in (p.strip() for p in range_str.split(",") if p.strip()):
            cons = _VIR_EMBEDDED_OP_RE.findall(part)
            if cons:
                for op, ver in cons:
                    r = _check_op(op, ver)
                    if r is False:
                        return MATCH_NOT_AFFECTED  # une borne exclut définitivement v
                    if r is True:
                        any_definite = True
                part = _VIR_EMBEDDED_OP_RE.sub("", part)  # retirer les bornes traitées
            enum.extend(_VIR_BARE_VER_RE.findall(part))
        if enum:
            for e in enum:
                ev = _parse_v(e)
                if ev is None:
                    continue
                if v == ev or (v.major == ev.major and v.minor == ev.minor):
                    return MATCH_AFFECTED  # v appartient à une série énumérée affectée
            return MATCH_NOT_AFFECTED  # v ne matche aucune version énumérée
        return MATCH_AFFECTED if any_definite else MATCH_UNKNOWN

    # ── Format espace-délimité deux tokens : "LOW <HIGH" / "LOW <=HIGH" ─────
    # Représente 68,5 % des entrées EUVD : "0 <26.2.47", "9.0 <=9.0.5400.0"
    # Variante avec wildcard (ex. MariaDB) : "10.6 <10.6.*", "11.1 <11.4.*"
    toks = range_str.split()

    def _norm_low(s: str) -> str:
        """Normalise la borne basse du format 'LOW <HIGH'.
        Cas rencontrés dans EUVD :
          "unspecified"  → "0"          (pas de borne inférieure)
          "8.2.*"        → "8.2.0"      (branche wildcard PHP/EUVD)
          "7.3.x"        → "7.3.0"      (idem lettre minuscule)
          "8.0.X"        → "8.0.0"      (idem lettre majuscule)
          "v1.2.3"       → "1.2.3"      (préfixe v)
        """
        if s.lower() == "unspecified":
            return "0"
        m = _VIR_LOW_BRANCH_RE.match(s)
        if m:
            return m.group(1) + ".0"
        if len(s) > 1 and s[0] in ('v', 'V') and s[1].isdigit():
            return s[1:]
        return s

    if len(toks) == 2:
        low_str, high_tok = toks
        m = _VIR_HIGH_TOK_RE.match(high_tok)
        if m:
            high_op, high_val_str = m.group(1), m.group(2)

            # Wildcard EUVD : "X.Y.*" → deux sémantiques selon le contexte
            # (ex. MariaDB CVE-2023-52970 : "11.1 <11.4.*", "10.6 <10.6.*")
            has_wildcard = high_val_str.endswith(".*")
            if has_wildcard:
                high_val_str = high_val_str[:-2]  # strip ".*"

            low_v  = _parse_v(_norm_low(low_str))
            high_v = _parse_v(high_val_str)
            if low_v is not None and high_v is not None:
                if low_v == high_v:
                    if has_wildcard:
                        # "10.6 <10.6.*" : branche entière affectée sans correctif
                        # dans cette série → tout X.Y.z (z quelconque) est affecté.
                        # On bumpe la borne haute au minor suivant.
                        bumped = Version(f"{high_v.major}.{high_v.minor + 1}.0")
                        return MATCH_AFFECTED if (v >= low_v and v < bumped) else MATCH_NOT_AFFECTED
                    # "186 <186" sans wildcard : encoding Chrome (borne basse répétée)
                    # → interpréter comme borne haute seule.
                    return _state(_check_op(high_op, high_val_str))
                # Cas normal : v >= low_v  ET  v OP high_v
                # "11.1 <11.4.*" (has_wildcard, low != high) : "< 11.4.0" = version
                # corrigée dans la branche 11.4 → les branches 11.1–11.3 sont affectées.
                if v < low_v:
                    return MATCH_NOT_AFFECTED
                return _state(_check_op(high_op, high_val_str))
            # HIGH non parseable ("unspecified", date textuelle…) :
            # v < borne basse connue → non affecté ; sinon plafond inconnu → doute.
            if low_v is not None:
                return MATCH_NOT_AFFECTED if v < low_v else MATCH_UNKNOWN
            return MATCH_UNKNOWN

        # m is None : high_tok n'a pas d'opérateur préfixe
        # "before X" / "below X" → équivalent à "< X"
        if low_str.lower() in ("before", "below", "prior"):
            return _state(_check_op("<", high_tok))
        # "NomÉditeur 2.10.34" (parenthèses déjà retirées) : 1er token non
        # numérique + 2e token = version → version EXACTE affectée.
        # (ex. GIMP CVE-2023-44442 : "GIMP 2.10.34" ⇒ seule 2.10.34 concernée)
        if _parse_v(low_str) is None and _parse_v(high_tok) is not None:
            return MATCH_AFFECTED if v == _parse_v(high_tok) else MATCH_NOT_AFFECTED

    # ── Trois tokens ─────────────────────────────────────────────────────────
    # "prior to X"                              → < X
    # "X and earlier/older/below"               → <= X
    # "X and newer/later/above"                 → >= X
    # "X.Y.z before Z.W"  / "X.Y.x below Z.W"   → >= X.Y.0 AND < Z.W
    # "X.Y - Z.W"                               → >= X.Y AND <= Z.W
    if len(toks) == 3:
        lo, op_word, hi = toks
        op_word_l, lo_l, hi_l = op_word.lower(), lo.lower(), hi.lower()
        # "prior to 2.17.1187" → < 2.17.1187
        if lo_l == "prior" and op_word_l == "to":
            return _state(_check_op("<", hi))
        # "3.0 and earlier" → <= 3.0 ; "2.3.12 and newer" → >= 2.3.12
        if op_word_l == "and":
            if hi_l in ("earlier", "older", "below", "before", "prior", "lower"):
                return _state(_check_op("<=", lo))
            if hi_l in ("newer", "later", "above", "higher", "greater"):
                return _state(_check_op(">=", lo))
        if op_word_l in ("before", "below", "prior"):
            low_v  = _parse_v(_norm_low(lo))
            high_v = _parse_v(hi)
            if low_v is not None and high_v is not None:
                if v < low_v:
                    return MATCH_NOT_AFFECTED
                return MATCH_AFFECTED if v < high_v else MATCH_NOT_AFFECTED
            return MATCH_UNKNOWN
        if op_word == "-":
            low_v  = _parse_v(lo)
            high_v = _parse_v(hi)
            if low_v is not None and high_v is not None:
                return MATCH_AFFECTED if low_v <= v <= high_v else MATCH_NOT_AFFECTED
            return MATCH_UNKNOWN

    # ── Quatre tokens : "all X.x before Y" / "all X.Y.x before Z" ────────────
    # Ex. PostgreSQL "all 10.x before 10.10" : seule la série 10.x (< 10.10)
    # est concernée — une version d'une autre branche majeure (18.4) ne l'est pas.
    if len(toks) == 4 and toks[0].lower() == "all" and toks[2].lower() in ("before", "below", "prior"):
        mb = _VIR_LOW_BRANCH_RE.match(toks[1])
        high_v = _parse_v(toks[3])
        if mb and high_v is not None:
            if not _in_series(v, mb.group(1)):
                return MATCH_NOT_AFFECTED
            return MATCH_AFFECTED if v < high_v else MATCH_NOT_AFFECTED
        return MATCH_UNKNOWN

    # ── Contrainte unique avec opérateur : "< 0.3.2", ">=10.0.0" ───────────
    m = _VIR_CONSTRAINT_RE.match(range_str)
    if m:
        return _state(_check_op(m.group(1), m.group(2)))

    # ── Version exacte : "4.1.0" ────────────────────────────────────────────
    b = _parse_v(range_str)
    if b is not None:
        return MATCH_AFFECTED if v == b else MATCH_NOT_AFFECTED

    # ── Format non reconnu (RPM epoch, git hash, labels vendeur…) → indéterminé
    return MATCH_UNKNOWN


def _version_in_range(version: str, range_str: str) -> str:
    """Wrapper : évalue normalement, puis — SEULEMENT si le résultat est UNKNOWN —
    réessaie sur une version nettoyée des qualificatifs non standard (ESR/EAP,
    'to <', 'X.x prior to'). Garantie zéro effet de bord : un résultat déjà décidé
    (AFFECTED/NOT_AFFECTED) n'est jamais modifié ; seul un UNKNOWN peut être rattrapé.
    """
    r = _version_in_range_raw(version, range_str)
    if r != MATCH_UNKNOWN:
        return r
    base = (range_str or "").strip()
    cleaned = _clean_version_qualifiers(base)
    if cleaned and cleaned != base:
        r2 = _version_in_range_raw(version, cleaned)
        if r2 != MATCH_UNKNOWN:
            return r2
    return MATCH_UNKNOWN


def _fetch_euvd_vulns(vendor: str, product: str,
                      from_updated_date: str | None = None) -> tuple[list[dict], bool]:
    """Récupère les vulns EUVD pour un vendor/product.

    from_updated_date (YYYY-MM-DD) : ne ramène que les CVE mises à jour depuis
    cette date (fetch INCRÉMENTAL). Sinon récupère tout le catalogue du produit.

    Retourne (items, complete). `complete` vaut False dès qu'une page échoue
    définitivement (réseau/timeout/rate-limit) ou qu'une page revient vide
    alors que la pagination n'était pas terminée : le jeu est alors PARTIEL et
    ne doit PAS servir de base à la résolution (sinon on résout à tort des
    findings dont le CVE n'a simplement pas été ramené ce cycle).
    """
    import urllib.request

    all_items = []
    total = None
    page = 0
    # EUVD plafonne à 100 enregistrements/requête ; la pagination se fait via `page`
    # (indice de page, débute à 0) — PAS via un offset. Utiliser `start` renvoyait
    # en boucle la première page (doublons + CVE au-delà de 100 jamais récupérées).
    page_size = min(_get_page_size(), 100)
    MAX_PAGES = 1000  # garde-fou anti-boucle si `total` est incohérent
    date_param = f"&fromUpdatedDate={from_updated_date}" if from_updated_date else ""

    while page < MAX_PAGES:
        url = (f"{EUVD_SEARCH_API}?vendor={urllib.request.quote(vendor)}"
               f"&product={urllib.request.quote(product)}&size={page_size}&page={page}{date_param}")

        # Helper commun : rate-limit + 429 (Retry-After / backoff) unifiés.
        data, err = _api_get_json(url, timeout=30, max_attempts=5,
                                  label=f"{vendor}/{product} page={page}")
        if data is None:
            # Échec définitif de cette page → jeu partiel (résolution ignorée)
            logger.warning(f"[CPE WATCH] EUVD page échouée {vendor}/{product} page={page}: {err}")
            return all_items, False

        items = data.get("items", [])
        if total is None:
            total = data.get("total", len(items))

        if not items:
            # Plus d'items : complet seulement si on a réellement tout parcouru
            return all_items, (total == 0 or len(all_items) >= total)

        all_items.extend(items)
        page += 1
        if len(all_items) >= total:
            return all_items, True
        # (espacement entre pages assuré par le throttle global dans _api_get_json)

    return all_items, False  # MAX_PAGES atteint → considéré partiel


def _extract_cve_entries(euvd_items: list[dict], product: str) -> list[dict]:
    """Normalise les items EUVD en [{cve, ranges, score, desc}] pour un produit.

    Ne conserve que les CVE ayant au moins une plage de version pour ce produit.
    C'est ce jeu allégé qui est mis en cache (cpe_watch_cache) et qui alimente
    aussi bien la surveillance en ligne que la réévaluation locale.
    """
    entries = []
    seen_cves: set[str] = set()  # dédup (robustesse : pagination ne doit pas dupliquer)
    for item in euvd_items:
        cve_id = ""
        for a in (item.get("aliases") or "").split("\n"):
            a = a.strip()
            if a.startswith("CVE-"):
                cve_id = a.upper()
                break
        if not cve_id or cve_id in seen_cves:
            continue
        ranges = []
        for p in item.get("enisaIdProduct", []):
            if p.get("product", {}).get("name", "").lower() != product.lower():
                continue
            vr = p.get("product_version", "")
            if vr:
                ranges.append(vr)
        if not ranges:
            continue
        seen_cves.add(cve_id)
        entries.append({
            "cve": cve_id,
            "ranges": ranges,
            "score": item.get("baseScore"),
            "desc": (item.get("description") or "")[:500],
        })
    return entries


def check_monitored_software(item_id: int | None = None, progress_callback=None,
                             use_cache: bool = False):
    """Vérifie les CVE pour tous les logiciels surveillés (ou un seul si item_id fourni).
    progress_callback(current, total, vendor, product) est appelé avant chaque item.
    Crée des findings source='cpe_watch' pour les vulns détectées.

    Deux modes :

    use_cache=False (surveillance en ligne, incrémentale) — par produit :
      • version inchangée ET cache frais (< intervalle) → SKIP (rien de neuf) ;
      • version changée mais cache frais → réévaluation depuis le cache, SANS fetch
        (résolution comprise) ;
      • cache périmé / partiel / absent → fetch EUVD (récupère les NOUVELLES CVE).

    use_cache=True (réévaluation locale FORCÉE) — relit les plages depuis
    cpe_watch_cache et réévalue TOUS les produits (même version inchangée), sans
    aucun appel réseau. Sert à réappliquer un correctif du moteur de matching aux
    anciens findings. Un produit sans cache est ignoré.
    """
    from app.db import connect_db
    from collections import defaultdict
    from datetime import datetime as _dt, timedelta as _td

    conn = connect_db()
    try:
        if item_id is not None:
            software_list = conn.execute(
                "SELECT * FROM monitored_software WHERE id=?", (item_id,)
            ).fetchall()
        else:
            software_list = conn.execute("SELECT * FROM monitored_software").fetchall()
        if not software_list:
            return

        # Skip incrémental (run complet en ligne uniquement) : un produit vérifié
        # avec succès il y a moins de ~90 % de l'intervalle configuré n'est pas
        # re-interrogé. Évite de tout re-télécharger à chaque « Lancer la vérification »
        # et, après un run partiel, ne refait que les produits pas encore à jour.
        fresh_cutoff = None
        if item_id is None and not use_cache:
            from app.auth.roles import app_settings
            iv = app_settings().get("schedules", {}).get("cpe_watch", {}).get("interval_hours", 24)
            if not iv or iv <= 0:
                iv = 24
            fresh_cutoff = (_dt.now() - _td(hours=iv * 0.9)).isoformat()

        now = _dt.now().isoformat()
        total_created = 0
        total_resolved = 0
        total_sw = len(software_list)

        # Regrouper par (vendor, product) : la résolution doit couvrir TOUS les hôtes
        # qui surveillent le même produit pour éviter de les résoudre mutuellement.
        groups: dict[tuple, list] = defaultdict(list)
        for sw in software_list:
            groups[(sw["vendor"], sw["product"])].append(sw)

        idx = 0
        for (vendor, product), sw_group in groups.items():
            # Signature des versions surveillées de ce produit (tous les hôtes).
            # Sert au skip incrémental par version : inchangée → matching identique.
            current_sig = "|".join(sorted(
                f"{(sw['host_ip'] or 'monitored')}={sw['version'] or '*'}" for sw in sw_group))

            # Source des plages : cache local (réévaluation forcée) ou EUVD (surveillance)
            if use_cache:
                # Réévaluation locale FORCÉE : réévalue TOUS les produits en cache,
                # même à version inchangée (réapplique un correctif de matching).
                row = conn.execute(
                    "SELECT complete, data FROM cpe_watch_cache WHERE vendor=? AND product=?",
                    (vendor, product),
                ).fetchone()
                if row is None:
                    logger.info(f"[CPE WATCH] {vendor}/{product} — pas de cache, ignoré (mode local)")
                    continue
                try:
                    cve_entries = json.loads(row["data"])
                except (json.JSONDecodeError, TypeError):
                    cve_entries = []
                fetch_complete = bool(row["complete"])
                conn.execute(
                    "UPDATE cpe_watch_cache SET versions_sig=?, evaluated_at=? WHERE vendor=? AND product=?",
                    (current_sig, now, vendor, product),
                )
                logger.info(
                    f"[CPE WATCH] {vendor}/{product} — {len(cve_entries)} CVE (cache local, "
                    f"{'complet' if fetch_complete else 'PARTIEL'})"
                )
            else:
                # Surveillance en ligne INCRÉMENTALE (run complet uniquement) :
                #   version inchangée + cache frais → skip
                #   version changée + cache frais   → réévaluation locale (sans fetch)
                #   sinon → fetch EUVD : INCRÉMENTAL par date (fromUpdatedDate) si un
                #           cache complet existe → seules les CVE mises à jour depuis le
                #           dernier fetch sont téléchargées, puis fusionnées dans le cache.
                prev = conn.execute(
                    "SELECT complete, fetched_at, versions_sig, data FROM cpe_watch_cache "
                    "WHERE vendor=? AND product=?", (vendor, product),
                ).fetchone()
                # Une base utilisable = des données en cache (même marquée incomplète :
                # EUVD renvoie du plus récent au plus ancien, donc un fetch partiel a les
                # CVE récentes = pertinentes ; l'incrémental par date la maintient à jour).
                has_base = bool(prev and prev["data"] and prev["data"] != "[]")
                reeval_only = False
                if fresh_cutoff is not None and has_base:
                    fresh = prev["fetched_at"] and prev["fetched_at"] >= fresh_cutoff
                    version_changed = prev["versions_sig"] != current_sig
                    if fresh and not version_changed:
                        logger.info(f"[CPE WATCH] {vendor}/{product} — à jour, versions inchangées, ignoré")
                        continue
                    if fresh and version_changed:
                        reeval_only = True  # version changée mais CVE fraîches → pas de fetch

                if reeval_only:
                    try:
                        cve_entries = json.loads(prev["data"])
                    except (json.JSONDecodeError, TypeError):
                        cve_entries = []
                    fetch_complete = True
                    conn.execute(
                        "UPDATE cpe_watch_cache SET versions_sig=?, evaluated_at=? WHERE vendor=? AND product=?",
                        (current_sig, now, vendor, product),
                    )
                    logger.info(
                        f"[CPE WATCH] {vendor}/{product} — version changée → réévaluation locale "
                        f"({len(cve_entries)} CVE, sans fetch)"
                    )
                else:
                    # Fetch incrémental par date dès qu'une base existe (fromUpdatedDate),
                    # sinon fetch complet (premier amorçage : aucune base).
                    from_date = None
                    if has_base and prev["fetched_at"]:
                        from_date = prev["fetched_at"][:10]  # YYYY-MM-DD
                    euvd_items, fetch_complete = _fetch_euvd_vulns(
                        vendor, product, from_updated_date=from_date)
                    new_entries = _extract_cve_entries(euvd_items, product)
                    if from_date is not None:
                        # Fusion : mise à jour/ajout des CVE modifiées dans la base.
                        # La base fusionnée est notre meilleur jeu complet → on la
                        # considère complète (résolution autorisée) même si la requête
                        # incrémentale a échoué partiellement (on ne perd rien).
                        try:
                            old_entries = json.loads(prev["data"])
                        except (json.JSONDecodeError, TypeError):
                            old_entries = []
                        merged = {e["cve"]: e for e in old_entries}
                        for e in new_entries:
                            merged[e["cve"]] = e
                        cve_entries = list(merged.values())
                        fetch_complete = True
                        logger.info(
                            f"[CPE WATCH] {vendor}/{product} — incrémental depuis {from_date} : "
                            f"+{len(new_entries)} MàJ → {len(cve_entries)} CVE au total"
                        )
                    else:
                        cve_entries = new_entries
                        logger.info(
                            f"[CPE WATCH] {vendor}/{product} — {len(cve_entries)} CVE EUVD "
                            f"(catalogue complet, fetch {'complet' if fetch_complete else 'PARTIEL'})"
                        )
                    conn.execute(
                        """INSERT INTO cpe_watch_cache
                             (vendor, product, complete, fetched_at, data, versions_sig, evaluated_at)
                           VALUES(?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(vendor, product) DO UPDATE SET
                             complete=excluded.complete, fetched_at=excluded.fetched_at,
                             data=excluded.data, versions_sig=excluded.versions_sig,
                             evaluated_at=excluded.evaluated_at""",
                        (vendor, product, 1 if fetch_complete else 0, now,
                         json.dumps(cve_entries, ensure_ascii=False), current_sig, now),
                    )

            # seen_vuln_keys  : (vuln_id, host_ip) dont la version matche cette exécution
            # evaluated_cve_ids : CVE IDs dont on a le range ET qu'on a évalués.
            #   Seuls ces CVEs peuvent déclencher une résolution : si le range est absent
            #   (réseau/pagination incomplète), on preserve le finding plutôt que de créer
            #   un faux-négatif transitoire (source du flapping).
            seen_vuln_keys: set[tuple] = set()
            evaluated_cve_ids: set[str] = set()

            for sw in sw_group:
                idx += 1
                host_ip = sw["host_ip"] or "monitored"
                version = sw["version"]

                # Libérer le verrou d'écriture (cache produit / findings hôte
                # précédent) AVANT le progress_callback : celui-ci écrit task_status
                # sur une autre connexion et se bloquerait sinon ("database is locked").
                conn.commit()
                if progress_callback:
                    progress_callback(idx, total_sw, vendor, product)
                logger.info(f"[CPE WATCH] [{idx}/{total_sw}] {vendor}/{product}@{host_ip} v{version or '*'}...")

                for entry in cve_entries:
                    cve_id = entry["cve"]
                    product_ranges = entry["ranges"]
                    if not product_ranges:
                        continue

                    evaluated_cve_ids.add(cve_id)
                    # Agrégation multi-plages : AFFECTED prime ; sinon UNKNOWN
                    # (doute) prime sur NOT_AFFECTED.
                    states = [_version_in_range(version, r) for r in product_ranges]
                    if MATCH_AFFECTED in states:
                        match_state = MATCH_AFFECTED
                    elif MATCH_UNKNOWN in states:
                        match_state = MATCH_UNKNOWN
                    else:
                        match_state = MATCH_NOT_AFFECTED
                    logger.debug(
                        f"[CPE WATCH] {cve_id} — {vendor}/{product} v{version or '*'} "
                        f"{match_state} (ranges: {product_ranges})"
                    )
                    if match_state == MATCH_NOT_AFFECTED:
                        continue  # prouvé hors plage → pas de finding
                    # AFFECTED → confiance 'confirmed' ; UNKNOWN → 'unknown'
                    confidence = "confirmed" if match_state == MATCH_AFFECTED else "unknown"

                    vuln_name = f"[CPE] {cve_id} — {vendor}/{product}"
                    oid = f"cpe-watch:{cve_id}:{vendor}:{product}"

                    # Upsert vulnerability — RETURNING id élimine le SELECT N+1
                    cur = conn.execute(
                        """INSERT INTO vulnerabilities (oid, name, family, cvss_base, solution)
                           VALUES (?, ?, 'CPE Watch', ?, '')
                           ON CONFLICT(oid) DO UPDATE SET name=excluded.name, cvss_base=excluded.cvss_base
                           RETURNING id""",
                        (oid, vuln_name, entry["score"]),
                    )
                    vuln_id = cur.fetchone()[0]

                    # Lier la CVE
                    conn.execute("INSERT OR IGNORE INTO vuln_cves(vuln_id, cve_id) VALUES(?, ?)", (vuln_id, cve_id))

                    # Upsert finding — RETURNING id élimine le SELECT N+1
                    sev = entry["score"] or 0
                    threat = "Critical" if sev >= 9 else "High" if sev >= 7 else "Medium" if sev >= 4 else "Low"
                    match_range = " ; ".join(product_ranges)  # plages du produit SURVEILLÉ
                    cur = conn.execute(
                        """INSERT INTO findings
                             (vuln_id, host_ip, port, severity, qod, threat, description,
                              primary_cve, vendor, product, status, first_seen, last_seen,
                              match_confidence, match_range)
                           VALUES (?, ?, 'N/A', ?, 100, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                           ON CONFLICT(vuln_id, host_ip, port) DO UPDATE SET
                             severity=MAX(findings.severity, excluded.severity),
                             last_seen=excluded.last_seen,
                             status=CASE WHEN findings.status='false_positive'
                                          THEN 'false_positive' ELSE 'active' END,
                             resolved_at=CASE WHEN findings.status='false_positive'
                                          THEN findings.resolved_at ELSE NULL END,
                             match_confidence=excluded.match_confidence,
                             vendor=excluded.vendor, product=excluded.product,
                             match_range=excluded.match_range
                           RETURNING id""",
                        (vuln_id, host_ip, sev,
                         threat, entry["desc"], cve_id,
                         vendor, product, now, now, confidence, match_range),
                    )
                    finding_id = cur.fetchone()[0]

                    conn.execute(
                        """INSERT OR IGNORE INTO sightings
                             (finding_id, task_id, task_name, report_id, scan_date)
                           VALUES (?, 'cpe_watch', 'CPE Watch', ?, ?)""",
                        (finding_id, f"cpe_watch_{now[:10]}", now),
                    )

                    seen_vuln_keys.add((vuln_id, host_ip))
                    total_created += 1

            # Résolution une seule fois par groupe — SEULEMENT si le fetch EUVD
            # a été complet. Un jeu partiel (page ratée) ne contient qu'une partie
            # des CVE : lancer la résolution figerait/résoudrait à tort le reste.
            if not fetch_complete:
                logger.warning(
                    f"[CPE WATCH] {vendor}/{product} — fetch partiel, résolution ignorée "
                    f"(findings existants préservés)"
                )
                conn.commit()
                continue

            # Échapper les wildcards LIKE (les noms CPE contiennent souvent des _)
            safe_v = vendor.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            safe_p = product.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            existing = conn.execute(
                """SELECT f.id, f.vuln_id, f.host_ip, v.oid FROM findings f
                   JOIN vulnerabilities v ON f.vuln_id = v.id
                   WHERE v.oid LIKE ? ESCAPE '\\' AND f.status = 'active'""",
                (f"cpe-watch:%:{safe_v}:{safe_p}",),
            ).fetchall()

            for row in existing:
                if (row["vuln_id"], row["host_ip"]) in seen_vuln_keys:
                    continue  # version toujours affectée → conserver

                # Ne résoudre que si le CVE a été explicitement évalué cette run.
                # Un CVE absent des résultats EUVD (timeout, pagination incomplète)
                # ne doit PAS déclencher de résolution → sinon flapping garanti.
                oid_parts = row["oid"].split(":", 3)
                cve_in_oid = oid_parts[1] if len(oid_parts) == 4 else ""
                if cve_in_oid not in evaluated_cve_ids:
                    continue  # EUVD ne l'a pas retourné ce cycle → préserver

                conn.execute(
                    "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?",
                    (now, row["id"]),
                )
                total_resolved += 1

            # Commit après chaque groupe (vendor/product) pour libérer le verrou
            conn.commit()

        # Nettoyage final (run complet seulement) : résoudre les findings CPE Watch
        # dont le couple (vendor, product) extrait de l'OID n'est plus surveillé.
        # Couvre les cas de renommage de produit (ex. xnview → xnview_mp) et de
        # suppression d'entrée sans passage par software_delete.
        if item_id is None:
            monitored_pairs = {(sw["vendor"], sw["product"]) for sw in software_list}
            orphaned = conn.execute(
                "SELECT f.id, v.oid FROM findings f"
                " JOIN vulnerabilities v ON f.vuln_id = v.id"
                " WHERE v.family='CPE Watch' AND f.status='active'"
            ).fetchall()
            orphan_count = 0
            for row in orphaned:
                # OID format : cpe-watch:{cve_id}:{vendor}:{product}
                oid_parts = row["oid"].split(":", 3)
                if len(oid_parts) == 4:
                    _, _, oid_vendor, oid_product = oid_parts
                    if (oid_vendor, oid_product) not in monitored_pairs:
                        conn.execute(
                            "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?",
                            (now, row["id"]),
                        )
                        orphan_count += 1
            if orphan_count:
                logger.info(f"[CPE WATCH] Nettoyage orphelins: {orphan_count} finding(s) résolus (produit retiré ou renommé)")
                total_resolved += orphan_count
                conn.commit()

        logger.info(f"[CPE WATCH] Terminé: {total_created} findings actifs, {total_resolved} résolus")

    finally:
        conn.close()


@cache_bp.route("/refresh-cpe-watch", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_cpe_watch():
    """Lance la vérification des logiciels surveillés."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("cpe_watch"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Vérification déjà en cours"})
        flash("Une vérification est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("cpe_watch", _task_cpe_watch)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "cpe_watch", "message": "Vérification démarrée"})

    if success:
        flash("Vérification des logiciels surveillés démarrée.", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/refresh-cpe-watch-local", methods=["POST"])
@login_required
@require_perm("cache.refresh_gmp")
def refresh_cpe_watch_local():
    """Réévaluation locale : réapplique le matching sur les plages EUVD en cache."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("cpe_watch"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Vérification déjà en cours"})
        flash("Une vérification est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    success, message = start_background_task("cpe_watch", _task_cpe_watch_local)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "cpe_watch", "message": "Réévaluation locale démarrée"})

    if success:
        flash("Réévaluation locale démarrée (sans appel EUVD).", "info")
    else:
        flash(f"Impossible de démarrer : {message}", "danger")

    return redirect(url_for("cache.index"))


def _finalize_cpe_watch():
    """Enrichissement + mise à jour du cache après une vérification CPE watch."""
    from app.tasks import update_task_status
    from app.db import connect_db, enrich_and_score, save_gmp_cache

    update_task_status("cpe_watch", message="Enrichissement...")
    conn = connect_db()
    try:
        enrich_and_score(conn)
        cpe_findings = conn.execute(
            "SELECT COUNT(*) FROM findings f JOIN vulnerabilities v ON f.vuln_id=v.id"
            " WHERE v.family='CPE Watch' AND f.status='active'"
        ).fetchone()[0]
        save_gmp_cache(conn, "cpe_watch", [{"_count": cpe_findings}])
    finally:
        conn.close()


def _task_cpe_watch():
    """Tâche de fond pour la vérification de tous les logiciels surveillés."""
    from app.tasks import update_task_status

    def _progress(current, total, vendor, product):
        update_task_status("cpe_watch",
                           progress=f"{current}/{total}",
                           message=f"{vendor}/{product}")

    update_task_status("cpe_watch", progress="0/?", message="Démarrage...")
    check_monitored_software(progress_callback=_progress)
    _finalize_cpe_watch()


def _task_cpe_watch_one(item_id: int):
    """Tâche de fond pour la vérification d'un seul logiciel (déclenché à l'édition)."""
    from app.tasks import update_task_status

    def _progress(current, total, vendor, product):
        update_task_status("cpe_watch",
                           progress=f"{current}/{total}",
                           message=f"{vendor}/{product}")

    update_task_status("cpe_watch", progress="0/1", message="Démarrage...")
    check_monitored_software(item_id=item_id, progress_callback=_progress)
    _finalize_cpe_watch()


def _task_cpe_watch_local():
    """Réévaluation LOCALE : réapplique le matching sur les plages EUVD en cache,
    sans aucun appel réseau (utile après un ajustement du moteur de matching)."""
    from app.tasks import update_task_status

    def _progress(current, total, vendor, product):
        update_task_status("cpe_watch",
                           progress=f"{current}/{total}",
                           message=f"{vendor}/{product} (local)")

    update_task_status("cpe_watch", progress="0/?", message="Réévaluation locale...")
    check_monitored_software(progress_callback=_progress, use_cache=True)
    _finalize_cpe_watch()


# ══════════════════════════════════════════════════════════════════════════════
# Tâches async
# ══════════════════════════════════════════════════════════════════════════════

NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _task_refresh_cpe_dict():
    """Synchro incrémentale du dictionnaire CPE depuis l'API NVD."""
    import urllib.request
    import urllib.error
    from app.tasks import update_task_status
    from app.db import connect_db

    logger.info("[CPE DICT] Démarrage synchro incrémentale")
    update_task_status("cpe_dict", message="Préparation...")

    conn = connect_db()
    last = conn.execute("SELECT MAX(last_modified) FROM cpe_dictionary").fetchone()[0]
    conn.close()

    start_index = 0
    results_per_page = 2000
    total_imported = 0
    has_more = True
    rate_limit = 7

    params = [f"resultsPerPage={results_per_page}"]
    if last:
        params.append(f"lastModStartDate={last}")
        params.append(f"lastModEndDate={datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')}")
        logger.info(f"[CPE DICT] Incrémental depuis {last}")
    else:
        logger.info("[CPE DICT] Import complet (pas de date en base)")

    while has_more:
        url = f"{NVD_CPE_API}?{'&'.join(params)}&startIndex={start_index}"
        update_task_status("cpe_dict", progress=f"{total_imported}+",
                           message=f"Téléchargement page (index {start_index})...")

        data = None
        for attempt in range(10):
            try:
                req = urllib.request.Request(url, headers={
                    "Accept": "application/json",
                    "User-Agent": "GMPilot-CPE/1.0",
                })
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                wait = min((attempt + 1) * 15, 120)
                logger.warning(f"[CPE DICT] Erreur page index={start_index}: {e} — retry {attempt+1}/10 dans {wait}s")
                time.sleep(wait)
            except Exception as e:
                logger.error(f"[CPE DICT] Erreur inattendue: {e}")
                time.sleep(30)

        if not data:
            logger.error(f"[CPE DICT] Échec page index={start_index} après 10 tentatives — skip")
            start_index += results_per_page
            continue

        products = data.get("products", [])
        total_results = data.get("totalResults", 0)

        batch = []
        for p in products:
            cpe = p.get("cpe", {})
            cpe_name = cpe.get("cpeName", "")
            parts = cpe_name.split(":")
            if len(parts) < 6:
                continue

            titles = cpe.get("titles", [])
            title = ""
            for t in titles:
                if t.get("lang", "en").startswith("en"):
                    title = t.get("title", "")
                    break
            if not title and titles:
                title = titles[0].get("title", "")

            batch.append((
                cpe_name, parts[2], parts[3], parts[4],
                parts[5] if parts[5] != "*" else "",
                parts[6] if len(parts) > 6 and parts[6] != "*" else "",
                title,
                cpe.get("created", ""),
                cpe.get("lastModified", ""),
            ))

        if batch:
            conn = connect_db()
            conn.executemany(
                """INSERT OR REPLACE INTO cpe_dictionary
                     (cpe_uri, cpe_type, vendor, product, version, update_str, title, created, last_modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                batch,
            )
            conn.commit()
            conn.close()

        total_imported += len(products)
        start_index += results_per_page

        has_more = start_index < total_results
        if has_more:
            time.sleep(rate_limit)

    logger.info(f"[CPE DICT] Terminé: {total_imported} CPEs importés")

def _task_refresh_cve():
    """Tâche de fond pour rafraîchir le cache CVE."""
    from app.tasks import update_task_status
    from app.db import connect_db, upsert_cve, enrich_and_score

    logger.info("[CVE TASK] Démarrage")
    update_task_status("cve", message="Analyse des CVE manquantes...")

    conn = connect_db()
    needed = {r["cve_id"] for r in conn.execute("SELECT DISTINCT cve_id FROM vuln_cves")}
    cached = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM cves WHERE euvd_updated_at IS NOT NULL")}
    conn.close()

    to_download = sorted(needed - cached)
    results = {"downloaded": 0, "skipped": len(cached & needed),
                "errors": 0, "total": len(needed)}
    batch = []
    BATCH_SIZE = 20

    for i, cve_id in enumerate(to_download):
        update_task_status("cve", progress=f"{i+1}/{len(to_download)}",
                           message=f"Téléchargement {cve_id}...")
        if results["downloaded"] > 0 or results["errors"] > 0:
            time.sleep(_get_rate_limit())

        data, error = fetch_cve_from_euvd(cve_id)
        if data:
            batch.append((cve_id, data))
            results["downloaded"] += 1
        elif error:
            results["errors"] += 1
            logger.warning(f"CVE fetch failed for {cve_id}: {error}")
            batch.append((cve_id, {
                "id": cve_id,
                "description": f"Indisponible: {error}",
                "_source": "unavailable",
            }))

        if len(batch) >= BATCH_SIZE:
            conn = connect_db()
            for cid, d in batch:
                upsert_cve(conn, cid, d)
            conn.commit()
            conn.close()
            batch = []

    if batch:
        conn = connect_db()
        for cid, d in batch:
            upsert_cve(conn, cid, d)
        conn.commit()
        conn.close()

    # Cleanup stale
    stale = cached - needed
    if stale:
        conn = connect_db()
        conn.executemany(
            "UPDATE cves SET vendor=NULL,product=NULL,epss=NULL,raw_json=NULL,euvd_updated_at=NULL WHERE cve_id=?",
            [(c,) for c in stale])
        conn.commit()
        conn.close()

    update_task_status("cve", message="Re-enrichissement des findings...")
    conn = connect_db()
    try:
        enrich_and_score(conn)
        from app.db import save_gmp_cache
        save_gmp_cache(conn, "cve", [{"_checked": results}])
    finally:
        conn.close()

    logger.info(f"[CVE TASK] Terminé: {results['downloaded']} téléchargées, {results['errors']} erreurs")


def _task_update_cve():
    """Tâche de fond : rafraîchit les CVE existantes DONT les données EUVD sont
    périmées (plus anciennes que l'intervalle configuré).

    Incrémental par péremption → un redémarrage du service juste après une synchro
    ne re-télécharge rien (évite le refetch complet du cache à chaque chargement).
    """
    from app.tasks import update_task_status
    from app.db import connect_db, upsert_cve, enrich_and_score
    from app.auth.roles import app_settings
    from datetime import datetime as _dt, timedelta as _td

    logger.info("[CVE UPDATE TASK] Démarrage")
    update_task_status("cve", message="Analyse des CVE périmées...")

    # Seuil de péremption : ~90 % de l'intervalle configuré (cve_update).
    # Une CVE rafraîchie il y a moins de ce seuil n'est pas re-téléchargée.
    iv = app_settings().get("schedules", {}).get("cve_update", {}).get("interval_hours", 24)
    if not iv or iv <= 0:
        iv = 24
    cutoff = (_dt.now() - _td(hours=iv * 0.9)).isoformat()

    conn = connect_db()
    existing = [r["cve_id"] for r in conn.execute(
        "SELECT cve_id FROM cves WHERE euvd_updated_at IS NOT NULL AND euvd_updated_at < ?",
        (cutoff,),
    )]
    conn.close()

    if not existing:
        logger.info("[CVE UPDATE TASK] Aucune CVE périmée — rien à re-télécharger")
        update_task_status("cve", message="À jour — aucune CVE périmée")
        conn = connect_db()
        try:
            from app.db import save_gmp_cache
            save_gmp_cache(conn, "cve", [{"_checked": {"updated": 0, "errors": 0, "total": 0}}])
        finally:
            conn.close()
        return

    results = {"updated": 0, "errors": 0, "total": len(existing)}
    batch = []
    BATCH_SIZE = 20

    for i, cve_id in enumerate(sorted(existing)):
        update_task_status("cve", progress=f"{i+1}/{len(existing)}",
                           message=f"Mise à jour {cve_id}...")
        if i > 0:
            time.sleep(_get_rate_limit())

        data, error = fetch_cve_from_euvd(cve_id)
        if error:
            results["errors"] += 1
        else:
            batch.append((cve_id, data))
            results["updated"] += 1

        if len(batch) >= BATCH_SIZE:
            conn = connect_db()
            for cid, d in batch:
                upsert_cve(conn, cid, d)
            conn.commit()
            conn.close()
            batch = []

    if batch:
        conn = connect_db()
        for cid, d in batch:
            upsert_cve(conn, cid, d)
        conn.commit()
        conn.close()

    update_task_status("cve", message="Re-enrichissement des findings...")
    conn = connect_db()
    try:
        enrich_and_score(conn)
        from app.db import save_gmp_cache
        save_gmp_cache(conn, "cve", [{"_checked": results}])
    finally:
        conn.close()

    logger.info(f"[CVE UPDATE TASK] Terminé: {results['updated']} mises à jour, {results['errors']} erreurs")


def _task_refresh_kev():
    """Tâche de fond pour rafraîchir le cache KEV."""
    from app.tasks import update_task_status
    from app.db import connect_db, import_kev_dump, enrich_and_score

    logger.info("[KEV TASK] Démarrage")
    update_task_status("kev", message="Téléchargement du dump KEV...")

    data, error = fetch_kev_dump()
    if error:
        logger.warning(f"[KEV TASK] Erreur: {error}")
        raise Exception(error)

    conn = connect_db()
    try:
        path = _kev_cache_path()
        with open(path, "r", encoding="utf-8") as f:
            raw_list = json.load(f)
        if not isinstance(raw_list, list):
            raw_list = []

        update_task_status("kev", message="Import des entrées KEV...")
        kev_cve_ids = import_kev_dump(conn, raw_list)

        # Rescore incrémental : uniquement les findings liés aux CVEs du dump
        update_task_status("kev", message="Re-enrichissement des findings...")
        affected_ids: set[int] | None = None
        if kev_cve_ids:
            ph = ",".join("?" * len(kev_cve_ids))
            affected_ids = {
                r[0] for r in conn.execute(
                    f"SELECT DISTINCT f.id FROM findings f"
                    f" JOIN vuln_cves vc ON f.vuln_id=vc.vuln_id"
                    f" WHERE vc.cve_id IN ({ph})",
                    list(kev_cve_ids),
                )
            }
            logger.info(f"[KEV TASK] {len(kev_cve_ids)} CVEs KEV → {len(affected_ids)} findings à rescorer")

        enrich_and_score(conn, finding_ids=affected_ids)
        logger.info(f"[KEV TASK] Terminé: {len(data) if data else 0} vulnérabilités")
    finally:
        conn.close()


def _task_refresh_iana():
    """Tâche de fond : rafraîchit le référentiel IANA port→service."""
    from app.tasks import update_task_status
    from app.db import connect_db, import_iana_services

    logger.info("[IANA TASK] Démarrage")
    update_task_status("iana", message="Téléchargement du registre IANA...")

    records, registry_date, error = fetch_iana_services()
    if error:
        logger.warning(f"[IANA TASK] Erreur: {error}")
        raise Exception(error)

    update_task_status("iana", message=f"Import de {len(records)} correspondances...")
    conn = connect_db()
    try:
        count = import_iana_services(conn, records)
    finally:
        conn.close()
    logger.info(f"[IANA TASK] Terminé: {count} ports (registre daté {registry_date or '?'})")


def _reverse_dns(ip: str):
    """Résolution PTR d'une IP. Retourne le hostname (str) ou None si absent."""
    import socket
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = (host or "").strip().rstrip(".")
        return host or None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _task_refresh_dns(full: bool = False):
    """Résolution DNS inverse des IP vues en base (findings + hôtes).

    Incrémental (défaut) : uniquement les IP jamais tentées.
    Complet (full=True)  : ré-résout TOUTES les IP valides (renommages, PTR ajoutés).
    Une IP sans PTR est stockée avec hostname NULL (= tentée, pas de retente auto).
    """
    import socket
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    from app.tasks import update_task_status
    from app.db import (connect_db, dns_scan_ips, dns_cached_ips,
                        dns_manual_ips, store_dns_results)

    mode = "complet" if full else "incrémental"
    logger.info(f"[DNS TASK] Démarrage ({mode})")
    update_task_status("dns", message="Collecte des adresses...")

    conn = connect_db()
    try:
        # Ne garder que les IP valides (ignore '179', '10.1.6.x' masqué, 'N/A'…)
        valid = []
        for ip in dns_scan_ips(conn):
            try:
                ipaddress.ip_address(ip)
                valid.append(ip)
            except ValueError:
                continue

        # Les entrées manuelles ne sont jamais re-résolues automatiquement
        manual = dns_manual_ips(conn)
        if full:
            targets = [ip for ip in valid if ip not in manual]
        else:
            cached = dns_cached_ips(conn)
            targets = [ip for ip in valid if ip not in cached]

        total = len(targets)
        if total == 0:
            update_task_status("dns", message="Aucune nouvelle adresse à résoudre")
            logger.info("[DNS TASK] Rien à faire")
            return

        update_task_status("dns", progress=f"0/{total}", message=f"Résolution de {total} adresses...")

        results = []
        resolved = 0
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)  # borne les lookups sans PTR (best-effort)
        try:
            with ThreadPoolExecutor(max_workers=32) as ex:
                for i, (ip, host) in enumerate(zip(targets, ex.map(_reverse_dns, targets), strict=True)):
                    results.append((ip, host))
                    if host:
                        resolved += 1
                    if (i + 1) % 25 == 0 or (i + 1) == total:
                        update_task_status("dns", progress=f"{i+1}/{total}",
                                           message=f"Résolution… ({resolved} hostnames)")
        finally:
            socket.setdefaulttimeout(old_timeout)

        count = store_dns_results(conn, results)
        logger.info(f"[DNS TASK] Terminé ({mode}): {count} IP traitées, {resolved} hostnames")
    finally:
        conn.close()


def _task_refresh_gmp(cache_name: str, username: str, password: str):
    """Tâche de fond pour rafraîchir un cache GMP."""
    from app.tasks import update_task_status

    task_type = f"gmp_{cache_name}"
    logger.info(f"[GMP TASK {cache_name}] Démarrage")
    update_task_status(task_type, message="Connexion GMP...")

    if cache_name not in CACHE_DEFS:
        raise Exception(f"Cache inconnu: {cache_name}")

    defn = CACHE_DEFS[cache_name]
    update_task_status(task_type, message=f"Téléchargement {defn['label']}...")

    with gmp_session(username, password, timeout=300) as gmp:
        xml = _fetch_and_save(gmp, cache_name, defn["filter"])

    if cache_name == "hosts" and xml is not None:
        from app.db import connect_db, import_hosts, recalculate_scores
        conn = connect_db()
        try:
            import_hosts(conn, xml)
            recalculate_scores(conn)
        finally:
            conn.close()

    logger.info(f"[GMP TASK {cache_name}] Terminé")


def _task_refresh_vulns(username: str, password: str):
    """Tâche de fond : refresh vulns depuis le dernier rapport de chaque tâche.
    Écrit dans SQLite (findings/sightings) avec détection de doublons.
    """
    from app.tasks import update_task_status
    from app.db import (connect_db, is_report_imported, import_gmp_results,
                        resolve_stale_findings, mark_report_imported, enrich_and_score)

    task_type = "gmp_vulns"
    logger.info("[VULNS TASK] Démarrage")
    update_task_status(task_type, message="Connexion GMP...")

    conn = connect_db()
    try:
        with gmp_session(username, password, timeout=300) as gmp:
            update_task_status(task_type, message="Récupération des tâches de scan...")
            tasks_xml = gmp.get_tasks(filter_string="rows=-1 details=1")
            tasks = tasks_xml.findall(".//task")

            if not tasks:
                logger.warning("[VULNS TASK] Aucune tâche trouvée")
                return

            updated = 0
            skipped = 0
            total = len(tasks)

            for i, task in enumerate(tasks):
                task_id = task.get("id", "")
                task_name = task.findtext("name") or task_id
                if not task_id:
                    continue

                last_report = task.find("last_report/report")
                if last_report is None:
                    skipped += 1
                    continue

                report_id = last_report.get("id", "")
                if not report_id:
                    skipped += 1
                    continue

                if is_report_imported(conn, task_id, report_id):
                    logger.info(f"[VULNS TASK] {task_name}: déjà importé (report {report_id[:8]}…)")
                    skipped += 1
                    continue

                update_task_status(task_type, progress=f"{i+1}/{total}",
                                   message=f"Téléchargement {task_name}...")
                logger.info(f"[VULNS TASK] {task_name}: téléchargement report {report_id[:8]}…")

                try:
                    results_xml = gmp.get_results(
                        filter_string=f"{VULNS_RESULTS_FILTER} report_id={report_id}"
                    )
                    scan_date = last_report.findtext("timestamp") or ""

                    seen_ids, count = import_gmp_results(
                        conn, results_xml, task_id, task_name, report_id, scan_date
                    )
                    resolved = resolve_stale_findings(conn, task_id, seen_ids, resolved_at=scan_date)
                    mark_report_imported(conn, task_id, task_name, report_id, scan_date, count)

                    updated += 1
                    logger.info(f"[VULNS TASK] {task_name}: {count} résultats importés, {resolved} résolus")
                except Exception as e:
                    logger.error(f"[VULNS TASK] {task_name}: erreur: {e}")

        update_task_status(task_type, message="Enrichissement et scoring...")
        enrich_and_score(conn)

        # Mettre à jour le timestamp même si aucun nouveau rapport
        from datetime import datetime as _dt
        conn.execute(
            """INSERT OR REPLACE INTO gmp_cache(cache_key, data, item_count, updated_at)
               VALUES('vulns_last_check', '[]', ?, ?)""",
            (conn.execute("SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0],
             _dt.now().isoformat()),
        )
        conn.commit()

        logger.info(f"[VULNS TASK] Terminé — {updated} mis à jour, {skipped} ignorés")
    finally:
        conn.close()


def _task_refresh_gmp_all(username: str, password: str):
    """Tâche de fond pour rafraîchir tous les caches GMP + vulns."""
    from app.tasks import update_task_status
    from app.db import connect_db, import_hosts

    logger.info("[GMP ALL TASK] Démarrage")

    hosts_xml = None
    with gmp_session(username, password, timeout=300) as gmp:
        total = len(CACHE_DEFS)
        for i, (key, defn) in enumerate(CACHE_DEFS.items()):
            update_task_status("gmp_all",
                               progress=f"{i+1}/{total+1}",
                               message=f"Téléchargement {defn['label']}...")
            try:
                xml = _fetch_and_save(gmp, key, defn["filter"])
                if key == "hosts":
                    hosts_xml = xml
            except Exception as e:
                logger.warning(f"[GMP ALL TASK] Erreur {key}: {e}")

    if hosts_xml is not None:
        conn = connect_db()
        try:
            import_hosts(conn, hosts_xml)
        finally:
            conn.close()

    update_task_status("gmp_all", progress=f"{total+1}/{total+1}", message="Mise à jour vulnérabilités...")
    try:
        _task_refresh_vulns(username, password)
    except Exception as e:
        logger.warning(f"[GMP ALL TASK] Erreur vulns: {e}")

    logger.info("[GMP ALL TASK] Terminé")


def _task_refresh_anssi(full_refresh: bool = False):
    """Tâche de fond pour rafraîchir le cache ANSSI."""
    from app.scoring import fetch_anssi_cache
    from app.tasks import update_task_status
    from app.db import connect_db, enrich_and_score

    logger.info(f"[ANSSI TASK] Démarrage (full_refresh={full_refresh})")

    def progress_callback(progress, message):
        logger.debug(f"[ANSSI TASK] Progress: {progress} - {message}")
        update_task_status("anssi", progress=progress, message=message)

    try:
        index, error = fetch_anssi_cache(full_refresh=full_refresh, progress_callback=progress_callback)

        update_task_status("anssi", message="Re-enrichissement des findings...")
        conn = connect_db()
        try:
            enrich_and_score(conn)
        finally:
            conn.close()

        if error:
            logger.warning(f"[ANSSI TASK] Terminé avec erreurs: {error}")
        else:
            logger.info(f"[ANSSI TASK] Terminé: {len(index)} CVE indexées")
    except Exception as e:
        logger.exception(f"[ANSSI TASK] Exception: {e}")
        raise


@cache_bp.route("/refresh-anssi", methods=["POST"])
@login_required
@require_perm("cache.refresh_anssi")
def refresh_anssi():
    """Lance le rafraîchissement du cache ANSSI en arrière-plan."""
    from flask import jsonify
    from app.tasks import start_background_task, is_task_running

    if is_task_running("anssi"):
        if _is_ajax():
            return jsonify({"success": False, "error": "Mise à jour ANSSI déjà en cours"})
        flash("Une mise à jour ANSSI est déjà en cours.", "warning")
        return redirect(url_for("cache.index"))

    full_refresh = request.form.get("full", "0") == "1"

    success, message = start_background_task("anssi", _task_refresh_anssi, full_refresh)

    if _is_ajax():
        return jsonify({"success": success, "task_type": "anssi", "message": "Mise à jour ANSSI démarrée"})

    if success:
        flash("Mise à jour ANSSI démarrée en arrière-plan.", "info")
    else:
        flash(f"Impossible de démarrer la mise à jour : {message}", "danger")

    return redirect(url_for("cache.index"))


@cache_bp.route("/status/<task_type>")
@login_required
@require_perm("cache.read")
def task_status(task_type: str):
    """Endpoint AJAX pour vérifier le statut d'une tâche."""
    from flask import jsonify
    from app.tasks import get_task_status

    # Types de tâches autorisés (inclut les caches GMP dynamiques)
    base_types = {"anssi", "cve", "kev", "gmp_all", "gmp_vulns", "cpe_dict", "cpe_watch", "iana", "dns"}
    gmp_types = {f"gmp_{name}" for name in CACHE_DEFS.keys()}
    allowed_types = base_types | gmp_types
    
    if task_type not in allowed_types:
        return jsonify({"error": "Type de tâche invalide"}), 400

    status = get_task_status(task_type)
    return jsonify(status)


@cache_bp.route("/cpe-watch-table")
@login_required
@require_perm("cache.read")
def cpe_watch_table():
    """État courant des logiciels surveillés (pour rafraîchir la table en direct)."""
    from flask import jsonify
    from app.db import get_db

    rows = get_db().execute(
        """SELECT ms.id, ms.vendor, ms.product, ms.version,
                  COALESCE(cwc.evaluated_at, cwc.fetched_at) AS last_checked, cwc.complete AS last_complete
           FROM monitored_software ms
           LEFT JOIN cpe_watch_cache cwc
             ON cwc.vendor = ms.vendor AND cwc.product = ms.product
           ORDER BY ms.vendor, ms.product"""
    ).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@cache_bp.route("/debug-anssi")
@login_required
@require_perm("cache.read")
def debug_anssi():
    """Endpoint de debug pour voir l'état du cache ANSSI."""
    from flask import jsonify
    from app.db import get_db

    db = get_db()
    result = {}
    for cert_type in ["alerte", "avis"]:
        pubs = db.execute(
            "SELECT COUNT(*) as cnt FROM anssi_publications WHERE cert_type=?", (cert_type,)
        ).fetchone()
        cves = db.execute(
            "SELECT COUNT(DISTINCT cve_id) as cnt FROM anssi_cves WHERE cert_type=?", (cert_type,)
        ).fetchone()
        result[f"{cert_type}s"] = {"publications": pubs["cnt"], "cves": cves["cnt"]}

    result["total_cves"] = db.execute("SELECT COUNT(DISTINCT cve_id) FROM anssi_cves").fetchone()[0]

    return jsonify(result)
