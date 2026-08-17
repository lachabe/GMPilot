"""
gvm_client.py — python-gvm 24.8.0 / GMPv227
v3 : pagination, sévérités Critical/High/Medium/Low/Log, parsing enrichi
"""
from contextlib import contextmanager
from flask import current_app
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.protocols.gmp._gmp224 import EntityType

HOST_ENTITY_TYPE = EntityType.HOST
OS_ENTITY_TYPE   = EntityType.OPERATING_SYSTEM

# ─── Sévérité ─────────────────────────────────────────────────────────────────
SEVERITY_CRITICAL = 9.0
SEVERITY_HIGH     = 7.0
SEVERITY_MEDIUM   = 4.0
SEVERITY_LOW      = 0.1

def severity_class(sev: float) -> str:
    """Retourne 'critical'|'high'|'medium'|'low'|'log'."""
    if sev >= SEVERITY_CRITICAL: return "critical"
    if sev >= SEVERITY_HIGH:     return "high"
    if sev >= SEVERITY_MEDIUM:   return "medium"
    if sev >= SEVERITY_LOW:      return "low"
    return "log"

def severity_label(sev: float) -> str:
    m = {"critical": "Critical", "high": "High", "medium": "Medium",
         "low": "Low", "log": "Log"}
    return m[severity_class(sev)]

# ─── Connexion ───────────────────────────────────────────────────────────────
def _get_connection(timeout: int = None):
    cfg = current_app.config
    if timeout is None:
        timeout = cfg.get("GVM_TIMEOUT", 60)
    if cfg["GVM_CONNECTION_TYPE"] == "tcp":
        return TLSConnection(hostname=cfg["GVM_HOST"], port=cfg["GVM_PORT"],
                             timeout=timeout)
    return UnixSocketConnection(path=cfg["GVM_SOCKET_PATH"],
                                timeout=timeout)

@contextmanager
def gmp_session(username: str, password: str, timeout: int = None):
    """
    Context manager pour une session GMP authentifiée.
    
    Args:
        username: Nom d'utilisateur GMP
        password: Mot de passe GMP
        timeout: Timeout en secondes (défaut: GVM_TIMEOUT ou 60s)
    """
    connection = _get_connection(timeout=timeout)
    with Gmp(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(username, password)
        yield gmp


@contextmanager
def gmp_session_for_user(user, timeout: int = None):
    """
    Context manager pour une session GMP pour un utilisateur authentifié.
    
    Compatible avec tous les backends d'authentification:
    - Backend GMP: utilise les credentials de l'utilisateur
    - Backend LDAP/OIDC: utilise le compte de service GMP
    
    Args:
        user: Instance de app.auth.User
        timeout: Timeout en secondes (défaut: GVM_TIMEOUT ou 60s)
    
    Usage:
        from flask_login import current_user
        with gmp_session_for_user(current_user) as gmp:
            tasks = gmp.get_tasks()
    """
    username, password = user.get_gmp_credentials()
    with gmp_session(username, password, timeout=timeout) as gmp:
        yield gmp

# ─── Helpers XML ─────────────────────────────────────────────────────────────
def _text(el, path: str) -> str:
    return el.findtext(path) or ""

def _attr(el, path: str, attr: str) -> str:
    child = el.find(path)
    return child.get(attr, "") if child is not None else ""

def _safe_float(val, default=0.0) -> float:
    try:
        v = float(val or 0)
        return v if (v == v and abs(v) != float("inf")) else default
    except (TypeError, ValueError):
        return default

def _parse_tags_str(tags_str: str) -> dict:
    """Parse la chaîne tags GMP : 'key=val|key2=val2' → dict."""
    result = {}
    if not tags_str:
        return result
    for part in tags_str.split("|"):
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result

# ─── GMP wrappers défensifs ───────────────────────────────────────────────────
def gmp_get_hosts(gmp, filter_string="", details=True):
    """Récupère les hôtes avec leurs détails (tags inclus)."""
    if hasattr(gmp, "get_hosts"):
        return gmp.get_hosts(filter_string=filter_string, details=details) if filter_string else gmp.get_hosts(details=details)
    return gmp.get_assets(asset_type=EntityType.HOST,
                          filter_string=filter_string, details=details) if filter_string \
           else gmp.get_assets(asset_type=EntityType.HOST, details=details)

def gmp_get_host(gmp, host_id):
    if hasattr(gmp, "get_host"):
        return gmp.get_host(host_id)
    return gmp.get_asset(host_id, asset_type=EntityType.HOST)

def gmp_delete_host(gmp, host_id):
    if hasattr(gmp, "delete_host"):
        return gmp.delete_host(host_id)
    return gmp.delete_asset(host_id)

def gmp_get_os(gmp, filter_string=""):
    if hasattr(gmp, "get_operating_systems"):
        return gmp.get_operating_systems(filter_string=filter_string) if filter_string \
               else gmp.get_operating_systems()
    return gmp.get_assets(asset_type=EntityType.OPERATING_SYSTEM)

def gmp_get_vulns(gmp, filter_string=""):
    if hasattr(gmp, "get_vulnerabilities"):
        return gmp.get_vulnerabilities(filter_string=filter_string) if filter_string \
               else gmp.get_vulnerabilities()
    if hasattr(gmp, "get_vulns"):
        return gmp.get_vulns(filter_string=filter_string) if filter_string \
               else gmp.get_vulns()
    raise AttributeError("get_vulnerabilities / get_vulns indisponible")

# ─── Pagination helper ────────────────────────────────────────────────────────
def build_filter(extra: str = "", page: int = 1, per_page: int = 50,
                 sort_field: str = "", sort_order: str = "desc") -> str:
    """Construit un filter_string GMP avec pagination et tri."""
    first = (page - 1) * per_page + 1
    parts = [f"rows={per_page}", f"first={first}"]
    if sort_field:
        parts.append(f"sort{'~' if sort_order == 'desc' else ''}={sort_field}")
    if extra:
        parts.append(extra)
    return " ".join(parts)

def parse_pagination(xml) -> dict:
    """Extrait les méta de pagination depuis l'élément racine XML."""
    filtered = int(xml.get("filtered", 0) or 0)
    full     = int(xml.get("full",     0) or filtered)
    start    = int(xml.get("start",    1) or 1)
    max_r    = int(xml.get("max",     50) or 50)
    page     = max(1, (start - 1) // max_r + 1) if max_r else 1
    total_pages = max(1, (filtered + max_r - 1) // max_r) if max_r else 1
    return {
        "total":       filtered,
        "total_all":   full,
        "page":        page,
        "per_page":    max_r,
        "total_pages": total_pages,
        "has_prev":    page > 1,
        "has_next":    page < total_pages,
    }

# ─── Parsers ─────────────────────────────────────────────────────────────────
def parse_tasks(xml) -> list:
    tasks = []
    for task in xml.findall("task"):
        lr = task.find("last_report/report")
        tasks.append({
            "id":                task.get("id", ""),
            "name":              _text(task, "name"),
            "status":            _text(task, "status"),
            "progress":          _text(task, "progress") or "0",
            "severity":          _safe_float(_text(task, "last_report/report/severity")),
            "hosts":             _text(task, "last_report/report/hosts/count") or "0",
            "target_name":       _text(task, "target/name") or "—",
            "target_id":         _attr(task, "target", "id"),
            "config_name":       _text(task, "config/name") or "—",
            "last_report_id":    lr.get("id", "") if lr is not None else "",
            "creation_time":     _text(task, "creation_time"),
            "modification_time": _text(task, "modification_time"),
            "comment":           _text(task, "comment"),
            "trend":             _text(task, "trend"),
        })
    return tasks

def parse_targets(xml) -> list:
    return [{
        "id":             t.get("id", ""),
        "name":           _text(t, "name"),
        "hosts":          _text(t, "hosts"),
        "exclude_hosts":  _text(t, "exclude_hosts"),
        "comment":        _text(t, "comment"),
        "port_list_id":   _attr(t, "port_list", "id"),
        "port_list_name": _text(t, "port_list/name") or "—",
        "creation_time":  _text(t, "creation_time"),
    } for t in xml.findall("target")]

def parse_reports(xml) -> list:
    reports = []
    for r in xml.findall("report"):
        inner = r.find("report")
        src = inner if inner is not None else r
        reports.append({
            "id":          r.get("id", ""),
            "task_name":   _text(r, "task/name") or "—",
            "task_id":     _attr(r, "task", "id"),
            "timestamp":   _text(src, "timestamp") or _text(r, "timestamp"),
            "scan_end":    _text(src, "scan_end") or _text(r, "scan_end"),
            "scan_start":  _text(src, "scan_start") or _text(r, "scan_start"),
            "severity":    _safe_float(_text(src, "severity") or _text(r, "severity")),
            "high":        int(src.findtext("vuln_count/high") or r.findtext("vuln_count/high") or 0),
            "medium":      int(src.findtext("vuln_count/medium") or r.findtext("vuln_count/medium") or 0),
            "low":         int(src.findtext("vuln_count/low") or r.findtext("vuln_count/low") or 0),
            "hosts_count": src.findtext("hosts/count") or "0",
        })
    return reports

def parse_hosts(xml) -> list:
    hosts = []
    tag = "host" if xml.find("host") is not None else "asset"
    for h in xml.findall(tag):
        os_val = "—"
        for detail in (h.findall("host/detail") or h.findall("detail")):
            if detail.findtext("name") == "best_os_txt":
                os_val = detail.findtext("value") or "—"
                break
        hosts.append({
            "id":        h.get("id", ""),
            "name":      _text(h, "name") or _text(h, "ip"),
            "ip":        _text(h, "ip") or _text(h, "name"),
            "severity":  _safe_float(_text(h, "severity") or _text(h, "host/severity")),
            "os":        os_val,
            "last_seen": _text(h, "modification_time"),
            "comment":   _text(h, "comment"),
        })
    return hosts

def parse_host_detail(xml) -> dict:
    el = xml.find("host") or xml.find("asset")
    if el is None:
        return {}
    details = {}
    for d in (el.findall("detail") or el.findall("host/detail")):
        name = d.findtext("name")
        if name:
            details[name] = d.findtext("value") or ""
    identifiers = []
    for ident in el.findall("identifiers/identifier"):
        identifiers.append({
            "name": _text(ident, "name"), "value": _text(ident, "value"),
            "source": _text(ident, "source/type"),
        })
    return {
        "id": el.get("id", ""), "name": _text(el, "name") or _text(el, "ip"),
        "ip": _text(el, "ip") or _text(el, "name"),
        "severity": _safe_float(_text(el, "severity") or _text(el, "host/severity")),
        "os": details.get("best_os_txt", "—"),
        "os_cpe": details.get("best_os_cpe", "—"),
        "last_seen": _text(el, "modification_time"),
        "comment": _text(el, "comment"),
        "details": details, "identifiers": identifiers,
    }

def parse_os(xml) -> list:
    tag = "os" if xml.find("os") is not None else "asset"
    return [{
        "id":              a.get("id", ""),
        "name":            _text(a, "name"),
        "severity":        _safe_float(_text(a, "severity") or _text(a, "os/severity")),
        "hosts_count":     a.findtext("hosts/count") or a.findtext("os/hosts/count") or "0",
        "latest_severity": _safe_float(_text(a, "latest_severity") or _text(a, "os/latest_severity")),
    } for a in xml.findall(tag)]

def parse_vulnerabilities(xml) -> tuple:
    """
    Retourne (vulns_list, pagination_dict).
    Parse get_vulnerabilities() / get_vulns().
    """
    pagination = parse_pagination(xml)
    vulns = []
    items = xml.findall("vulnerability") or xml.findall("vuln")
    for v in items:
        nvt = v.find("nvt") or v
        sev = _safe_float(v.findtext("severity"))

        # CVE(s) depuis refs
        cves = []
        for ref in v.findall(".//ref"):
            if ref.get("type") == "cve":
                cves.append(ref.get("id", ""))
        if not cves:
            cve_raw = _text(nvt, "cve") or _text(v, "cve")
            if cve_raw and cve_raw != "NOCVE":
                cves = [c.strip() for c in cve_raw.split(",") if c.strip()]

        # CPEs affectés
        cpes = []
        for ref in v.findall(".//ref"):
            if ref.get("type") == "cpe":
                cpes.append(ref.get("id", ""))
        # fallback depuis solution tags
        tags_str = _text(nvt, "tags")
        tags_dict = _parse_tags_str(tags_str)

        vulns.append({
            "id":            v.get("id", ""),
            "oid":           _attr(v, "nvt", "oid") or v.get("id", ""),
            "name":          _text(v, "name") or _text(nvt, "name") or "—",
            "severity":      sev,
            "sev_class":     severity_class(sev),
            "sev_label":     severity_label(sev),
            "qod":           v.findtext("qod/value") or v.findtext("qod") or "—",
            "hosts_count":   int(v.findtext("hosts/count") or v.findtext("hosts") or 0),
            "results_count": int(v.findtext("results/count") or v.findtext("results") or 0),
            "oldest":        (_text(v, "oldest"))[:10] or "—",
            "newest":        (_text(v, "newest"))[:10] or "—",
            # Enrichissement NVT
            "family":        _text(nvt, "family"),
            "cvss_base":     _text(nvt, "cvss_base") or str(sev),
            "cves":          cves,
            "cpe":           cpes,
            "solution":      _text(nvt, "solution") or tags_dict.get("solution", ""),
            "solution_type": _attr(nvt, "solution", "type") or tags_dict.get("solution_type", ""),
            "summary":       tags_dict.get("summary", "") or _text(nvt, "tags"),
            "insight":       tags_dict.get("insight", ""),
            "affected":      tags_dict.get("affected", ""),
            "impact":        tags_dict.get("impact", ""),
        })
    return vulns, pagination

def parse_tickets(xml) -> list:
    tickets = []
    for t in xml.findall("ticket"):
        sev = _safe_float(t.findtext("severity"))
        # result lié au ticket
        result_id   = _attr(t, "result", "id")
        task_name   = _text(t, "task/name")
        task_id     = _attr(t, "task", "id")
        tickets.append({
            "id":           t.get("id", ""),
            "name":         _text(t, "name") or "—",
            "status":       _text(t, "status") or "Open",
            "severity":     sev,
            "sev_class":    severity_class(sev),
            "host":         _text(t, "host") or "—",
            "location":     _text(t, "location") or "—",
            "solution_type":_text(t, "solution_type") or "—",
            "assigned_to":  _text(t, "assigned_to/user/name") or "—",
            "task_name":    task_name or "—",
            "task_id":      task_id,
            "result_id":    result_id,
            "open_note":    _text(t, "open_note") or _text(t, "comment"),
            "fixed_note":   _text(t, "fixed_note"),
            "fix_verified_note": _text(t, "fix_verified_note"),
            "closed_note":  _text(t, "closed_note"),
            "creation_time":(_text(t, "creation_time"))[:16],
            "modification_time": (_text(t, "modification_time"))[:16],
        })
    return tickets

def parse_scan_configs(xml) -> list:
    return [{"id": c.get("id", ""), "name": _text(c, "name"), "comment": _text(c, "comment")}
            for c in xml.findall("config")]

def parse_port_lists(xml) -> list:
    return [{"id": p.get("id", ""), "name": _text(p, "name"),
             "all": p.findtext("port_count/all") or "0",
             "tcp": p.findtext("port_count/tcp") or "0",
             "udp": p.findtext("port_count/udp") or "0",
             "comment": _text(p, "comment")}
            for p in xml.findall("port_list")]

def parse_tags(xml) -> list:
    return [{"id": t.get("id", ""), "name": _text(t, "name"),
             "value": _text(t, "value"), "comment": _text(t, "comment"),
             "resources_count": t.findtext("resources/count") or "0",
             "resource_type": _text(t, "resources/type")}
            for t in xml.findall("tag")]

def parse_results(xml, min_severity: float = 0.0) -> list:
    results = []
    for r in xml.findall(".//result"):
        sev = _safe_float(r.findtext("severity"))
        if sev < min_severity:
            continue
        cve = "—"
        for ref in r.findall(".//ref"):
            if ref.get("type") == "cve":
                cve = ref.get("id", "—")
                break
        results.append({
            "id":          r.get("id", ""),
            "name":        _text(r, "name") or "—",
            "host":        _text(r, "host") or _text(r, "host/ip") or "—",
            "port":        _text(r, "port") or "—",
            "severity":    sev,
            "sev_class":   severity_class(sev),
            "threat":      _text(r, "threat") or "Log",
            "description": _text(r, "description"),
            "solution":    _text(r, "solution") or _text(r, "nvt/solution"),
            "nvt_name":    _text(r, "nvt/name"),
            "cvss_base":   _text(r, "nvt/cvss_base") or "—",
            "cve":         cve,
            "qod":         r.findtext("qod/value") or "—",
        })
    results.sort(key=lambda x: x["severity"], reverse=True)
    return results
