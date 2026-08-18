from app.auth.permissions import require_perm
"""Vulnérabilités — lecture depuis SQLite, enrichi EUVD + scoring."""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required

vulns_bp = Blueprint("vulns", __name__, url_prefix="/vulns")
PER_PAGE = 50


def _norm_vendor(s: str) -> str:
    """Normalise un nom de vendor : Title Case (cohérent avec upsert_cve)."""
    s = (s or "").strip()
    return s.title() if s else "—"


def _norm_product(s: str) -> str:
    """Normalise un nom de product : tout en minuscules."""
    s = (s or "").strip()
    return s.lower() if s else "—"


def _extract_filter_options(results: list) -> dict:
    """Extrait les options de filtres pour la vue Synthèse.
    
    Retourne:
    - vendors: liste triée des vendors connus + "Non classifié" si applicable
    - vendor_products: dict {vendor: [products]} pour cascading JS
      Pour "Non classifié", les "products" sont les noms NVT distincts.
    """
    vendor_products: dict = {}

    for r in results:
        vendor = _norm_vendor(r.get("euvd_vendor") or "")
        product = _norm_product(r.get("euvd_product") or "")

        if vendor == "—":
            nvt_name = r.get("nvt_name") or r.get("name") or "—"
            vendor_products.setdefault("Non classifié", set()).add(nvt_name)
        else:
            vendor_products.setdefault(vendor, set()).add(product if product != "—" else "—")

    # Trier vendors : classifiés d'abord, "Non classifié" en dernier
    vendors_sorted = sorted(v for v in vendor_products if v != "Non classifié")
    if "Non classifié" in vendor_products:
        vendors_sorted.append("Non classifié")

    return {
        "vendors": vendors_sorted,
        "vendor_products": {v: sorted(ps) for v, ps in vendor_products.items()},
    }


def _group_by_vendor_product(results: list, anssi_data: dict) -> list:
    """Regroupe les vulnérabilités par vendor puis product (arborescence 2 niveaux)."""
    
    # Structure : {vendor: {product: [vulns]}}
    tree = {}
    ungrouped = []

    for v in results:
        vendor = _norm_vendor(v.get("euvd_vendor") or "")
        product = _norm_product(v.get("euvd_product") or "")

        if vendor == "—":
            ungrouped.append(v)
            continue

        if vendor not in tree:
            tree[vendor] = {}
        if product not in tree[vendor]:
            tree[vendor][product] = []
        tree[vendor][product].append(v)

    # Convertir en liste structurée
    groups = []
    for vendor, products in tree.items():
        vendor_group = {
            "vendor": vendor,
            "products": [],
            "total_vulns": 0,
            "max_severity": 0,
            "exploited_count": 0,
        }

        for product, vulns in products.items():
            # Collecter toutes les CVE uniques
            all_cves = set()
            for v in vulns:
                for c in v.get("all_cves", []):
                    all_cves.add(c)
                if v.get("cve") and v.get("cve") != "—":
                    all_cves.add(v.get("cve"))
            
            # Collecter tous les hôtes:ports uniques
            hosts_ports = set()
            for v in vulns:
                host = v.get("host", "")
                port = v.get("port", "")
                if host:
                    hosts_ports.add(f"{host}:{port}" if port else host)
            
            # Collecter les solutions uniques
            solutions = set()
            for v in vulns:
                sol = v.get("solution", "")
                if sol and sol.strip():
                    solutions.add(sol.strip())
            
            # Collecter les références ANSSI
            anssi_refs = []
            for cve in all_cves:
                entry = anssi_data.get(cve.upper())
                if entry:
                    ref_str = f"{entry.get('type', '').upper()}|{entry.get('ref', '')}|{entry.get('url', '')}"
                    if ref_str not in [r for r in anssi_refs]:
                        anssi_refs.append(ref_str)
            
            # Score max
            max_score = max((v.get("ctx_score", 0) for v in vulns), default=0)
            
            product_group = {
                "product": product,
                "vulns": vulns,
                "max_severity": max((v.get("severity", 0) for v in vulns), default=0),
                "max_score": max_score,
                "exploited_count": sum(1 for v in vulns if v.get("euvd_exploited")),
                "all_cves": sorted(all_cves),
                "hosts_ports": sorted(hosts_ports),
                "solutions": list(solutions),
                "anssi_refs": anssi_refs,
            }
            vendor_group["products"].append(product_group)
            vendor_group["total_vulns"] += len(vulns)
            vendor_group["max_severity"] = max(vendor_group["max_severity"], product_group["max_severity"])
            vendor_group["exploited_count"] += product_group["exploited_count"]

        # Trier products par sévérité max
        vendor_group["products"].sort(key=lambda p: p["max_severity"], reverse=True)
        groups.append(vendor_group)

    # Trier vendors par sévérité max
    groups.sort(key=lambda g: g["max_severity"], reverse=True)

    # Ajouter les vulns sans données EUVD — groupées par nom NVT (1 niveau)
    if ungrouped:
        nvt_tree: dict = {}
        for v in ungrouped:
            nvt_name = v.get("nvt_name") or v.get("name") or "—"
            nvt_tree.setdefault(nvt_name, []).append(v)

        nvt_products = []
        for nvt_name, vulns in nvt_tree.items():
            all_cves_n: set = set()
            hosts_ports_n: set = set()
            solutions_n: set = set()
            for v in vulns:
                for c in v.get("all_cves", []):
                    all_cves_n.add(c)
                if v.get("cve") and v.get("cve") != "—":
                    all_cves_n.add(v.get("cve"))
                host = v.get("host", "")
                port = v.get("port", "")
                if host:
                    hosts_ports_n.add(f"{host}:{port}" if port else host)
                sol = v.get("solution", "")
                if sol and sol.strip():
                    solutions_n.add(sol.strip())

            anssi_refs_n = []
            for cve in all_cves_n:
                entry = anssi_data.get(cve.upper())
                if entry:
                    ref_str = f"{entry.get('type', '').upper()}|{entry.get('ref', '')}|{entry.get('url', '')}"
                    if ref_str not in anssi_refs_n:
                        anssi_refs_n.append(ref_str)

            nvt_products.append({
                "product": nvt_name,
                "nvt_group": True,
                "vulns": vulns,
                "max_severity": max((v.get("severity", 0) for v in vulns), default=0),
                "max_score": max((v.get("ctx_score", 0) for v in vulns), default=0),
                "exploited_count": sum(1 for v in vulns if v.get("euvd_exploited")),
                "all_cves": sorted(all_cves_n),
                "hosts_ports": sorted(hosts_ports_n),
                "solutions": list(solutions_n),
                "anssi_refs": anssi_refs_n,
            })

        nvt_products.sort(key=lambda p: p["max_severity"], reverse=True)

        groups.append({
            "vendor": "Non classifié",
            "unclassified": True,
            "products": nvt_products,
            "total_vulns": len(ungrouped),
            "max_severity": max((v.get("severity", 0) for v in ungrouped), default=0),
            "exploited_count": sum(1 for v in ungrouped if v.get("euvd_exploited")),
        })

    return groups


def _group_by_ticket(results: list) -> list:
    """Regroupe les findings « en cours de traitement » par numéro de ticket.

    Retourne une liste de dicts {ticket, count, vulns, product_count, host_count,
    max_severity, max_score, exploited, treated_by, treated_at}, triée par
    nombre de vulnérabilités décroissant.
    """
    by_ticket: dict = {}
    for v in results:
        if not v.get("is_in_progress"):
            continue
        tk = (v.get("ticket_number") or "").strip()
        if not tk:
            continue
        g = by_ticket.get(tk)
        if g is None:
            g = by_ticket[tk] = {
                "ticket": tk, "vulns": [], "products": set(), "hosts": set(),
                "max_severity": 0.0, "max_score": 0, "exploited": 0,
                "treated_by": "", "treated_at": "",
            }
        g["vulns"].append(v)
        prod = (v.get("euvd_product") or "").strip()
        if prod and prod != "—":
            g["products"].add(((v.get("euvd_vendor") or "").strip(), prod))
        if v.get("host"):
            g["hosts"].add(v.get("host"))
        g["max_severity"] = max(g["max_severity"], v.get("severity") or 0)
        g["max_score"] = max(g["max_score"], v.get("ctx_score") or 0)
        if v.get("euvd_exploited"):
            g["exploited"] += 1
        if v.get("treatment_by") and not g["treated_by"]:
            g["treated_by"] = v.get("treatment_by")
        ta = v.get("treatment_at") or ""
        if ta and (not g["treated_at"] or ta < g["treated_at"]):
            g["treated_at"] = ta

    out = []
    for g in by_ticket.values():
        g["count"] = len(g["vulns"])
        g["product_count"] = len(g["products"])
        g["host_count"] = len(g["hosts"])
        out.append(g)
    out.sort(key=lambda t: (-t["count"], t["ticket"]))
    return out


@vulns_bp.route("/")
@login_required
@require_perm("vulns.read")
def index():
    from app.db import get_db, query_active_findings, query_active_findings_page, get_scan_imports

    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))
    sort_field = request.args.get("sort", "score")
    sort_order = request.args.get("order", "desc")
    search = request.args.get("q", "").strip()
    min_sev = request.args.get("min_sev", "")
    max_sev = request.args.get("max_sev", "")
    min_score = request.args.get("min_score", "")
    exploited_only = request.args.get("exploited", "") == "1"
    selected_tasks = request.args.getlist("task_ids")

    db = get_db()
    vulns_meta = get_scan_imports(db)

    # Liste complète (non filtrée) pour la Synthèse et les dropdowns de filtre
    results = query_active_findings(db, task_ids=selected_tasks if selected_tasks else None)
    anssi_data = {r["cve_id"]: {"type": r["cert_type"], "ref": r["ref"]}
                  for r in db.execute("SELECT cve_id, cert_type, ref FROM anssi_cves")}
    filter_options = _extract_filter_options(results)
    groups = _group_by_vendor_product(results, anssi_data)
    tickets = _group_by_ticket(results)
    from app.statuses import load_statuses, closed_status_ids
    status_defs = load_statuses()
    _closed = closed_status_ids()
    _cph = ",".join("?" * len(_closed)) if _closed else "''"
    resolved_count = db.execute(
        f"SELECT COUNT(*) FROM findings WHERE status IN ({_cph})", _closed
    ).fetchone()[0]

    def _safe_float(val, default=None):
        try:
            f = float(val)
            return default if (f != f or abs(f) == float("inf")) else f
        except (ValueError, TypeError):
            return default

    # Page filtrée/triée en SQL — aucun chargement complet en mémoire
    paged, total, exploited_count, with_euvd_count, avg_score = query_active_findings_page(
        db,
        task_ids=selected_tasks if selected_tasks else None,
        search=search,
        min_sev=_safe_float(min_sev),
        max_sev=_safe_float(max_sev),
        min_score=_safe_float(min_score),
        exploited_only=exploited_only,
        sort_field=sort_field,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )

    total_pages = max(1, (total + per_page - 1) // per_page)
    pagination = {
        "total": total, "page": page, "per_page": per_page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }

    from app.auth.roles import app_settings
    _settings = app_settings()
    remediation_warn = _settings.get("remediation_warn_days", 30)
    remediation_critical = _settings.get("remediation_critical_days", 90)

    return render_template(
        "vulns/index.html",
        vulns=paged, groups=groups, tickets=tickets, resolved_count=resolved_count,
        status_defs=status_defs, status_map={s["id"]: s for s in status_defs},
        pagination=pagination,
        sort_field=sort_field, sort_order=sort_order,
        search=search, min_sev=min_sev, max_sev=max_sev,
        min_score=min_score, per_page=per_page,
        exploited_only=exploited_only, exploited_count=exploited_count,
        with_euvd_count=with_euvd_count, avg_score=avg_score,
        filter_options=filter_options, vulns_meta=vulns_meta,
        selected_tasks=selected_tasks,
        remediation_warn=remediation_warn,
        remediation_critical=remediation_critical,
        ticket_url=_settings.get("ticket_url", ""),
    )


@vulns_bp.route("/export.csv")
@login_required
@require_perm("vulns.read")
def export_csv():
    """Export CSV de la synthèse — une ligne par finding, colonne Vendor incluse.
    Applique les mêmes filtres que la vue Synthèse (vendor, produit, score, recherche,
    hôte, scans sélectionnés) passés en query-string."""
    import csv, io
    from datetime import datetime as _dt
    from flask import Response
    from app.db import get_db, query_active_findings

    db = get_db()
    task_ids = request.args.getlist("task_ids")
    results = query_active_findings(db, task_ids=task_ids if task_ids else None)

    f_vendor  = request.args.get("vendor", "").strip()
    f_product = request.args.get("product", "").strip()
    f_search  = request.args.get("q", "").strip().lower()
    f_host    = request.args.get("host", "").strip()
    try:
        f_min_score = float(request.args.get("min_score") or 0)
    except (ValueError, TypeError):
        f_min_score = 0.0

    def _keep(v):
        vendor  = _norm_vendor(v.get("euvd_vendor") or "")
        product = _norm_product(v.get("euvd_product") or "")
        if f_vendor:
            want = "—" if f_vendor == "Non classifié" else f_vendor
            if vendor != want:
                return False
        if f_product and product != f_product:
            return False
        if (v.get("ctx_score") or 0) < f_min_score:
            return False
        if f_search and f_search not in vendor.lower() and f_search not in product.lower() \
                and f_search not in (v.get("name") or "").lower():
            return False
        if f_host and (v.get("host") or "").split(":")[0] != f_host:
            return False
        return True

    rows = [v for v in results if _keep(v)]
    # Classifiés d'abord (tri alpha), "Non classifié" (—) en dernier — comme la synthèse
    rows.sort(key=lambda v: (_norm_vendor(v.get("euvd_vendor") or "") == "—",
                             _norm_vendor(v.get("euvd_vendor") or ""),
                             _norm_product(v.get("euvd_product") or ""),
                             -(v.get("ctx_score") or 0)))

    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Vendor", "Produit", "CVE", "Vulnérabilité", "Sévérité", "Score",
                "EPSS %", "Exploité", "ANSSI", "Nom d'hôte", "IP", "Port", "Détecté le", "Tâche(s)"])
    for v in rows:
        epss = v.get("euvd_epss")
        w.writerow([
            _norm_vendor(v.get("euvd_vendor") or ""),
            _norm_product(v.get("euvd_product") or ""),
            v.get("cve", ""),
            (v.get("name") or "").replace("\n", " ").replace(";", ",").strip(),
            f"{v.get('severity', 0):.1f}",
            f"{v.get('ctx_score', 0):.0f}",
            f"{epss * 100:.1f}" if epss is not None else "",
            "Oui" if v.get("euvd_exploited") else "Non",
            v.get("anssi_level", "none"),
            v.get("hostname", ""),
            v.get("host", ""),
            v.get("port", ""),
            (v.get("first_seen") or "")[:10],
            (v.get("task_name") or "").replace(";", ","),
        ])
    data = "﻿" + buf.getvalue()  # BOM UTF-8 → accents corrects dans Excel
    fname = f"vulnerabilites_{_dt.now():%Y%m%d}.csv"
    return Response(data, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@vulns_bp.route("/api/version-tooltip")
@login_required
@require_perm("vulns.read")
def api_version_tooltip():
    """Endpoint AJAX léger — versions affectées (EUVD) + version déclarée/détectée."""
    from app.db import get_db
    db = get_db()
    try:
        finding_id = int(request.args.get("id", 0))
    except (ValueError, TypeError):
        return jsonify({"ok": False}), 400

    row = db.execute(
        """SELECT f.host_ip, f.vendor, f.product, v.family,
                  GROUP_CONCAT(DISTINCT vc.cve_id) as all_cves
           FROM findings f
           JOIN vulnerabilities v ON f.vuln_id = v.id
           LEFT JOIN vuln_cves vc ON v.id = vc.vuln_id
           WHERE f.id = ?
           GROUP BY f.id""",
        (finding_id,),
    ).fetchone()
    if not row:
        return jsonify({"ok": False}), 404

    cves = row["all_cves"].split(",") if row["all_cves"] else []

    # Ranges de versions affectées par CVE (table cves, remplie par refresh EUVD)
    affected = {}
    for cve in cves:
        r = db.execute(
            "SELECT product_version FROM cves WHERE cve_id=?", (cve,)
        ).fetchone()
        if r and r["product_version"]:
            affected[cve] = r["product_version"]

    # Version déclarée (CPE Watch) ou None (GVM — pas stockée par finding)
    detected = None
    if row["family"] == "CPE Watch":
        ms = db.execute(
            """SELECT version FROM monitored_software
               WHERE vendor=? AND product=?
                 AND COALESCE(host_ip,'monitored')=?
               LIMIT 1""",
            (row["vendor"], row["product"], row["host_ip"] or "monitored"),
        ).fetchone()
        if ms:
            detected = ms["version"]

    return jsonify({
        "ok": True,
        "source": "cpe_watch" if row["family"] == "CPE Watch" else "gvm",
        "affected": affected,
        "detected": detected,
    })


@vulns_bp.route("/api/resolved")
@login_required
@require_perm("vulns.read")
def api_resolved():
    """Endpoint AJAX — retourne les findings résolus en JSON."""
    from app.db import get_db, query_resolved_findings
    db = get_db()
    resolved = query_resolved_findings(db)
    from app.auth.roles import app_settings
    _settings = app_settings()
    return jsonify({
        "resolved": resolved,
        "remediation_warn": _settings.get("remediation_warn_days", 30),
        "remediation_critical": _settings.get("remediation_critical_days", 90),
    })


@vulns_bp.route("/detail/<vuln_id>")
@login_required
@require_perm("vulns.detail")
def detail_json(vuln_id):
    """Endpoint AJAX — finding detail depuis SQLite."""
    from app.db import get_db, get_finding_detail

    db = get_db()
    try:
        finding_id = int(vuln_id)
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "ID invalide"}), 400

    vuln = get_finding_detail(db, finding_id)
    if vuln is None:
        return jsonify({"ok": False, "error": "Résultat introuvable"}), 404

    return jsonify({"ok": True, "vuln": vuln})


@vulns_bp.route("/<int:finding_id>/mark-fp", methods=["POST"])
@login_required
@require_perm("vulns.mark_fp")
def mark_false_positive(finding_id):
    """Déclare un finding comme faux positif (masqué des vues actives)."""
    from flask_login import current_user
    from app.db import get_db, mark_finding_false_positive

    reason = (request.form.get("reason") or "").strip() or None
    by = getattr(current_user, "username", None) or "?"

    db = get_db()
    ok = mark_finding_false_positive(db, finding_id, by, reason)
    if not ok:
        return jsonify({"ok": False, "error": "Résultat introuvable ou déjà marqué"}), 404
    return jsonify({"ok": True})


@vulns_bp.route("/<int:finding_id>/unmark-fp", methods=["POST"])
@login_required
@require_perm("vulns.mark_fp")
def unmark_false_positive(finding_id):
    """Annule le marquage faux positif : le finding redevient actif."""
    from app.db import get_db, unmark_finding_false_positive

    db = get_db()
    ok = unmark_finding_false_positive(db, finding_id)
    if not ok:
        return jsonify({"ok": False, "error": "Résultat introuvable ou non marqué"}), 404
    return jsonify({"ok": True})


@vulns_bp.route("/treat", methods=["POST"])
@login_required
@require_perm("vulns.mark_fp")
def treat_findings():
    """Applique un statut (config dynamique) à un ou plusieurs findings.

    Form : finding_ids (répété), status (id de statut), et les champs custom du
    statut sous la forme field_<clé> (les obligatoires sont validés).
    """
    from flask_login import current_user
    from app.db import get_db, set_findings_status
    from app.statuses import get_status

    ids = request.form.getlist("finding_ids")
    status = (request.form.get("status") or "").strip()
    by = getattr(current_user, "username", None) or "?"

    sdef = get_status(status)
    if not sdef:
        return jsonify({"ok": False, "error": "Statut invalide"}), 400
    if not ids:
        return jsonify({"ok": False, "error": "Aucun finding sélectionné"}), 400

    # Collecte + validation des champs custom du statut
    data = {}
    for f in sdef.get("fields", []):
        val = (request.form.get("field_" + f["key"]) or "").strip()
        if f.get("required") and not val:
            return jsonify({"ok": False, "error": f"Champ « {f['label']} » obligatoire"}), 400
        if val:
            data[f["key"]] = val

    db = get_db()
    n = set_findings_status(db, ids, status, data=data, by=by)
    return jsonify({"ok": True, "updated": n})


@vulns_bp.route("/debug-scoring")
@login_required
@require_perm("vulns.debug")
def debug_scoring():
    """Endpoint de debug pour le scoring."""
    from app.scoring import load_scoring_config
    from app.db import get_db

    db = get_db()
    config = load_scoring_config()
    kev_count = db.execute("SELECT COUNT(*) FROM cves WHERE is_kev=1").fetchone()[0]
    anssi_count = db.execute("SELECT COUNT(DISTINCT cve_id) FROM anssi_cves").fetchone()[0]
    tags_count = db.execute("SELECT COUNT(DISTINCT host_ip) FROM host_tags").fetchone()[0]

    sample = db.execute("""
        SELECT f.host_ip, f.severity, v.name,
               GROUP_CONCAT(DISTINCT vc.cve_id) as cves
        FROM findings f
        JOIN vulnerabilities v ON f.vuln_id=v.id
        LEFT JOIN vuln_cves vc ON v.id=vc.vuln_id
        WHERE f.status='active'
        GROUP BY f.id LIMIT 5
    """).fetchall()

    return jsonify({
        "config_loaded": bool(config.get("scoring", {}).get("criteria")),
        "criteria_count": len(config.get("scoring", {}).get("criteria", [])),
        "formula": config.get("scoring", {}).get("formula", ""),
        "kev_count": kev_count,
        "anssi_count": anssi_count,
        "hosts_with_tags": tags_count,
        "sample_vulns": [{"name": r["name"][:50], "host": r["host_ip"],
                          "severity": r["severity"],
                          "cves": r["cves"].split(",") if r["cves"] else []}
                         for r in sample],
    })
