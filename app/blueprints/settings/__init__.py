"""
Settings blueprint — Configuration du scoring.
"""
import json
import copy
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.auth.permissions import require_perm

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


def _load_config() -> dict:
    from app.scoring import load_scoring_config
    return load_scoring_config()


def _save_config(cfg: dict) -> bool:
    from app.scoring import save_scoring_config
    ok, _ = save_scoring_config(cfg)
    return ok


def _auto_formula(criteria: list) -> tuple[str, int]:
    """Génère la formule et le total_weight depuis la liste des critères."""
    parts = []
    total = 0
    for c in criteria:
        cid = c.get("id", "")
        w = int(c.get("weight", 1))
        if cid:
            parts.append(f"({{{cid}}} * {w})")
            total += w
    if not parts or total == 0:
        return "", 0
    formula = "(" + " + ".join(parts) + f") / {total} * 100"
    return formula, total


def _validate_formula(formula: str, criteria: list) -> tuple[bool, str]:
    """Valide syntaxiquement la formule avec des valeurs fictives (0.5)."""
    from app.scoring import _safe_eval
    # Substituer les variables par 0.5
    test = formula
    for c in criteria:
        cid = c.get("id", "")
        if cid:
            test = test.replace(f"{{{cid}}}", "0.5")
    if len(test) > 1000:
        return False, "Formule trop longue"
    remaining = []
    i = 0
    while i < len(test):
        if test[i] == '{':
            j = test.find('}', i + 1)
            if j > i:
                remaining.append(test[i:j+1])
                i = j + 1
            else:
                i += 1
        else:
            i += 1
    if remaining:
        return False, f"Variables inconnues dans la formule : {remaining}"
    try:
        result = _safe_eval(test)
        if result != result:  # NaN
            return False, "La formule produit NaN"
        return True, f"OK (résultat test : {result:.2f})"
    except Exception:
        return False, "Formule invalide (erreur de syntaxe)"


@settings_bp.route("/general", methods=["GET", "POST"])
@login_required
@require_perm("settings.general_read")
def general():
    """Page des paramètres généraux."""
    from app.auth.roles import app_settings, save_app_settings, _SCHEDULE_DEFAULTS

    settings = app_settings()

    if request.method == "POST":
        if not current_user.has_perm("settings.general_edit"):
            flash("Permission refusée.", "danger")
            return redirect(url_for("settings.general"))

        settings["deny_if_no_role"] = request.form.get("deny_if_no_role") == "on"
        try:
            settings["remediation_warn_days"] = int(request.form.get("remediation_warn_days", 30))
        except (ValueError, TypeError):
            settings["remediation_warn_days"] = 30
        try:
            settings["remediation_critical_days"] = int(request.form.get("remediation_critical_days", 90))
        except (ValueError, TypeError):
            settings["remediation_critical_days"] = 90

        settings["scheduler_enabled"] = request.form.get("scheduler_enabled") == "on"
        settings["ticket_url"] = (request.form.get("ticket_url", "") or "").strip()

        schedules = settings.get("schedules", {})
        for key in _SCHEDULE_DEFAULTS:
            val = request.form.get(f"sched_{key}", "")
            try:
                schedules[key] = {"interval_hours": max(0, int(val))}
            except (ValueError, TypeError):
                pass
            if _SCHEDULE_DEFAULTS[key].get("after_vulns"):
                schedules[key]["after_vulns"] = True
        settings["schedules"] = schedules

        if save_app_settings(settings):
            from app.scheduler import apply_schedules
            from flask import current_app
            apply_schedules(current_app._get_current_object())
            flash("Paramètres sauvegardés.", "success")
        else:
            flash("Erreur de sauvegarde.", "danger")
        return redirect(url_for("settings.general"))

    return render_template("settings/general.html", settings=settings,
                           schedule_defs=_SCHEDULE_DEFAULTS)


# ══════════════════════════════════════════════════════════════════════════════
# Surveillance logicielle (CPE watch)
# ══════════════════════════════════════════════════════════════════════════════

CPE_TYPES = {"a": "Applications", "o": "Systèmes d'exploitation", "h": "Matériels"}


@settings_bp.route("/cpe/vendors")
@login_required
@require_perm("settings.general_read")
def cpe_vendors():
    """Retourne les vendors depuis le dictionnaire CPE local."""
    from app.db import get_db
    q = request.args.get("q", "").strip()
    cpe_type = request.args.get("type", "")
    if not q or len(q) < 2:
        return jsonify([])
    db = get_db()
    safe_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    params = [f"%{safe_q}%"]
    sql = "SELECT DISTINCT vendor FROM cpe_dictionary WHERE vendor LIKE ? ESCAPE '\\'"
    if cpe_type:
        sql += " AND cpe_type=?"
        params.append(cpe_type)
    sql += " ORDER BY vendor LIMIT 50"
    rows = db.execute(sql, params).fetchall()
    return jsonify([r[0] for r in rows])


@settings_bp.route("/cpe/products")
@login_required
@require_perm("settings.general_read")
def cpe_products():
    """Retourne les produits pour un vendor donné."""
    from app.db import get_db
    vendor = request.args.get("vendor", "").strip()
    cpe_type = request.args.get("type", "")
    if not vendor:
        return jsonify([])
    db = get_db()
    params = [vendor]
    sql = "SELECT DISTINCT product FROM cpe_dictionary WHERE vendor=?"
    if cpe_type:
        sql += " AND cpe_type=?"
        params.append(cpe_type)
    sql += " ORDER BY product"
    rows = db.execute(sql, params).fetchall()
    return jsonify([r[0] for r in rows])


@settings_bp.route("/cpe/versions")
@login_required
@require_perm("settings.general_read")
def cpe_versions():
    """Retourne les versions pour un vendor/product donné."""
    from app.db import get_db
    vendor = request.args.get("vendor", "").strip()
    product = request.args.get("product", "").strip()
    if not vendor or not product:
        return jsonify([])
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT version FROM cpe_dictionary WHERE vendor=? AND product=? AND version!='' ORDER BY version DESC",
        (vendor, product),
    ).fetchall()
    return jsonify([r[0] for r in rows])


@settings_bp.route("/software")
@login_required
@require_perm("settings.general_read")
def software():
    """Page de gestion des logiciels surveillés."""
    from app.db import get_db
    db = get_db()
    rows = db.execute("SELECT * FROM monitored_software ORDER BY vendor, product").fetchall()
    items = [dict(r) for r in rows]
    return render_template("settings/software.html", items=items, cpe_types=CPE_TYPES)


@settings_bp.route("/software/<int:item_id>/check", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def software_check(item_id):
    """Lance la surveillance CPE Watch d'un seul logiciel surveillé."""
    from app.db import get_db
    from app.tasks import start_background_task, is_task_running

    back = request.referrer or url_for("settings.software")
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    row = get_db().execute(
        "SELECT vendor, product FROM monitored_software WHERE id=?", (item_id,)
    ).fetchone()
    if row is None:
        if is_ajax:
            return jsonify({"success": False, "error": "Logiciel introuvable"}), 404
        flash("Logiciel introuvable.", "danger")
        return redirect(back)

    if is_task_running("cpe_watch"):
        if is_ajax:
            return jsonify({"success": False, "error": "Une vérification CPE est déjà en cours"})
        flash("Une vérification CPE est déjà en cours — réessayez à la fin.", "warning")
        return redirect(back)

    from app.blueprints.cache import _task_cpe_watch_one
    start_background_task("cpe_watch", _task_cpe_watch_one, item_id)
    label = f"{row['vendor']}/{row['product']}"
    if is_ajax:
        return jsonify({"success": True, "task_type": "cpe_watch",
                        "message": f"Surveillance de « {label} » lancée"})
    flash(f"Surveillance de « {label} » lancée.", "info")
    return redirect(back)


@settings_bp.route("/software/add", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def software_add():
    """Ajoute un logiciel à surveiller."""
    import sqlite3 as _sqlite3
    from app.db import get_db
    from datetime import datetime as _dt

    db = get_db()
    cpe_type = request.form.get("cpe_type", "a")
    vendor = request.form.get("vendor", "").strip()
    product = request.form.get("product", "").strip()
    version = request.form.get("version", "").strip() or None
    # Rejeter le sentinel JS côté serveur (protection si JS désactivé)
    if version == "__other__":
        version = None
    host_ip = request.form.get("host_ip", "").strip() or None
    comment = request.form.get("comment", "").strip() or None

    if not vendor or not product:
        flash("Vendor et produit requis.", "danger")
        return redirect(url_for("settings.software"))

    try:
        cursor = db.execute(
            "INSERT INTO monitored_software(cpe_type,vendor,product,version,host_ip,comment,created_at) VALUES(?,?,?,?,?,?,?)",
            (cpe_type, vendor, product, version, host_ip, comment, _dt.now().isoformat()),
        )
        new_id = cursor.lastrowid
        db.commit()
    except _sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            flash("Base de données temporairement verrouillée (synchronisation en cours). Réessayez dans quelques secondes.", "warning")
        else:
            logger.exception(f"Erreur lors de l'ajout du logiciel: {e}")
            flash("Erreur inattendue lors de l'ajout du logiciel.", "danger")
        return redirect(url_for("settings.software"))

    flash(f"Logiciel « {vendor}/{product} » ajouté à la surveillance.", "success")

    from app.tasks import start_background_task, is_task_running
    if not is_task_running("cpe_watch"):
        from app.blueprints.cache import _task_cpe_watch_one
        start_background_task("cpe_watch", _task_cpe_watch_one, new_id)
    else:
        flash("Une vérification CPE est en cours — la re-vérification sera effectuée lors du prochain cycle.", "info")

    return redirect(url_for("settings.software"))


@settings_bp.route("/software/edit/<int:item_id>", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def software_edit(item_id):
    """Met à jour un logiciel surveillé (version, hôte, commentaire)."""
    from app.db import get_db
    db = get_db()
    row = db.execute("SELECT * FROM monitored_software WHERE id=?", (item_id,)).fetchone()
    if not row:
        flash("Logiciel introuvable.", "danger")
        return redirect(url_for("settings.software"))

    import sqlite3 as _sqlite3
    version = request.form.get("version", "").strip() or None
    # Rejeter le sentinel JS côté serveur (protection si JS désactivé)
    if version == "__other__":
        version = None
    host_ip = request.form.get("host_ip", "").strip() or None
    comment = request.form.get("comment", "").strip() or None

    try:
        db.execute(
            "UPDATE monitored_software SET version=?, host_ip=?, comment=? WHERE id=?",
            (version, host_ip, comment, item_id),
        )
        db.commit()
    except _sqlite3.OperationalError as e:
        if "database is locked" in str(e):
            flash(
                "Base de données temporairement verrouillée (synchronisation en cours). "
                "Réessayez dans quelques secondes.",
                "warning",
            )
        else:
            logger.exception(f"Erreur lors de la mise à jour du logiciel {item_id}: {e}")
            flash("Erreur inattendue lors de la mise à jour.", "danger")
        return redirect(url_for("settings.software"))

    flash(f"Logiciel « {row['vendor']}/{row['product']} » mis à jour.", "success")

    from app.tasks import start_background_task, is_task_running
    if not is_task_running("cpe_watch"):
        from app.blueprints.cache import _task_cpe_watch_one
        start_background_task("cpe_watch", _task_cpe_watch_one, item_id)
    else:
        flash("Une vérification CPE est en cours — la re-vérification sera effectuée lors du prochain cycle.", "info")

    return redirect(url_for("settings.software"))


@settings_bp.route("/software/delete/<int:item_id>", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def software_delete(item_id):
    """Supprime un logiciel surveillé et résout ses findings CPE Watch."""
    from app.db import get_db
    from datetime import datetime as _dt
    db = get_db()
    row = db.execute("SELECT vendor, product, host_ip FROM monitored_software WHERE id=?", (item_id,)).fetchone()
    db.execute("DELETE FROM monitored_software WHERE id=?", (item_id,))
    if row:
        now = _dt.now().isoformat()
        # host_ip est stocké tel quel dans findings, avec fallback 'monitored' (cf. check_monitored_software)
        host_key = row["host_ip"] or "monitored"
        # Ne résoudre les findings de CE host que si plus aucune entrée ne surveille
        # ce (vendor, product, host) — un autre hôte ou une autre version peut le couvrir.
        still_monitored = db.execute(
            """SELECT 1 FROM monitored_software
               WHERE vendor=? AND product=? AND COALESCE(host_ip,'monitored')=? LIMIT 1""",
            (row["vendor"], row["product"], host_key),
        ).fetchone()
        if not still_monitored:
            safe_v = row["vendor"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            safe_p = row["product"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            resolved = db.execute(
                """UPDATE findings SET status='resolved', resolved_at=?
                   WHERE status='active' AND host_ip=?
                   AND vuln_id IN (
                       SELECT id FROM vulnerabilities
                       WHERE oid LIKE ? ESCAPE '\\'
                   )""",
                (now, host_key, f"cpe-watch:%:{safe_v}:{safe_p}"),
            ).rowcount
            if resolved:
                logging.getLogger(__name__).info(
                    f"[CPE WATCH] Suppression {row['vendor']}/{row['product']}@{host_key} — {resolved} finding(s) résolu(s)"
                )
    db.commit()
    flash("Logiciel retiré de la surveillance.", "success")
    return redirect(url_for("settings.software"))


@settings_bp.route("/scoring")
@login_required
@require_perm("settings.scoring_read")
def scoring():
    """Page de configuration du scoring."""
    cfg = _load_config()
    scoring_cfg = cfg.get("scoring", {})
    criteria = scoring_cfg.get("criteria", [])
    formula = scoring_cfg.get("formula", "")
    total_weight = scoring_cfg.get("total_weight", 0)

    # Prévisualisation sur 5 vulns
    preview_vulns = _get_preview_vulns()

    return render_template(
        "settings/scoring.html",
        criteria=criteria,
        formula=formula,
        total_weight=total_weight,
        scoring_name=scoring_cfg.get("name", "Score contextualisé"),
        preview_vulns=preview_vulns,
        sources=["severity", "epss", "qod", "kev", "anssi", "host_tag"],
    )


@settings_bp.route("/scoring/save", methods=["POST"])
@login_required
@require_perm("settings.scoring_edit")
def scoring_save():
    """Sauvegarde la configuration du scoring."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "Données JSON manquantes"}), 400

        criteria = data.get("criteria", [])
        formula = data.get("formula", "").strip()
        name = data.get("name", "Score contextualisé").strip()

        # Validation de la formule
        valid, msg = _validate_formula(formula, criteria)
        if not valid:
            return jsonify({"ok": False, "error": f"Formule invalide : {msg}"}), 400

        # Calcul du total_weight
        total_weight = sum(int(c.get("weight", 1)) for c in criteria if c.get("id"))

        cfg = _load_config()
        cfg["scoring"] = {
            "name": name,
            "description": cfg.get("scoring", {}).get("description", ""),
            "criteria": criteria,
            "formula": formula,
            "total_weight": total_weight,
        }

        if _save_config(cfg):
            return jsonify({"ok": True, "message": "Configuration sauvegardée"})
        return jsonify({"ok": False, "error": "Erreur d'écriture fichier"}), 500

    except Exception as e:
        logging.getLogger(__name__).error(f"Erreur: {e}")
        return jsonify({"ok": False, "error": "Erreur interne"}), 500


@settings_bp.route("/scoring/preview", methods=["POST"])
@login_required
@require_perm("settings.scoring_read")
def scoring_preview():
    """Calcule les scores en live avec la config envoyée (sans sauvegarder)."""
    try:
        data = request.get_json()
        criteria = data.get("criteria", [])
        formula = data.get("formula", "")

        preview_vulns = _get_preview_vulns()
        if not preview_vulns:
            return jsonify({"ok": True, "results": []})

        # Calcul avec la config temporaire
        from app.scoring import _get_criterion_value, _safe_eval
        from app.db import get_db
        import json as _json

        db = get_db()
        kev_data = {r["cve_id"]: {"dateAdded": r["kev_date_added"]}
                    for r in db.execute("SELECT cve_id, kev_date_added FROM cves WHERE is_kev=1")}
        anssi_data = {r["cve_id"]: {"type": r["cert_type"], "ref": r["ref"]}
                      for r in db.execute("SELECT cve_id, cert_type, ref FROM anssi_cves")}
        host_tags_map = {}
        for r in db.execute("SELECT host_ip, GROUP_CONCAT(tag_name) as t FROM host_tags GROUP BY host_ip"):
            host_tags_map[r["host_ip"]] = r["t"].split(",") if r["t"] else []

        results = []
        for v in preview_vulns:
            host_tags = host_tags_map.get(v.get("host", ""), [])
            details = {}
            for c in criteria:
                cid = c.get("id", "")
                if cid:
                    val = _get_criterion_value(c, v, host_tags, kev_data, anssi_data)
                    details[cid] = round(val, 4)

            # Évaluer la formule
            try:
                test = formula
                for cid, val in details.items():
                    test = test.replace(f"{{{cid}}}", str(val))
                score = round(min(100, max(0, _safe_eval(test))), 1)
            except Exception:
                score = 0

            results.append({
                "name": v.get("name", "—")[:60],
                "host": v.get("host", "—"),
                "severity": v.get("severity", 0),
                "cve": v.get("cve", "—"),
                "score": score,
                "details": details,
            })

        return jsonify({"ok": True, "results": results})

    except Exception as e:
        logging.getLogger(__name__).error(f"Erreur: {e}")
        return jsonify({"ok": False, "error": "Erreur interne"}), 500


@settings_bp.route("/scoring/validate-formula", methods=["POST"])
@login_required
@require_perm("settings.scoring_read")
def scoring_validate_formula():
    """Valide syntaxiquement une formule."""
    data = request.get_json()
    formula = data.get("formula", "")
    criteria = data.get("criteria", [])
    valid, msg = _validate_formula(formula, criteria)
    return jsonify({"ok": valid, "message": msg})


@settings_bp.route("/scoring/auto-formula", methods=["POST"])
@login_required
@require_perm("settings.scoring_read")
def scoring_auto_formula():
    """Génère automatiquement la formule depuis les critères."""
    data = request.get_json()
    criteria = data.get("criteria", [])
    formula, total = _auto_formula(criteria)
    return jsonify({"ok": True, "formula": formula, "total_weight": total})


def _get_preview_vulns(n: int = 5) -> list:
    """Récupère n vulns variées depuis SQLite pour la prévisualisation."""
    try:
        from app.db import get_db, _row_to_vuln, _FINDING_SELECT
        db = get_db()
        rows = db.execute(
            _FINDING_SELECT +
            " WHERE f.status='active' GROUP BY f.id ORDER BY f.severity DESC LIMIT ?",
            (n * 4,),
        ).fetchall()
        if not rows:
            return []
        results = [_row_to_vuln(r) for r in rows]
        by_sev = {"critical": [], "high": [], "medium": [], "other": []}
        for r in results:
            sev = r.get("severity", 0)
            if sev >= 9.0: by_sev["critical"].append(r)
            elif sev >= 7.0: by_sev["high"].append(r)
            elif sev >= 4.0: by_sev["medium"].append(r)
            else: by_sev["other"].append(r)
        sample = []
        for key in ["critical", "high", "medium", "other"]:
            if by_sev[key] and len(sample) < n:
                sample.append(by_sev[key][0])
        return sample[:n]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Statuts dynamiques de findings (libellé, icône, couleur, comportement, champs)
# ══════════════════════════════════════════════════════════════════════════════
STATUS_COLORS = ["secondary", "blue", "azure", "cyan", "teal", "green",
                 "lime", "yellow", "orange", "red", "pink", "purple", "indigo"]


@settings_bp.route("/statuses")
@login_required
@require_perm("settings.general_read")
def statuses_index():
    from app.statuses import load_statuses
    return render_template("settings/statuses.html", statuses=load_statuses())


@settings_bp.route("/statuses/reorder", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def statuses_reorder():
    """Réordonne les statuts (AJAX). Les ancres sont re-épinglées par save_statuses."""
    from app.statuses import load_statuses, save_statuses
    data = request.get_json(silent=True) or {}
    order = data.get("order")
    if not isinstance(order, list):
        return jsonify(ok=False, error="Ordre invalide"), 400
    statuses = load_statuses()
    by_id = {s["id"]: s for s in statuses}
    ordered, used = [], set()
    for sid in order:
        if sid in by_id and sid not in used:
            ordered.append(by_id[sid])
            used.add(sid)
    # Sécurité : réinsère tout statut absent de la soumission dans son ordre actuel
    for s in statuses:
        if s["id"] not in used:
            ordered.append(s)
    if save_statuses(ordered):
        return jsonify(ok=True)
    return jsonify(ok=False, error="Sauvegarde impossible"), 500


def _parse_status_form(form, existing=None):
    from app.statuses import slug
    label = (form.get("label") or "").strip()
    sid = existing["id"] if existing else slug(form.get("id") or label)
    st = {
        "id": sid,
        "label": label or (existing.get("label") if existing else sid),
        "icon": (form.get("icon") or "ti-circle").strip(),
        "color": (form.get("color") or "secondary").strip(),
        "scope": form.get("scope") if form.get("scope") in ("open", "closed") else "open",
        "sticky": form.get("sticky") == "on",
        "auto_resolve": form.get("auto_resolve") == "on",
        "fields": [],
    }
    try:
        fields = json.loads(form.get("fields_json") or "[]")
        if isinstance(fields, list):
            st["fields"] = fields
    except Exception:
        pass
    # Statut verrouillé : on garde ses 3 flags (save_statuses les re-verrouille de toute façon)
    if existing and existing.get("fixed"):
        for k in ("scope", "sticky", "auto_resolve"):
            st[k] = existing[k]
    return st


@settings_bp.route("/statuses/new", methods=["GET", "POST"])
@login_required
@require_perm("settings.general_edit")
def statuses_create():
    from app.statuses import load_statuses, save_statuses
    if request.method == "POST":
        st = _parse_status_form(request.form)
        if not st["id"]:
            flash("Un libellé (ou identifiant) est requis.", "danger")
            return redirect(url_for("settings.statuses_create"))
        alls = load_statuses()
        if any(s["id"] == st["id"] for s in alls):
            flash(f"Un statut « {st['id']} » existe déjà.", "danger")
            return redirect(url_for("settings.statuses_create"))
        alls.append(st)
        save_statuses(alls)
        flash(f"Statut « {st['label']} » créé.", "success")
        return redirect(url_for("settings.statuses_index"))
    return render_template("settings/status_edit.html", status=None, colors=STATUS_COLORS)


@settings_bp.route("/statuses/<status_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("settings.general_edit")
def statuses_edit(status_id):
    from app.statuses import load_statuses, save_statuses, get_status
    st = get_status(status_id)
    if not st:
        flash("Statut introuvable.", "danger")
        return redirect(url_for("settings.statuses_index"))
    if request.method == "POST":
        updated = _parse_status_form(request.form, existing=st)
        alls = [updated if s["id"] == st["id"] else s for s in load_statuses()]
        save_statuses(alls)
        flash(f"Statut « {updated['label']} » mis à jour.", "success")
        return redirect(url_for("settings.statuses_index"))
    return render_template("settings/status_edit.html", status=st, colors=STATUS_COLORS)


@settings_bp.route("/statuses/<status_id>/delete", methods=["POST"])
@login_required
@require_perm("settings.general_edit")
def statuses_delete(status_id):
    from app.statuses import load_statuses, save_statuses, get_status
    st = get_status(status_id)
    if not st:
        flash("Statut introuvable.", "danger")
    elif st.get("fixed"):
        flash("Ce statut est verrouillé et ne peut pas être supprimé.", "danger")
    else:
        # Les findings portant ce statut repassent en 'active' (statut de base)
        from app.db import get_db
        db = get_db()
        db.execute(
            "UPDATE findings SET status='active', resolved_at=NULL, "
            "status_data=NULL, status_by=NULL, status_at=NULL WHERE status=?",
            (status_id,),
        )
        db.commit()
        save_statuses([s for s in load_statuses() if s["id"] != status_id])
        flash(f"Statut « {st['label']} » supprimé — vulnérabilités concernées repassées en actif.", "info")
    return redirect(url_for("settings.statuses_index"))
