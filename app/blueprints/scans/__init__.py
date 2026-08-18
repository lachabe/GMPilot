from app.auth.permissions import require_perm
"""Scans (Tasks) blueprint — reads from SQLite, actions go direct to GMP."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user

logger = logging.getLogger(__name__)

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")
PER_PAGE = 50


@scans_bp.route("/")
@login_required
@require_perm("scans.read")
def index():
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))

    from app.db import get_db, read_gmp_cache
    tasks = read_gmp_cache(get_db(), "tasks")

    total = len(tasks)
    start = (page - 1) * per_page
    paged = tasks[start:start + per_page]

    return render_template("scans/index.html", tasks=paged,
                           page=page, per_page=per_page, total=total)


@scans_bp.route("/create", methods=["GET", "POST"])
@login_required
@require_perm("scans.create")
def create():
    from app.db import get_db, read_gmp_cache
    db = get_db()
    targets = read_gmp_cache(db, "targets")
    configs = read_gmp_cache(db, "scan_configs")

    if request.method == "POST":
        try:
            with gmp_session_for_user(current_user) as gmp:
                name = request.form["name"]
                target_id = request.form["target_id"]
                config_id = request.form["config_id"]
                comment = request.form.get("comment", "")
                scanner_id = request.form.get("scanner_id", "")

                if not scanner_id:
                    scanners = read_gmp_cache(db, "scanners")
                    for s in scanners:
                        if "OpenVAS" in s.get("name", "") or "Default" in s.get("name", ""):
                            scanner_id = s.get("id", "")
                            break
                    if not scanner_id:
                        xml_s2 = gmp.get_scanners()
                        first = xml_s2.find("scanner")
                        if first is not None:
                            scanner_id = first.get("id", "")

                gmp.create_task(name=name, config_id=config_id,
                                target_id=target_id, scanner_id=scanner_id,
                                comment=comment)
                flash(f"Tâche « {name} » créée.", "success")
                return redirect(url_for("scans.index"))
        except Exception as e:
            flash(f"Erreur : {e}", "danger")

    return render_template("scans/create.html", targets=targets, configs=configs)


@scans_bp.route("/<task_id>/start", methods=["POST"])
@login_required
@require_perm("scans.start")
def start(task_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.start_task(task_id)
            flash("Scan démarré.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("scans.index"))


@scans_bp.route("/<task_id>/stop", methods=["POST"])
@login_required
@require_perm("scans.stop")
def stop(task_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.stop_task(task_id)
            flash("Scan arrêté.", "warning")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("scans.index"))


@scans_bp.route("/<task_id>/resume", methods=["POST"])
@login_required
@require_perm("scans.resume")
def resume(task_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.resume_task(task_id)
            flash("Scan repris.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("scans.index"))


@scans_bp.route("/<task_id>/delete", methods=["POST"])
@login_required
@require_perm("scans.delete")
def delete(task_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.delete_task(task_id, ultimate=False)
            flash("Tâche supprimée.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("scans.index"))


@scans_bp.route("/<task_id>/status")
@login_required
@require_perm("scans.read")
def status(task_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp.get_task(task_id)
            task = xml.find("task")
            if task is None:
                return jsonify({"error": "not found"}), 404
            from app.gvm_client import _safe_float
            lr = task.find("last_report/report")
            return jsonify({
                "status":         task.findtext("status") or "Unknown",
                "progress":       task.findtext("progress") or "0",
                "severity":       _safe_float(task.findtext("last_report/report/severity")),
                "last_report_id": lr.get("id", "") if lr is not None else "",
            })
    except Exception as e:
        logger.error(f"Erreur: {e}")
        return jsonify({"error": "Erreur interne"}), 500


@scans_bp.route("/status-all")
@login_required
@require_perm("scans.read")
def status_all():
    """Retourne les statuts de toutes les tâches en un seul appel GMP."""
    try:
        with gmp_session_for_user(current_user) as gmp:
            from app.gvm_client import parse_tasks
            xml = gmp.get_tasks(filter_string="rows=-1 details=1")
            tasks = parse_tasks(xml)
            result = {}
            for t in tasks:
                result[t["id"]] = {
                    "status":         t["status"],
                    "progress":       t["progress"],
                    "severity":       t["severity"],
                    "last_report_id": t["last_report_id"],
                }
            return jsonify(result)
    except Exception as e:
        logger.error(f"Erreur: {e}")
        return jsonify({"error": "Erreur interne"}), 500
