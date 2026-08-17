from app.auth.permissions import require_perm
"""Assets blueprint — Hôtes, reads from SQLite + GMP for detail."""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user, parse_host_detail, gmp_get_host, gmp_delete_host

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")
PER_PAGE = 50

@assets_bp.route("/hosts")
@login_required
@require_perm("assets.read")
def hosts():
    from app.db import get_db

    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))

    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    offset = (page - 1) * per_page

    rows = db.execute(
        "SELECT id, ip, name, os, severity, last_seen, comment FROM hosts ORDER BY severity DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()

    host_list = [dict(r) for r in rows]
    return render_template("assets/hosts.html", hosts=host_list,
                           page=page, per_page=per_page, total=total)

@assets_bp.route("/hosts/<host_id>")
@login_required
@require_perm("assets.detail")
def host_detail(host_id):
    host = {}
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp_get_host(gmp, host_id)
            host = parse_host_detail(xml)
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return render_template("assets/host_detail.html", host=host)

@assets_bp.route("/hosts/<host_id>/delete", methods=["POST"])
@login_required
@require_perm("assets.delete")
def delete_host(host_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp_delete_host(gmp, host_id)
            flash("Hôte supprimé.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("assets.hosts"))
