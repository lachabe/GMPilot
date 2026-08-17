from app.auth.permissions import require_perm
"""Targets blueprint — reads from SQLite."""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user

targets_bp = Blueprint("targets", __name__, url_prefix="/targets")
PER_PAGE = 50

@targets_bp.route("/")
@login_required
@require_perm("targets.read")
def index():
    from app.db import get_db, read_gmp_cache
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))
    targets = read_gmp_cache(get_db(), "targets")
    total = len(targets)
    paged = targets[(page-1)*per_page:(page-1)*per_page+per_page]
    return render_template("targets/index.html", targets=paged,
                           page=page, per_page=per_page, total=total)

@targets_bp.route("/create", methods=["GET", "POST"])
@login_required
@require_perm("targets.create")
def create():
    from app.db import get_db, read_gmp_cache
    port_lists = read_gmp_cache(get_db(), "port_lists")
    if request.method == "POST":
        try:
            with gmp_session_for_user(current_user) as gmp:
                name = request.form["name"]
                hosts = request.form["hosts"]
                gmp.create_target(
                    name=name,
                    hosts=[h.strip() for h in hosts.split(",") if h.strip()],
                    port_list_id=request.form["port_list_id"],
                    comment=request.form.get("comment", ""),
                    exclude_hosts=[h.strip() for h in request.form.get("exclude_hosts","").split(",") if h.strip()] or None,
                )
                flash(f"Cible « {name} » créée.", "success")
                return redirect(url_for("targets.index"))
        except Exception as e:
            flash(f"Erreur : {e}", "danger")
    return render_template("targets/create.html", port_lists=port_lists)

@targets_bp.route("/<target_id>/delete", methods=["POST"])
@login_required
@require_perm("targets.delete")
def delete(target_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.delete_target(target_id)
            flash("Cible supprimée.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("targets.index"))
