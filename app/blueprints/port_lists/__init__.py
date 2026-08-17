from app.auth.permissions import require_perm
"""Listes de ports — reads from SQLite."""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user

port_lists_bp = Blueprint("port_lists", __name__, url_prefix="/port-lists")

@port_lists_bp.route("/")
@login_required
@require_perm("port_lists.read")
def index():
    from app.db import get_db, read_gmp_cache
    port_lists = read_gmp_cache(get_db(), "port_lists")
    return render_template("port_lists/index.html", port_lists=port_lists)

@port_lists_bp.route("/<pl_id>/delete", methods=["POST"])
@login_required
@require_perm("port_lists.delete")
def delete(pl_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.delete_port_list(pl_id)
            flash("Liste de ports supprimée.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("port_lists.index"))
