from app.auth.permissions import require_perm
"""Scanners blueprint — reads from SQLite."""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user

scanners_bp = Blueprint("scanners", __name__, url_prefix="/scanners")

@scanners_bp.route("/")
@login_required
@require_perm("scanners.read")
def index():
    from app.db import get_db, read_gmp_cache
    scanners = read_gmp_cache(get_db(), "scanners")
    return render_template("scanners/index.html", scanners=scanners)

@scanners_bp.route("/<scanner_id>/verify", methods=["POST"])
@login_required
@require_perm("scanners.verify")
def verify(scanner_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.verify_scanner(scanner_id)
            flash("Scanner vérifié.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("scanners.index"))

@scanners_bp.route("/<scanner_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("scanners.edit")
def edit(scanner_id):
    scanner = {}
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp.get_scanner(scanner_id)
            s = xml.find("scanner")
            if s is None:
                flash("Scanner introuvable.", "danger")
                return redirect(url_for("scanners.index"))
            scanner = {"id": scanner_id, "name": s.findtext("name") or "",
                "host": s.findtext("host") or "", "port": s.findtext("port") or "9390",
                "comment": s.findtext("comment") or "", "type": s.findtext("type") or "2"}
            if request.method == "POST":
                gmp.modify_scanner(scanner_id=scanner_id, name=request.form["name"],
                    host=request.form.get("host",""),
                    port=int(request.form.get("port", 9390)),
                    comment=request.form.get("comment",""))
                flash("Scanner mis à jour.", "success")
                return redirect(url_for("scanners.index"))
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return render_template("scanners/edit.html", scanner=scanner)
