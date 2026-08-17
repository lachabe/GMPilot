from app.auth.permissions import require_perm
"""Tags blueprint — reads from SQLite."""
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user, HOST_ENTITY_TYPE

tags_bp = Blueprint("tags", __name__, url_prefix="/tags")
PER_PAGE = 50

def _safe_redirect_back(fallback):
    referrer = request.referrer
    if referrer:
        parsed = urlparse(referrer)
        host_parsed = urlparse(request.host_url)
        if parsed.netloc == host_parsed.netloc and parsed.scheme in ("http", "https"):
            safe_path = parsed.path
            if safe_path and safe_path.startswith("/"):
                return safe_path
    return fallback

@tags_bp.route("/")
@login_required
@require_perm("tags.read")
def index():
    from app.db import get_db, read_gmp_cache
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))
    tags = read_gmp_cache(get_db(), "tags")
    total = len(tags)
    paged = tags[(page-1)*per_page:(page-1)*per_page+per_page]
    return render_template("tags/index.html", tags=paged,
                           page=page, per_page=per_page, total=total)

@tags_bp.route("/api/list")
@login_required
@require_perm("tags.read")
def api_list():
    from app.db import get_db, read_gmp_cache
    return jsonify(read_gmp_cache(get_db(), "tags"))

@tags_bp.route("/create", methods=["GET", "POST"])
@login_required
@require_perm("tags.create")
def create():
    if request.method == "POST":
        name = request.form["name"]
        try:
            with gmp_session_for_user(current_user) as gmp:
                gmp.create_tag(name=name, resource_type=HOST_ENTITY_TYPE,
                    value=request.form.get("value",""),
                    comment=request.form.get("comment",""), active=True)
                flash(f"Tag « {name} » créé.", "success")
                return redirect(url_for("tags.index"))
        except Exception as e:
            flash(f"Erreur : {e}", "danger")
    return render_template("tags/create.html")

@tags_bp.route("/<tag_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("tags.edit")
def edit(tag_id):
    tag_data = {}
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp.get_tag(tag_id)
            t = xml.find("tag")
            tag_data = {"id": tag_id, "name": t.findtext("name") or "",
                        "value": t.findtext("value") or "",
                        "comment": t.findtext("comment") or "",
                        "active": t.findtext("active") == "1"}
            if request.method == "POST":
                gmp.modify_tag(tag_id=tag_id, name=request.form["name"],
                    value=request.form.get("value",""),
                    comment=request.form.get("comment",""),
                    active=request.form.get("active") == "on")
                flash("Tag mis à jour.", "success")
                return redirect(url_for("tags.index"))
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return render_template("tags/edit.html", tag=tag_data)

@tags_bp.route("/<tag_id>/assign", methods=["POST"])
@login_required
@require_perm("tags.assign")
def assign_to_host(tag_id):
    host_id = request.form.get("host_id")
    if not host_id:
        flash("host_id manquant.", "danger")
        return redirect(url_for("tags.index"))
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp.get_tag(tag_id)
            t = xml.find("tag")
            gmp.modify_tag(tag_id=tag_id, name=t.findtext("name") or "",
                value=t.findtext("value") or "", comment=t.findtext("comment") or "",
                resource_ids=[host_id], resource_type=HOST_ENTITY_TYPE, active=True)
            flash("Tag assigné.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("tags.index"))

@tags_bp.route("/<tag_id>/delete", methods=["POST"])
@login_required
@require_perm("tags.delete")
def delete(tag_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.delete_tag(tag_id)
            flash("Tag supprimé.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("tags.index"))
