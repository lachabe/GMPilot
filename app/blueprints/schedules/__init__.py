from app.auth.permissions import require_perm
"""Schedules blueprint — reads from SQLite."""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.gvm_client import gmp_session_for_user

schedules_bp = Blueprint("schedules", __name__, url_prefix="/schedules")
PER_PAGE = 50

@schedules_bp.route("/")
@login_required
@require_perm("schedules.read")
def index():
    from app.db import get_db, read_gmp_cache
    page = max(1, int(request.args.get("page", 1)))
    per_page = max(10, min(200, int(request.args.get("per_page", PER_PAGE))))
    schedules = read_gmp_cache(get_db(), "schedules")
    total = len(schedules)
    paged = schedules[(page-1)*per_page:(page-1)*per_page+per_page]
    return render_template("schedules/index.html", schedules=paged,
                           page=page, per_page=per_page, total=total)

@schedules_bp.route("/create", methods=["GET", "POST"])
@login_required
@require_perm("schedules.create")
def create():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        icalendar = request.form.get("icalendar", "").strip()
        timezone = request.form.get("timezone", "UTC").strip()
        comment = request.form.get("comment", "").strip()
        if not name or not icalendar:
            flash("Nom et iCalendar requis.", "danger")
            return render_template("schedules/create.html")
        try:
            with gmp_session_for_user(current_user) as gmp:
                gmp.create_schedule(name=name, icalendar=icalendar,
                                    timezone=timezone, comment=comment)
            flash(f"Planification « {name} » créée.", "success")
            return redirect(url_for("schedules.index"))
        except Exception as e:
            flash(f"Erreur : {e}", "danger")
    return render_template("schedules/create.html")

@schedules_bp.route("/<schedule_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("schedules.edit")
def edit(schedule_id):
    schedule = {}
    try:
        with gmp_session_for_user(current_user) as gmp:
            xml = gmp.get_schedule(schedule_id)
            s = xml.find("schedule")
            if s is None:
                flash("Planification introuvable.", "danger")
                return redirect(url_for("schedules.index"))
            schedule = {"id": schedule_id, "name": s.findtext("name") or "",
                "comment": s.findtext("comment") or "", "timezone": s.findtext("timezone") or "UTC",
                "icalendar": s.findtext("icalendar") or ""}
            if request.method == "POST":
                gmp.modify_schedule(schedule_id=schedule_id, name=request.form["name"],
                    icalendar=request.form["icalendar"],
                    timezone=request.form.get("timezone","UTC"),
                    comment=request.form.get("comment",""))
                flash("Planification mise à jour.", "success")
                return redirect(url_for("schedules.index"))
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return render_template("schedules/edit.html", schedule=schedule)

@schedules_bp.route("/<schedule_id>/delete", methods=["POST"])
@login_required
@require_perm("schedules.delete")
def delete(schedule_id):
    try:
        with gmp_session_for_user(current_user) as gmp:
            gmp.delete_schedule(schedule_id)
            flash("Planification supprimée.", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("schedules.index"))
