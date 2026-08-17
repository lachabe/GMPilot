"""Dashboard blueprint — vue synthétique de l'état de sécurité."""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from app.auth.permissions import require_perm
from app.db import get_db, get_dashboard_stats, get_timeline_data

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/")
@login_required
@require_perm("vulns.read")
def index():
    db = get_db()
    stats = get_dashboard_stats(db)
    return render_template("dashboard/index.html", **stats)


@dashboard_bp.route("/api")
@login_required
@require_perm("vulns.read")
def api_stats():
    """Retourne les stats du dashboard en JSON, optionnellement à une date donnée."""
    db = get_db()
    at_date = request.args.get("date")
    stats = get_dashboard_stats(db, at_date=at_date)
    stats["top_hosts"] = [{"host": h, **d} for h, d in stats["top_hosts"]]
    stats["top_products"] = [{"label": l, **d} for l, d in stats["top_products"]]
    return jsonify(stats)


@dashboard_bp.route("/api/timeline")
@login_required
@require_perm("vulns.read")
def api_timeline():
    """Retourne les séries temporelles pour l'onglet Tendances."""
    db = get_db()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    if not date_from or not date_to:
        row = db.execute(
            "SELECT MIN(date(first_seen)) as d0, MAX(COALESCE(date(resolved_at), date('now'))) as d1 FROM findings"
        ).fetchone()
        date_from = date_from or row["d0"] or "2024-01-01"
        date_to = date_to or row["d1"] or "2026-12-31"
    data = get_timeline_data(db, date_from, date_to)
    return jsonify(data)
