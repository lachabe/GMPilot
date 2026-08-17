from app.auth.permissions import require_perm
"""Flux NVT / SCAP / CERT — reads from SQLite."""
from flask import Blueprint, render_template
from flask_login import login_required

feeds_bp = Blueprint("feeds", __name__, url_prefix="/feeds")

@feeds_bp.route("/")
@login_required
@require_perm("feeds.read")
def index():
    from app.db import get_db, read_gmp_cache
    feeds = read_gmp_cache(get_db(), "feeds")
    return render_template("feeds/index.html", feeds=feeds)
