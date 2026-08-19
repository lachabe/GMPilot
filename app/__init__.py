"""GMPilot — Application Factory"""
import os
import logging
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth
from .config import Config

login_manager = LoginManager()
csrf = CSRFProtect()
oauth = OAuth()  # Pour OIDC

APP_NAME = "GMPilot"
APP_VERSION = "2.0.0"


def _configure_app(app, config_class):
    """Config de base : objet config, métadonnées, logging, cache dir, cookies."""
    app.config.from_object(config_class)
    app.config["APP_NAME"] = APP_NAME
    app.config["APP_VERSION"] = APP_VERSION

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

    cache_dir = os.path.join(app.root_path, "..", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    app.config["CACHE_DIR"] = os.path.abspath(cache_dir)

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _init_extensions(app):
    """Initialise login_manager, CSRF et OAuth (OIDC)."""
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
    login_manager.login_message_category = "warning"
    csrf.init_app(app)
    oauth.init_app(app)


def _inject_globals():
    return {"APP_NAME": APP_NAME, "APP_VERSION": APP_VERSION}


def _inject_helpers():
    from flask import request as req

    def query_with(**kwargs):
        p = req.args.copy()
        for k, v in kwargs.items():
            if v is None:
                p.pop(k, None)
            else:
                p[k] = str(v)
        return p.to_dict(flat=False)

    return {"query_with": query_with}


def _inject_cache_info():
    """Injecte cache_meta et has_perm dans tous les templates."""
    def cache_meta(name):
        from app.db import get_db, get_gmp_cache_meta
        from app.auth.roles import app_settings
        meta = get_gmp_cache_meta(get_db(), name)
        schedules = app_settings().get("schedules", {})
        interval_h = schedules.get(name, {}).get("interval_hours", 0)
        meta["threshold_ok"] = interval_h * 60 if interval_h > 0 else 60
        meta["threshold_warn"] = interval_h * 60 * 2 if interval_h > 0 else 1440
        return meta

    from flask_login import current_user as _cu

    def has_perm(perm: str) -> bool:
        """Vérifie la permission de l'utilisateur courant (templates)."""
        if not _cu.is_authenticated:
            return False
        return getattr(_cu, "has_perm", lambda p: False)(perm)

    return {"cache_meta": cache_meta, "has_perm": has_perm}


def _register_blueprints(app):
    from .blueprints.auth       import auth_bp
    from .blueprints.cache      import cache_bp
    from .blueprints.dashboard  import dashboard_bp
    from .blueprints.scans      import scans_bp
    from .blueprints.targets    import targets_bp
    from .blueprints.assets     import assets_bp
    from .blueprints.tags       import tags_bp
    from .blueprints.schedules  import schedules_bp
    from .blueprints.vulns      import vulns_bp
    from .blueprints.scanners   import scanners_bp
    from .blueprints.feeds      import feeds_bp
    from .blueprints.port_lists import port_lists_bp
    from .blueprints.admin      import admin_bp
    from .blueprints.settings   import settings_bp

    for bp in [auth_bp, cache_bp, dashboard_bp, scans_bp, targets_bp,
               assets_bp, tags_bp, schedules_bp, vulns_bp, scanners_bp,
               feeds_bp, port_lists_bp, admin_bp, settings_bp]:
        app.register_blueprint(bp)


def _root_redirect():
    """Route racine : redirige vers la 1re page autorisée de l'utilisateur."""
    from flask import redirect, url_for
    from flask_login import current_user
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
    menu_order = [
        ("vulns.read",       "dashboard.index"),
        ("scans.read",       "scans.index"),
        ("targets.read",     "targets.index"),
        ("schedules.read",   "schedules.index"),
        ("vulns.read",       "vulns.index"),
        ("assets.read",      "assets.hosts"),
        ("tags.read",        "tags.index"),
        ("cache.read",       "cache.index"),
        ("roles.read",       "admin.roles_index"),
    ]
    for perm, endpoint in menu_order:
        if current_user.has_perm(perm):
            return redirect(url_for(endpoint))
    return redirect(url_for("auth.login"))


def create_app(config_class=Config):
    app = Flask(__name__)
    _configure_app(app, config_class)

    from .db import init_app as init_db
    init_db(app)
    from .scheduler import init_app as init_scheduler
    init_scheduler(app)

    _init_extensions(app)
    app.context_processor(_inject_globals)
    app.context_processor(_inject_helpers)
    app.context_processor(_inject_cache_info)
    _register_blueprints(app)
    app.add_url_rule("/", "root", _root_redirect)

    return app
