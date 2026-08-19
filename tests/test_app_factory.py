"""Smoke test de l'application factory create_app.

init_db / init_scheduler sont neutralisés (pas de vraie BDD ni de thread). Vérifie
que l'app boote et enregistre config, blueprints, context processors et route racine.
Sert de filet au refactor de create_app.
"""


def _make_app(monkeypatch):
    import app as app_pkg
    import app.db
    import app.scheduler
    monkeypatch.setattr(app.db, "init_app", lambda a: None)
    monkeypatch.setattr(app.scheduler, "init_app", lambda a: None)
    return app_pkg.create_app()


EXPECTED_BLUEPRINTS = {
    "auth", "cache", "dashboard", "scans", "targets", "assets", "tags",
    "schedules", "vulns", "scanners", "feeds", "port_lists", "admin", "settings",
}


def test_boot_et_blueprints(monkeypatch):
    flask_app = _make_app(monkeypatch)
    assert EXPECTED_BLUEPRINTS <= set(flask_app.blueprints)


def test_config(monkeypatch):
    flask_app = _make_app(monkeypatch)
    assert flask_app.config["APP_NAME"] == "GMPilot"
    assert flask_app.config["APP_VERSION"]
    assert "CACHE_DIR" in flask_app.config


def test_route_racine_et_context_processors(monkeypatch):
    flask_app = _make_app(monkeypatch)
    assert "/" in {r.rule for r in flask_app.url_map.iter_rules()}
    # les context processors injectent APP_NAME + helpers
    procs = {}
    for fn in flask_app.template_context_processors[None]:
        procs.update(fn())
    assert procs.get("APP_NAME") == "GMPilot"
    assert callable(procs.get("query_with"))
    assert callable(procs.get("has_perm"))
