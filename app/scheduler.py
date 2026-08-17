"""Scheduler — synchronisation périodique des caches GMP/CVE/KEV/ANSSI."""
import logging
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _get_gmp_credentials(app):
    """Retourne (username, password) du compte de service GMP ou None."""
    with app.app_context():
        cfg = app.config
        user = cfg.get("GMP_SERVICE_ACCOUNT", "")
        pwd = cfg.get("GMP_SERVICE_PASSWORD", "")
        if user and pwd:
            return user, pwd
    return None


def _run_gmp_refresh(app, cache_name):
    """Rafraîchit un cache GMP via le système de tâches (visible dans l'UI)."""
    creds = _get_gmp_credentials(app)
    if not creds:
        return
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        task_type = f"gmp_{cache_name}"
        if is_task_running(task_type):
            return
        from app.blueprints.cache import _task_refresh_gmp
        start_background_task(task_type, _task_refresh_gmp, cache_name, creds[0], creds[1])
        logger.info(f"[SCHEDULER] {cache_name} lancé")


def _run_vulns_refresh(app):
    """Rafraîchit vulns puis CVE si configuré."""
    creds = _get_gmp_credentials(app)
    if not creds:
        return
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("gmp_vulns"):
            return
        from app.blueprints.cache import _task_refresh_vulns

        def _vulns_then_cve():
            _task_refresh_vulns(creds[0], creds[1])
            from app.auth.roles import app_settings
            sched = app_settings().get("schedules", {}).get("cve", {})
            if sched.get("after_vulns", True):
                from app.blueprints.cache import _task_refresh_cve
                _task_refresh_cve()

        start_background_task("gmp_vulns", _vulns_then_cve)
        logger.info("[SCHEDULER] Vulns (+CVE) lancé")


def _run_kev_refresh(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("kev"):
            return
        from app.blueprints.cache import _task_refresh_kev
        start_background_task("kev", _task_refresh_kev)
        logger.info("[SCHEDULER] KEV lancé")


def _run_cve_update(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("cve"):
            return
        from app.blueprints.cache import _task_update_cve
        start_background_task("cve", _task_update_cve)
        logger.info("[SCHEDULER] CVE update lancé")


def _run_cpe_watch(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("cpe_watch"):
            return
        from app.blueprints.cache import _task_cpe_watch
        start_background_task("cpe_watch", _task_cpe_watch)
        logger.info("[SCHEDULER] CPE watch lancé")


def _run_cpe_dict_refresh(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("cpe_dict"):
            return
        from app.blueprints.cache import _task_refresh_cpe_dict
        start_background_task("cpe_dict", _task_refresh_cpe_dict)
        logger.info("[SCHEDULER] CPE dict lancé")


def _run_anssi_refresh(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("anssi"):
            return
        from app.blueprints.cache import _task_refresh_anssi
        start_background_task("anssi", _task_refresh_anssi, False)
        logger.info("[SCHEDULER] ANSSI lancé")


def _run_iana_refresh(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("iana"):
            return
        from app.blueprints.cache import _task_refresh_iana
        start_background_task("iana", _task_refresh_iana)
        logger.info("[SCHEDULER] IANA lancé")


def _run_dns_refresh(app):
    with app.app_context():
        from app.tasks import start_background_task, is_task_running
        if is_task_running("dns"):
            return
        from app.blueprints.cache import _task_refresh_dns
        # Périodique = incrémental (IP jamais tentées uniquement)
        start_background_task("dns", _task_refresh_dns, False)
        logger.info("[SCHEDULER] DNS inverse lancé (incrémental)")


_GMP_CACHE_KEYS = ["tasks", "targets", "schedules", "tags",
                    "scanners", "port_lists", "feeds", "scan_configs", "hosts"]
_GMP_CACHE_KEYS_SET = set(_GMP_CACHE_KEYS)


def _cache_key_to_task_type(cache_key: str) -> str:
    """Mappe cache_key → task_type dans task_status."""
    if cache_key == "cve_update":
        return "cve"
    if cache_key in _GMP_CACHE_KEYS_SET or cache_key == "vulns":
        return f"gmp_{cache_key}"
    return cache_key  # kev, anssi, cpe_watch, cpe_dict → identique


def _next_run_for(app, cache_key, interval_hours):
    """Calcule le prochain run depuis la dernière synchro connue.

    Priorité :
      1. task_status.finished  — mis à jour à chaque fin de tâche, fiable même
         pour cpe_watch / cve_update / cpe_dict qui n'écrivent pas dans gmp_cache.
      2. Source métier (gmp_cache, scan_imports…) — fallback premier démarrage.

    Si overdue → now + 10 s (lancement quasi-immédiat).
    Sinon      → now + temps_restant (pas de lancement au redémarrage).
    Inconnu    → now + 30 s (première exécution après install).
    """
    from datetime import datetime, timedelta
    from app.db import connect_db

    now = datetime.now()
    dt = None
    read_ok = False  # la lecture DB a-t-elle abouti ?

    try:
        conn = connect_db()
        try:
            # Source 1 : task_status. On se rabat sur `started` si `finished` est
            # NULL — une tâche interrompue par un redémarrage (démarrée mais jamais
            # terminée) ne doit PAS se relancer immédiatement au redémarrage suivant
            # (sinon boucle de relance à chaque restart pendant qu'elle tourne).
            task_type = _cache_key_to_task_type(cache_key)
            row = conn.execute(
                "SELECT finished, started FROM task_status WHERE task_type=?",
                (task_type,),
            ).fetchone()
            if row:
                dt = row["finished"] or row["started"]

            # Source 2 : fallback métier (premier démarrage — task_status vide)
            if dt is None:
                if cache_key == "vulns":
                    r = conn.execute("SELECT MAX(imported_at) as dt FROM scan_imports").fetchone()
                    dt = r["dt"] if r else None
                elif cache_key == "kev":
                    r = conn.execute("SELECT MAX(kev_updated_at) as dt FROM cves WHERE is_kev=1").fetchone()
                    dt = r["dt"] if r else None
                elif cache_key == "anssi":
                    r = conn.execute("SELECT MAX(updated_at) as dt FROM anssi_publications").fetchone()
                    dt = r["dt"] if r else None
                elif cache_key in _GMP_CACHE_KEYS_SET:
                    r = conn.execute("SELECT updated_at as dt FROM gmp_cache WHERE cache_key=?",
                                     (cache_key,)).fetchone()
                    dt = r["dt"] if r else None
            read_ok = True
        finally:
            conn.close()
    except Exception:
        read_ok = False

    if dt:
        try:
            last = datetime.fromisoformat(dt)
            age_minutes = (now - last).total_seconds() / 60
            if age_minutes >= interval_hours * 60:
                return now + timedelta(seconds=10)
            return now + timedelta(minutes=interval_hours * 60 - age_minutes)
        except Exception:
            pass

    if read_ok:
        # Lecture OK mais aucune date connue → première exécution (post-install)
        return now + timedelta(seconds=30)
    # Lecture DB échouée (verrou, contention…) → NE PAS déclencher un run : on
    # diffère d'un intervalle. Le prochain apply_schedules/redémarrage recalcule
    # correctement une fois la base libre. Évite la cascade de relances au restart.
    return now + timedelta(hours=max(1, interval_hours))


def _add_job(func, interval_hours, app, job_id, cache_key=None, extra_args=None):
    """Ajoute un job au scheduler avec next_run_time intelligent."""
    _scheduler.remove_job(job_id) if _scheduler.get_job(job_id) else None
    if interval_hours <= 0:
        return

    args = [app] + (extra_args or [])
    next_run = _next_run_for(app, cache_key or job_id, interval_hours)

    # Trace explicite : permet de vérifier au démarrage qu'un job différé ne se
    # relance pas (dans X min) plutôt que ~immédiatement (< 1 min).
    from datetime import datetime
    mins = (next_run - datetime.now()).total_seconds() / 60
    logger.info(f"[SCHEDULER] {job_id}: prochain run à {next_run:%Y-%m-%d %H:%M} (dans {mins:.0f} min)")

    _scheduler.add_job(
        func, "interval", hours=interval_hours,
        args=args, id=job_id, replace_existing=True,
        max_instances=1, misfire_grace_time=3600,
        next_run_time=next_run,
    )


def apply_schedules(app):
    """(Re)configure tous les jobs du scheduler depuis app_settings."""
    global _scheduler
    if _scheduler is None:
        return

    from app.auth.roles import app_settings
    settings = app_settings()

    if not settings.get("scheduler_enabled", False):
        for job in _scheduler.get_jobs():
            _scheduler.remove_job(job.id)
        logger.info("[SCHEDULER] Désactivé — tous les jobs supprimés")
        return

    schedules = settings.get("schedules", {})

    # GMP caches
    for key in _GMP_CACHE_KEYS:
        hours = schedules.get(key, {}).get("interval_hours", 0)
        _add_job(_run_gmp_refresh, hours, app, f"gmp_{key}", cache_key=key, extra_args=[key])

    # Vulns
    _add_job(_run_vulns_refresh, schedules.get("vulns", {}).get("interval_hours", 0),
             app, "vulns", cache_key="vulns")

    # KEV
    _add_job(_run_kev_refresh, schedules.get("kev", {}).get("interval_hours", 0),
             app, "kev")

    # CPE watch
    _add_job(_run_cpe_watch, schedules.get("cpe_watch", {}).get("interval_hours", 0),
             app, "cpe_watch")

    # CPE dictionary
    _add_job(_run_cpe_dict_refresh, schedules.get("cpe_dict", {}).get("interval_hours", 0),
             app, "cpe_dict")

    # CVE update
    _add_job(_run_cve_update, schedules.get("cve_update", {}).get("interval_hours", 0),
             app, "cve_update")

    # ANSSI
    _add_job(_run_anssi_refresh, schedules.get("anssi", {}).get("interval_hours", 0),
             app, "anssi")

    # IANA (référentiel des ports)
    _add_job(_run_iana_refresh, schedules.get("iana", {}).get("interval_hours", 0),
             app, "iana")

    # DNS inverse
    _add_job(_run_dns_refresh, schedules.get("dns", {}).get("interval_hours", 0),
             app, "dns")

    jobs = _scheduler.get_jobs()
    logger.info(f"[SCHEDULER] {len(jobs)} jobs configurés")


def init_app(app):
    """Initialise le scheduler et configure les jobs."""
    global _scheduler
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.start()
    logger.info("[SCHEDULER] Démarré")
    apply_schedules(app)


def get_jobs_info() -> list[dict]:
    """Retourne les infos des jobs pour l'affichage."""
    if _scheduler is None:
        return []
    return [
        {"id": job.id, "next_run": str(job.next_run_time),
         "interval": str(job.trigger)}
        for job in _scheduler.get_jobs()
    ]
