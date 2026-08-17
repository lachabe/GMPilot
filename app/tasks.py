"""
Module de gestion des tâches en arrière-plan.
Utilise des threads Python natifs avec statut en SQLite.
"""
import threading
import logging
from datetime import datetime
from typing import Callable

from flask import current_app

logger = logging.getLogger(__name__)

_running_threads: dict[str, threading.Thread] = {}
# Protège le TOCTOU is_task_running → _save_status(running=True) → thread.start()
_start_lock = threading.Lock()


def _get_conn():
    from app.db import connect_db
    return connect_db()


def get_task_status(task_type: str) -> dict:
    default = {"running": False, "started": None, "progress": None,
               "message": None, "error": None, "finished": None}
    try:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM task_status WHERE task_type=?", (task_type,)).fetchone()
        conn.close()
        if not row:
            return default

        status = {
            "running": bool(row["running"]),
            "started": row["started"],
            "progress": row["progress"],
            "message": row["message"],
            "error": row["error"],
            "finished": row["finished"],
        }

        if status["running"]:
            thread = _running_threads.get(task_type)
            if thread is None or not thread.is_alive():
                status["running"] = False
                status["error"] = "Tâche interrompue de manière inattendue"
                status["finished"] = datetime.now().isoformat()
                _save_status(task_type, status)

        return status
    except Exception:
        return default


def _save_status(task_type: str, status: dict) -> None:
    try:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO task_status (task_type, running, started, progress, message, error, finished)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(task_type) DO UPDATE SET
                 running=excluded.running, started=excluded.started,
                 progress=excluded.progress, message=excluded.message,
                 error=excluded.error, finished=excluded.finished""",
            (task_type, int(status.get("running", False)),
             status.get("started"), status.get("progress"),
             status.get("message"), status.get("error"),
             status.get("finished")),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"[TASK] Erreur sauvegarde statut {task_type}: {e}")


def update_task_status(task_type: str, progress: str = None, message: str = None) -> None:
    status = get_task_status(task_type)
    if progress is not None:
        status["progress"] = progress
    if message is not None:
        status["message"] = message
    _save_status(task_type, status)


def is_task_running(task_type: str) -> bool:
    return get_task_status(task_type).get("running", False)


def start_background_task(task_type: str, task_func: Callable, *args, **kwargs) -> tuple[bool, str]:
    with _start_lock:
        if is_task_running(task_type):
            return False, "Une tâche est déjà en cours"

        app = current_app._get_current_object()

        def run_with_context():
            with app.app_context():
                try:
                    logger.info(f"[TASK {task_type}] Démarrage")
                    task_func(*args, **kwargs)
                    logger.info(f"[TASK {task_type}] Terminé")
                    status = get_task_status(task_type)
                    status["running"] = False
                    status["finished"] = datetime.now().isoformat()
                    status["message"] = "Terminé"
                    _save_status(task_type, status)
                except Exception as e:
                    logger.exception(f"[TASK {task_type}] Erreur: {e}")
                    status = get_task_status(task_type)
                    status["running"] = False
                    status["error"] = str(e)
                    status["finished"] = datetime.now().isoformat()
                    _save_status(task_type, status)
                finally:
                    _running_threads.pop(task_type, None)

        _save_status(task_type, {
            "running": True,
            "started": datetime.now().isoformat(),
            "progress": None,
            "message": "Démarrage...",
            "error": None,
            "finished": None,
        })

        thread = threading.Thread(target=run_with_context, daemon=True)
        _running_threads[task_type] = thread
        thread.start()

    logger.info(f"[TASK {task_type}] Thread démarré (id={thread.ident})")
    return True, "Tâche démarrée"


def clear_task_status(task_type: str) -> None:
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM task_status WHERE task_type=?", (task_type,))
        conn.commit()
        conn.close()
    except Exception:
        pass
