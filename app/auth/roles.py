"""
roles.py — Chargement, résolution et fusion des rôles depuis config/roles/*.json
"""
import os
import json
import logging
from typing import Optional
from .permissions import PERMISSION_KEYS

logger = logging.getLogger(__name__)


def _roles_dir() -> str:
    """Retourne le chemin du dossier config/roles/."""
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "config", "roles")


def load_all_roles() -> list[dict]:
    """Charge tous les fichiers role-*.json depuis config/roles/."""
    d = _roles_dir()
    if not os.path.isdir(d):
        return []
    roles = []
    for fname in sorted(os.listdir(d)):
        if not fname.startswith("role-") or not fname.endswith(".json"):
            continue
        path = os.path.join(d, fname)
        try:
            with open(path, encoding="utf-8") as f:
                role = json.load(f)
            role["_file"] = fname
            roles.append(role)
        except Exception as e:
            logger.warning(f"[ROLES] Erreur chargement {fname}: {e}")
    return roles


def _safe_role_path(role_id: str) -> str | None:
    """Retourne le chemin sécurisé d'un fichier rôle, ou None si invalide."""
    import re
    role_id = role_id.strip() if role_id else ""
    if not role_id or not re.match(r"^[a-zA-Z0-9_-]+$", role_id):
        return None
    d = _roles_dir()
    path = os.path.realpath(os.path.join(d, f"role-{role_id}.json"))
    if not path.startswith(os.path.realpath(d) + os.sep):
        return None
    return path


def save_role(role: dict) -> bool:
    """Sauvegarde un rôle dans config/roles/role-{id}.json."""
    os.makedirs(_roles_dir(), exist_ok=True)
    path = _safe_role_path(role.get("id", ""))
    if not path:
        return False
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(role, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"[ROLES] Erreur sauvegarde {role.get('id')}: {e}")
        return False


def delete_role(role_id: str) -> bool:
    """Supprime le fichier role-{id}.json."""
    path = _safe_role_path(role_id)
    if not path:
        return False
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        logger.error(f"[ROLES] Erreur suppression {role_id}: {e}")
        return False


def get_role(role_id: str) -> Optional[dict]:
    """Charge un rôle par son id."""
    path = _safe_role_path(role_id)
    if not path:
        return None
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def resolve_permissions(user, backend: str) -> tuple[dict, bool]:
    """
    Résout les permissions d'un utilisateur selon son backend et ses groupes.

    - backend GMP : admin total automatique (toutes permissions à True)
    - backend LDAP/OIDC : matching des groupes sur les rôles configurés,
      union des permissions de tous les rôles matchés.

    Retourne un dict {perm_key: bool}.
    """
    # Backend GMP → accès total
    if backend == "gmp":
        return {k: True for k in PERMISSION_KEYS}, True

    # Charger les rôles
    roles = load_all_roles()
    user_groups = getattr(user, "groups", []) or []

    # Permissions initiales : tout à False
    merged: dict[str, bool] = {k: False for k in PERMISSION_KEYS}
    matched_any = False

    logger.info(f"[ROLES] user.groups raw: {getattr(user, 'groups', 'ATTR_MISSING')}")
    logger.info(f"[ROLES] user_groups ({len(user_groups)}): {user_groups[:3]}...")
    for role in roles:
        matching = role.get("matching", {})
        backend_cfg = matching.get(backend, {})

        if not backend_cfg.get("enabled", False):
            logger.debug(f"[ROLES] Role {role.get('id')} disabled for backend {backend}")
            continue

        role_groups = backend_cfg.get("groups", [])
        logger.info(f"[ROLES] Role {role.get('id')} groups: {role_groups}")
        logger.info(f"[ROLES] Intersection: {[g for g in role_groups if g in user_groups]}")
        if not any(g in user_groups for g in role_groups):
            continue

        # Ce rôle matche — fusionner les permissions (union)
        matched_any = True
        for perm_key, allowed in role.get("permissions", {}).items():
            if perm_key in merged and allowed:
                merged[perm_key] = True

    if not matched_any:
        logger.info(f"[ROLES] Aucun rôle matché pour {getattr(user, 'username', '?')} via {backend}")

    return merged, matched_any


_SCHEDULE_DEFAULTS = {
    "tasks":        {"interval_hours": 168, "label": "Tâches de scan"},
    "vulns":        {"interval_hours": 4,   "label": "Vulnérabilités"},
    "hosts":        {"interval_hours": 24,  "label": "Hôtes"},
    "cve":          {"interval_hours": 0,   "label": "CVE — nouvelles", "after_vulns": True},
    "cve_update":   {"interval_hours": 72,  "label": "CVE — mise à jour"},
    "kev":          {"interval_hours": 24,  "label": "KEV"},
    "anssi":        {"interval_hours": 24,  "label": "ANSSI (CERT-FR)"},
    "targets":      {"interval_hours": 24,  "label": "Cibles"},
    "schedules":    {"interval_hours": 24,  "label": "Planifications"},
    "tags":         {"interval_hours": 24,  "label": "Tags"},
    "scanners":     {"interval_hours": 168, "label": "Scanners"},
    "port_lists":   {"interval_hours": 168, "label": "Listes de ports"},
    "feeds":        {"interval_hours": 168, "label": "Flux de données"},
    "scan_configs": {"interval_hours": 168, "label": "Configurations de scan"},
    "cpe_dict":    {"interval_hours": 168, "label": "Dictionnaire CPE (NVD)"},
    "cpe_watch":   {"interval_hours": 24,  "label": "Surveillance logicielle"},
    "iana":        {"interval_hours": 168, "label": "Référentiel des ports (IANA)"},
    "dns":         {"interval_hours": 24,  "label": "Résolution DNS inverse"},
}

_APP_SETTINGS_DEFAULTS = {
    "deny_if_no_role": True,
    "remediation_warn_days": 30,
    "remediation_critical_days": 90,
    "ticket_url": "",
    "scheduler_enabled": False,
    "schedules": {k: {"interval_hours": v["interval_hours"]}
                  for k, v in _SCHEDULE_DEFAULTS.items()},
}


def _app_settings_path() -> str:
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "config", "app_settings.json")


def app_settings() -> dict:
    """Charge config/app_settings.json avec valeurs par défaut."""
    path = _app_settings_path()
    result = dict(_APP_SETTINGS_DEFAULTS)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                result.update(json.load(f))
        except Exception:
            pass
    return result


def save_app_settings(settings: dict) -> bool:
    """Sauvegarde config/app_settings.json."""
    path = _app_settings_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"[SETTINGS] Erreur sauvegarde: {e}")
        return False
