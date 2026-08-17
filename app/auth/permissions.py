"""
permissions.py — Liste canonique des permissions et décorateur require_perm().
"""
from functools import wraps
from flask import abort, request, jsonify
from flask_login import current_user

# ── Liste complète des permissions ────────────────────────────────────────────
PERMISSIONS = [
    # Cache
    ("cache.read",           "Cache",         "Voir l'état des caches"),
    ("cache.refresh_gmp",    "Cache",         "Rafraîchir les caches GMP"),
    ("cache.refresh_vulns",  "Cache",         "Rafraîchir le cache vulnérabilités"),
    ("cache.refresh_cve",    "Cache",         "Télécharger/mettre à jour les CVE"),
    ("cache.refresh_kev",    "Cache",         "Télécharger le KEV"),
    ("cache.refresh_anssi",  "Cache",         "Mettre à jour le cache ANSSI"),
    # Vulnérabilités
    ("vulns.read",           "Vulnérabilités","Voir la liste des vulnérabilités"),
    ("vulns.detail",         "Vulnérabilités","Voir le détail d'une vulnérabilité"),
    ("vulns.mark_fp",        "Vulnérabilités","Déclarer / annuler un faux positif"),
    ("vulns.debug",          "Vulnérabilités","Accéder au endpoint debug-scoring"),
    # Tâches de scan
    ("scans.read",           "Scans",         "Voir la liste des tâches"),
    ("scans.create",         "Scans",         "Créer une tâche de scan"),
    ("scans.start",          "Scans",         "Démarrer un scan"),
    ("scans.stop",           "Scans",         "Arrêter un scan"),
    ("scans.resume",         "Scans",         "Reprendre un scan"),
    ("scans.delete",         "Scans",         "Supprimer une tâche"),
    # Cibles
    ("targets.read",         "Cibles",        "Voir la liste des cibles"),
    ("targets.create",       "Cibles",        "Créer une cible"),
    ("targets.delete",       "Cibles",        "Supprimer une cible"),
    # Planifications
    ("schedules.read",       "Planifications","Voir la liste des planifications"),
    ("schedules.create",     "Planifications","Créer une planification"),
    ("schedules.edit",       "Planifications","Modifier une planification"),
    ("schedules.delete",     "Planifications","Supprimer une planification"),
    # Hôtes
    ("assets.read",          "Hôtes",         "Voir la liste des hôtes"),
    ("assets.detail",        "Hôtes",         "Voir le détail d'un hôte"),
    ("assets.delete",        "Hôtes",         "Supprimer un hôte"),
    # Tags
    ("tags.read",            "Tags",          "Voir la liste des tags"),
    ("tags.create",          "Tags",          "Créer un tag"),
    ("tags.edit",            "Tags",          "Modifier un tag"),
    ("tags.assign",          "Tags",          "Assigner un tag à un hôte"),
    ("tags.delete",          "Tags",          "Supprimer un tag"),
    # Configuration
    ("port_lists.read",      "Configuration", "Voir les listes de ports"),
    ("port_lists.delete",    "Configuration", "Supprimer une liste de ports"),
    ("scanners.read",        "Configuration", "Voir les scanners"),
    ("scanners.edit",        "Configuration", "Modifier un scanner"),
    ("scanners.verify",      "Configuration", "Vérifier un scanner"),
    ("feeds.read",           "Configuration", "Voir les flux de données"),
    # Administration
    ("roles.read",            "Administration","Voir la liste des rôles"),
    ("roles.create",          "Administration","Créer un rôle"),
    ("roles.edit",            "Administration","Modifier un rôle"),
    ("roles.delete",          "Administration","Supprimer un rôle"),
    ("settings.scoring_read", "Administration","Voir la configuration du scoring"),
    ("settings.scoring_edit", "Administration","Modifier la configuration du scoring"),
    ("settings.general_read", "Administration","Voir les paramètres généraux"),
    ("settings.general_edit", "Administration","Modifier les paramètres généraux"),
    ("dns.manage",            "Administration","Éditer les résolutions DNS (hostnames)"),
]

# Set des clés pour validation rapide
PERMISSION_KEYS = {p[0] for p in PERMISSIONS}

# Regroupement par section pour l'UI
def permissions_by_section() -> dict:
    sections = {}
    for key, section, desc in PERMISSIONS:
        sections.setdefault(section, []).append({"key": key, "desc": desc})
    return sections


def require_perm(perm: str):
    """
    Décorateur Flask — vérifie que l'utilisateur connecté possède la permission.
    Retourne 403 (JSON si AJAX, redirect sinon).
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not getattr(current_user, "has_perm", lambda p: False)(perm):
                if request.headers.get("X-Requested-With") == "XMLHttpRequest" or \
                   request.accept_mimetypes.best == "application/json":
                    return jsonify({"error": "Permission refusée", "perm": perm}), 403
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator
