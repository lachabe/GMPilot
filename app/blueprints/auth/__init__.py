"""
Auth blueprint — Multi-backend authentication (GMP / LDAP / OIDC).
"""
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required
from app import login_manager, oauth
from app.auth.backends import get_current_backend, User
from app.auth.backends.oidc import OidcAuthBackend

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")

# Ordre de priorité des redirections post-login
_PERM_TO_ENDPOINT = [
    ("vulns.read",       "dashboard.index"),
    ("scans.read",       "scans.index"),
    ("targets.read",     "targets.index"),
    ("schedules.read",   "schedules.index"),
    ("assets.read",      "assets.hosts"),
    ("tags.read",        "tags.index"),
    ("port_lists.read",  "port_lists.index"),
    ("scanners.read",    "scanners.index"),
    ("feeds.read",       "feeds.index"),
    ("roles.read",       "admin.roles_index"),
]

def _default_redirect(user) -> str:
    """Retourne l'URL de la première page accessible par l'utilisateur."""
    for perm, endpoint in _PERM_TO_ENDPOINT:
        if user.has_perm(perm):
            return url_for(endpoint)
    return url_for("auth.login")


def _save_user_to_session(user: User):
    """Persiste l'objet User dans la session Flask (stockée sur filesystem)."""
    session["_user_data"] = user.to_dict()


@login_manager.user_loader
def load_user(user_id):
    """Reconstruit l'utilisateur depuis la session persistée."""
    data = session.get("_user_data")
    if data and data.get("username") == user_id:
        return User.from_dict(data)
    return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Route de login unifiée.
    
    - GET: Affiche le formulaire de login adapté au backend
    - POST: Traite l'authentification GMP ou LDAP
    """
    backend_name = current_app.config.get("AUTH_BACKEND", "gmp")
    
    if request.method == "POST":
        # Authentification pour GMP et LDAP (form-based)
        if backend_name in ["gmp", "ldap"]:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            
            if not username or not password:
                flash("Identifiant et mot de passe requis.", "danger")
                return render_template("login.html", backend_name=backend_name)
            
            try:
                backend = get_current_backend()
                user = backend.authenticate(username=username, password=password)
                
                if user:
                    # Résoudre les permissions selon les rôles
                    from app.auth.roles import resolve_permissions, app_settings
                    perms, matched = resolve_permissions(user, backend_name)
                    settings = app_settings()
                    if not matched and settings.get("deny_if_no_role", True):
                        logger.warning(f"Login refusé pour {username} : aucun rôle matché")
                        flash("Accès refusé : aucun rôle attribué à votre compte.", "danger")
                    else:
                        user.set_permissions(perms)
                        _save_user_to_session(user)
                        login_user(user)
                        logger.info(f"User {username} logged in via {backend_name}")
                        flash(f"Connecté avec succès via {backend_name.upper()}.", "success")

                        return redirect(_default_redirect(user))
                else:
                    flash("Identifiant ou mot de passe incorrect.", "danger")
            except Exception as e:
                logger.error(f"Authentication error for {username}: {e}")
                flash(f"Erreur d'authentification : {e}", "danger")
        else:
            flash(f"Backend {backend_name} ne supporte pas l'authentification par formulaire.", "warning")
    
    return render_template("login.html", backend_name=backend_name)


@auth_bp.route("/login/oidc")
def login_oidc():
    """
    Initie le flow OAuth2 OIDC.
    
    Redirige vers le provider OIDC pour authentification.
    """
    backend_name = current_app.config.get("AUTH_BACKEND", "gmp")
    
    if backend_name != "oidc":
        flash("Le backend OIDC n'est pas activé.", "warning")
        return redirect(url_for("auth.login"))
    
    # Configuration du client OIDC
    try:
        cfg = current_app.config
        
        # Vérifier que les paramètres OIDC sont configurés
        if not cfg.get("AUTH_OIDC_ISSUER") or not cfg.get("AUTH_OIDC_CLIENT_ID"):
            flash("Configuration OIDC incomplète. Vérifiez votre .env", "danger")
            return redirect(url_for("auth.login"))
        
        # Enregistrer le client OIDC dynamiquement si pas déjà fait
        if 'oidc' not in oauth._clients:
            oauth.register(
                name='oidc',
                client_id=cfg["AUTH_OIDC_CLIENT_ID"],
                client_secret=cfg["AUTH_OIDC_CLIENT_SECRET"],
                server_metadata_url=f"{cfg['AUTH_OIDC_ISSUER']}/.well-known/openid-configuration",
                client_kwargs={
                    'scope': cfg["AUTH_OIDC_SCOPE"]
                }
            )
        
        redirect_uri = cfg["AUTH_OIDC_REDIRECT_URI"]
        return oauth.oidc.authorize_redirect(redirect_uri)
    
    except Exception as e:
        logger.error(f"OIDC login error: {e}")
        flash(f"Erreur lors de l'initialisation OIDC : {e}", "danger")
        return redirect(url_for("auth.login"))


@auth_bp.route("/callback")
def callback():
    """
    Callback OAuth2 OIDC.
    
    Récupère le token, extrait les userinfo, et crée la session utilisateur.
    """
    backend_name = current_app.config.get("AUTH_BACKEND", "gmp")
    
    if backend_name != "oidc":
        flash("Callback OIDC non autorisé.", "danger")
        return redirect(url_for("auth.login"))
    
    try:
        # Échange du code contre un token
        token = oauth.oidc.authorize_access_token()
        
        # Récupération des userinfo
        userinfo = token.get("userinfo")
        if not userinfo:
            # Appel explicite au endpoint userinfo si absent du token
            userinfo = oauth.oidc.userinfo()
        
        # Création de l'utilisateur
        user = OidcAuthBackend.create_user_from_userinfo(userinfo)
        
        # Stockage du token en session pour refresh éventuel
        session["oidc_token"] = token
        
        # Résoudre les permissions
        from app.auth.roles import resolve_permissions, app_settings
        perms, matched = resolve_permissions(user, "oidc")
        settings = app_settings()
        if not matched and settings.get("deny_if_no_role", True):
            logger.warning(f"Login OIDC refusé pour {user.username} : aucun rôle matché")
            flash("Accès refusé : aucun rôle attribué à votre compte.", "danger")
            return redirect(url_for("auth.login"))

        user.set_permissions(perms)
        _save_user_to_session(user)
        login_user(user)
        logger.info(f"User {user.username} logged in via OIDC")
        flash("Connecté avec succès via OIDC.", "success")

        return redirect(_default_redirect(user))
    
    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        flash(f"Erreur lors de l'authentification OIDC : {e}", "danger")
        return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
@login_required
def logout():
    """
    Déconnexion de l'utilisateur.
    
    Pour OIDC, redirige également vers le logout du provider si configuré.
    """
    from flask_login import current_user
    
    backend_name = current_user.auth_backend if hasattr(current_user, "auth_backend") else "gmp"
    username = current_user.id
    
    # Nettoyage de la session
    session.pop("_user_data", None)
    session.pop("oidc_token", None)
    logout_user()
    
    logger.info(f"User {username} logged out (backend: {backend_name})")
    flash("Déconnecté.", "info")
    
    # Pour OIDC, on pourrait ajouter un logout du provider ici
    # if backend_name == "oidc":
    #     return redirect(f"{issuer}/protocol/openid-connect/logout?redirect_uri={app_url}")
    
    return redirect(url_for("auth.login"))
