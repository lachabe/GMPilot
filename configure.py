#!/usr/bin/env python3
"""Assistant d'installation interactif de GMPilot.

Génère .env + config/app_settings.json (+ config/roles/role-admin.json si
LDAP/OIDC) et, optionnellement, initialise la base SQLite.

Ré-exécutable : ne remplace jamais un fichier existant sans confirmation
explicite. La génération de config n'utilise que la stdlib.

    python configure.py            # installe dans le dossier du dépôt
    python configure.py --dir /srv/gmpilot   # cible un autre dossier

Nommé configure.py (et non setup.py) pour ne pas entrer en collision avec
setuptools/pip.
"""
import argparse
import getpass
import json
import os
import secrets
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


# ── Petites aides d'entrée ────────────────────────────────────────────────────
def ask(prompt, default=""):
    suffix = f" [{default}]" if default != "" else ""
    return input(f"  {prompt}{suffix} : ").strip() or default


def ask_bool(prompt, default=False):
    d = "O/n" if default else "o/N"
    r = input(f"  {prompt} [{d}] : ").strip().lower()
    if not r:
        return default
    return r in ("o", "oui", "y", "yes")


def ask_choice(prompt, choices, default):
    while True:
        r = ask(f"{prompt} ({'/'.join(choices)})", default)
        if r in choices:
            return r
        print(f"    → réponse invalide, choisir parmi : {', '.join(choices)}")


def ask_secret(prompt):
    try:
        return getpass.getpass(f"  {prompt} : ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def section(title):
    print(f"\n\033[1;36m── {title} ──\033[0m")


def can_write(path: Path) -> bool:
    """True si on peut écrire path (inexistant, ou l'utilisateur confirme l'écrasement)."""
    if path.exists():
        return ask_bool(f"{path.name} existe déjà — écraser ?", default=False)
    return True


# ── Collecte de configuration ─────────────────────────────────────────────────
def collect_env() -> dict:
    env = {}
    section("Flask")
    env["SECRET_KEY"] = secrets.token_urlsafe(48)
    print("  SECRET_KEY générée aléatoirement ✓")

    section("Connexion GVM/OpenVAS")
    ctype = ask_choice("Type de connexion", ["socket", "tcp"], "socket")
    env["GVM_CONNECTION_TYPE"] = ctype
    if ctype == "socket":
        env["GVM_SOCKET_PATH"] = ask("Chemin du socket gvmd", "/run/gvmd/gvmd.sock")
        env["GVM_HOST"] = "127.0.0.1"
        env["GVM_PORT"] = "9390"
    else:
        env["GVM_SOCKET_PATH"] = "/run/gvmd/gvmd.sock"
        env["GVM_HOST"] = ask("Hôte GVM", "127.0.0.1")
        env["GVM_PORT"] = ask("Port GVM", "9390")
    env["GVM_TIMEOUT"] = ask("Timeout des requêtes GVM (s)", "300")

    section("Authentification")
    backend = ask_choice("Backend", ["gmp", "ldap", "oidc"], "gmp")
    env["AUTH_BACKEND"] = backend

    admin_group = ""
    if backend in ("ldap", "oidc"):
        print("  Un compte de service GVM (lecture) est requis pour ce backend.")
        env["GMP_SERVICE_ACCOUNT"] = ask("Compte de service GVM")
        env["GMP_SERVICE_PASSWORD"] = ask_secret("Mot de passe du compte de service")

    if backend == "ldap":
        env["AUTH_LDAP_URL"] = ask("URL LDAP", "ldaps://ldap.example.com:636")
        env["AUTH_LDAP_BIND_DN"] = ask("Bind DN (compte de lecture)", "cn=readonly,dc=example,dc=com")
        env["AUTH_LDAP_BIND_PASSWORD"] = ask_secret("Mot de passe du bind DN")
        env["AUTH_LDAP_BASE_DN"] = ask("Base DN (recherche utilisateurs)", "ou=users,dc=example,dc=com")
        env["AUTH_LDAP_USER_FILTER"] = ask("Filtre utilisateur", "(sAMAccountName={username})")
        env["AUTH_LDAP_ATTR_EMAIL"] = ask("Attribut e-mail", "mail")
        env["AUTH_LDAP_ATTR_DISPLAYNAME"] = ask("Attribut nom affiché", "displayName")
        env["AUTH_LDAP_START_TLS"] = "true" if ask_bool("StartTLS ?", False) else "false"
        env["AUTH_LDAP_VALIDATE_CERT"] = "true" if ask_bool("Valider le certificat TLS ?", True) else "false"
        admin_group = ask("Groupe (DN) des administrateurs", "")

    if backend == "oidc":
        env["AUTH_OIDC_ISSUER"] = ask("Issuer OIDC", "https://keycloak.example.com/realms/prod")
        env["AUTH_OIDC_CLIENT_ID"] = ask("Client ID", "gmpilot")
        env["AUTH_OIDC_CLIENT_SECRET"] = ask_secret("Client Secret")
        env["AUTH_OIDC_REDIRECT_URI"] = ask("Redirect URI", "http://localhost:5000/auth/callback")
        env["AUTH_OIDC_SCOPE"] = ask("Scopes", "openid email profile")
        admin_group = ask("Groupe des administrateurs", "")

    return env, backend, admin_group


ENV_TEMPLATE = """\
# Généré par configure.py — ne pas committer (voir .gitignore)

# ──── Flask ────
SECRET_KEY={SECRET_KEY}

# ──── GVM ────
GVM_CONNECTION_TYPE={GVM_CONNECTION_TYPE}
GVM_SOCKET_PATH={GVM_SOCKET_PATH}
GVM_HOST={GVM_HOST}
GVM_PORT={GVM_PORT}
GVM_TIMEOUT={GVM_TIMEOUT}

# ──── Authentification ────
AUTH_BACKEND={AUTH_BACKEND}
GMP_SERVICE_ACCOUNT={GMP_SERVICE_ACCOUNT}
GMP_SERVICE_PASSWORD={GMP_SERVICE_PASSWORD}

# ──── LDAP ────
AUTH_LDAP_URL={AUTH_LDAP_URL}
AUTH_LDAP_BIND_DN={AUTH_LDAP_BIND_DN}
AUTH_LDAP_BIND_PASSWORD={AUTH_LDAP_BIND_PASSWORD}
AUTH_LDAP_BASE_DN={AUTH_LDAP_BASE_DN}
AUTH_LDAP_USER_FILTER={AUTH_LDAP_USER_FILTER}
AUTH_LDAP_ATTR_EMAIL={AUTH_LDAP_ATTR_EMAIL}
AUTH_LDAP_ATTR_DISPLAYNAME={AUTH_LDAP_ATTR_DISPLAYNAME}
AUTH_LDAP_START_TLS={AUTH_LDAP_START_TLS}
AUTH_LDAP_VALIDATE_CERT={AUTH_LDAP_VALIDATE_CERT}

# ──── OIDC ────
AUTH_OIDC_ISSUER={AUTH_OIDC_ISSUER}
AUTH_OIDC_CLIENT_ID={AUTH_OIDC_CLIENT_ID}
AUTH_OIDC_CLIENT_SECRET={AUTH_OIDC_CLIENT_SECRET}
AUTH_OIDC_REDIRECT_URI={AUTH_OIDC_REDIRECT_URI}
AUTH_OIDC_SCOPE={AUTH_OIDC_SCOPE}
"""

# Valeurs par défaut pour les clés non demandées selon le backend
ENV_DEFAULTS = {
    "GMP_SERVICE_ACCOUNT": "", "GMP_SERVICE_PASSWORD": "",
    "AUTH_LDAP_URL": "ldaps://ldap.example.com:636",
    "AUTH_LDAP_BIND_DN": "cn=readonly,dc=example,dc=com",
    "AUTH_LDAP_BIND_PASSWORD": "", "AUTH_LDAP_BASE_DN": "ou=users,dc=example,dc=com",
    "AUTH_LDAP_USER_FILTER": "(uid={username})", "AUTH_LDAP_ATTR_EMAIL": "mail",
    "AUTH_LDAP_ATTR_DISPLAYNAME": "displayName", "AUTH_LDAP_START_TLS": "false",
    "AUTH_LDAP_VALIDATE_CERT": "true", "AUTH_OIDC_ISSUER": "", "AUTH_OIDC_CLIENT_ID": "",
    "AUTH_OIDC_CLIENT_SECRET": "", "AUTH_OIDC_REDIRECT_URI": "http://localhost:5000/auth/callback",
    "AUTH_OIDC_SCOPE": "openid email profile",
}


def write_env(target: Path, env: dict):
    path = target / ".env"
    if not can_write(path):
        print("  → .env conservé.")
        return
    merged = {**ENV_DEFAULTS, **env}
    path.write_text(ENV_TEMPLATE.format(**merged), encoding="utf-8")
    os.chmod(path, 0o600)
    print(f"  → {path} écrit (chmod 600) ✓")


def write_app_settings(target: Path):
    path = target / "config" / "app_settings.json"
    if not can_write(path):
        print("  → app_settings.json conservé.")
        return
    example = SCRIPT_DIR / "config" / "app_settings.json.example"
    data = json.loads(example.read_text(encoding="utf-8")) if example.exists() else {}
    section("Paramètres applicatifs")
    data["ticket_url"] = ask("URL de ticket ( <id> = numéro )", data.get("ticket_url", ""))
    data["remediation_warn_days"] = int(ask("Seuil d'alerte remédiation (jours)",
                                             str(data.get("remediation_warn_days", 30))))
    data["remediation_critical_days"] = int(ask("Seuil critique remédiation (jours)",
                                                 str(data.get("remediation_critical_days", 90))))
    data["scheduler_enabled"] = ask_bool("Activer le planificateur de tâches ?",
                                          bool(data.get("scheduler_enabled", False)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"  → {path} écrit ✓")


def write_admin_role(target: Path, backend: str, group: str):
    if backend not in ("ldap", "oidc") or not group:
        return
    path = target / "config" / "roles" / "role-admin.json"
    if not can_write(path):
        print("  → role-admin.json conservé.")
        return
    example = SCRIPT_DIR / "config" / "roles" / "role-admin.json.example"
    if not example.exists():
        print("  ⚠ role-admin.json.example introuvable — rôle admin non créé.")
        return
    role = json.loads(example.read_text(encoding="utf-8"))
    role.setdefault("matching", {}).setdefault(backend, {})
    role["matching"][backend]["enabled"] = True
    role["matching"][backend]["groups"] = [group]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(role, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"  → {path} écrit (groupe admin : {group}) ✓")


def init_database(target: Path):
    if not ask_bool("Initialiser la base SQLite maintenant ?", default=True):
        return
    try:
        from flask import Flask
        from app.db import init_db
    except Exception as e:
        print(f"  ⚠ Dépendances non installées ({e}). Lance d'abord "
              "`pip install -r requirements.txt`, la base sera créée au 1er démarrage.")
        return
    app = Flask(__name__)
    app.config["CACHE_DIR"] = str((target / "cache").resolve())
    (target / "cache").mkdir(parents=True, exist_ok=True)
    with app.app_context():
        init_db()
    print(f"  → base initialisée : {target / 'cache' / 'gmpilot.db'} ✓")


def main():
    parser = argparse.ArgumentParser(description="Assistant d'installation GMPilot.")
    parser.add_argument("--dir", default=str(SCRIPT_DIR),
                        help="Dossier cible pour .env et config/ (défaut : dossier du dépôt)")
    args = parser.parse_args()
    target = Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    print("\033[1mAssistant d'installation GMPilot\033[0m")
    print(f"Cible : {target}\n(Entrée = valeur par défaut entre crochets)")

    try:
        env, backend, admin_group = collect_env()
        write_env(target, env)
        write_app_settings(target)
        write_admin_role(target, backend, admin_group)
        init_database(target)
    except (EOFError, KeyboardInterrupt):
        print("\nInstallation interrompue.")
        return 1

    section("Terminé")
    print("  Prochaines étapes :")
    print("    1. pip install -r requirements.txt")
    print("    2. python run.py   (ou via votre gestionnaire de service)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
