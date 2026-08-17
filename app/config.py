import os
from dotenv import load_dotenv

load_dotenv(override=True)


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    # Flask-WTF CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1h
    
    # ──── GVM ────────────────────────────────────────────────────────────────
    GVM_CONNECTION_TYPE = os.environ.get("GVM_CONNECTION_TYPE", "socket")
    GVM_SOCKET_PATH     = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
    GVM_HOST            = os.environ.get("GVM_HOST", "127.0.0.1")
    GVM_PORT            = int(os.environ.get("GVM_PORT", 9390))
    GVM_TIMEOUT         = int(os.environ.get("GVM_TIMEOUT", 60))
    
    # ──── Authentification ───────────────────────────────────────────────────
    # Backend d'authentification : "gmp" | "ldap" | "oidc"
    AUTH_BACKEND = os.environ.get("AUTH_BACKEND", "gmp")
    
    # Compte de service GVM (utilisé uniquement si AUTH_BACKEND != "gmp")
    # Ce compte est utilisé pour toutes les requêtes GMP après authentification LDAP/OIDC
    GMP_SERVICE_ACCOUNT  = os.environ.get("GMP_SERVICE_ACCOUNT", "")
    GMP_SERVICE_PASSWORD = os.environ.get("GMP_SERVICE_PASSWORD", "")
    
    # ──── LDAP ───────────────────────────────────────────────────────────────
    # Configuration pour AUTH_BACKEND=ldap
    AUTH_LDAP_URL              = os.environ.get("AUTH_LDAP_URL", "ldaps://ldap.example.com:636")
    AUTH_LDAP_BIND_DN          = os.environ.get("AUTH_LDAP_BIND_DN", "cn=readonly,dc=example,dc=com")
    AUTH_LDAP_BIND_PASSWORD    = os.environ.get("AUTH_LDAP_BIND_PASSWORD", "")
    AUTH_LDAP_BASE_DN          = os.environ.get("AUTH_LDAP_BASE_DN", "ou=users,dc=example,dc=com")
    AUTH_LDAP_USER_FILTER      = os.environ.get("AUTH_LDAP_USER_FILTER", "(uid={username})")
    AUTH_LDAP_ATTR_EMAIL       = os.environ.get("AUTH_LDAP_ATTR_EMAIL", "mail")
    AUTH_LDAP_ATTR_DISPLAYNAME = os.environ.get("AUTH_LDAP_ATTR_DISPLAYNAME", "displayName")
    AUTH_LDAP_START_TLS        = os.environ.get("AUTH_LDAP_START_TLS", "false").lower() == "true"
    AUTH_LDAP_VALIDATE_CERT    = os.environ.get("AUTH_LDAP_VALIDATE_CERT", "true").lower() == "true"
    
    # ──── OIDC ───────────────────────────────────────────────────────────────
    # Configuration pour AUTH_BACKEND=oidc
    AUTH_OIDC_ISSUER        = os.environ.get("AUTH_OIDC_ISSUER", "")
    AUTH_OIDC_CLIENT_ID     = os.environ.get("AUTH_OIDC_CLIENT_ID", "")
    AUTH_OIDC_CLIENT_SECRET = os.environ.get("AUTH_OIDC_CLIENT_SECRET", "")
    AUTH_OIDC_REDIRECT_URI  = os.environ.get("AUTH_OIDC_REDIRECT_URI", "http://localhost:5000/auth/callback")
    AUTH_OIDC_SCOPE         = os.environ.get("AUTH_OIDC_SCOPE", "openid email profile")

    # ──── EUVD (ENISA) ───────────────────────────────────────────────────────
    # Délai minimal (secondes) entre deux requêtes à l'API EUVD.
    # EUVD limite à ~1 requête / 6 secondes → défaut 6.0s (sinon 429 en rafale).
    # Utilisé pour la pagination CPE Watch et le refresh CVE.
    EUVD_RATE_LIMIT = float(os.environ.get("EUVD_RATE_LIMIT", "6.0"))
    # Taille de page de la recherche EUVD (surveillance logicielle).
    # EUVD PLAFONNE à 100 enregistrements/requête → 100 est l'optimum (valeur
    # bornée à 100 dans le code). Un produit à N CVE nécessite ceil(N/100) pages.
    EUVD_PAGE_SIZE = int(os.environ.get("EUVD_PAGE_SIZE", "100"))

    # ──── Sessions ────────────────────────────────────────────────────────
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME", 86400))  # 24h par défaut
