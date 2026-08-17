"""
OIDC authentication backend using authlib.
"""
import logging
from typing import Optional, Tuple
from flask import current_app
from .base import AuthBackend, User

logger = logging.getLogger(__name__)


class OidcAuthBackend(AuthBackend):
    """
    Backend d'authentification OIDC (OAuth2 + OpenID Connect).
    
    - Authentification : Flow OAuth2 Authorization Code
    - Credentials GMP : Utilise le compte de service configuré dans .env
    
    Note: L'authentification OIDC se fait via redirect (pas de credentials directs),
    donc ce backend ne peut pas être utilisé avec authenticate() directement.
    Il sert principalement pour get_gmp_credentials().
    """
    
    def authenticate(self, **kwargs) -> Optional[User]:
        """
        L'authentification OIDC se fait via le flow OAuth2 (redirect).
        Cette méthode ne devrait pas être appelée directement.
        
        Returns:
            None (utiliser le flow OIDC via /auth/login_oidc)
        """
        logger.warning("OIDC authenticate() called directly - use OAuth flow instead")
        return None
    
    @staticmethod
    def create_user_from_userinfo(userinfo: dict) -> User:
        """
        Crée un User à partir des claims OIDC.
        
        Args:
            userinfo: Dict contenant les claims OIDC (sub, email, name, etc.)
            
        Returns:
            User object
        """
        # Préférer 'preferred_username' ou 'email' comme username
        username = userinfo.get("preferred_username") or \
                   userinfo.get("email") or \
                   userinfo.get("sub")
        
        email = userinfo.get("email")
        display_name = userinfo.get("name") or userinfo.get("given_name")
        
        logger.info(f"OIDC user created: {username}")
        
        return User(
            username=username,
            auth_backend="oidc",
            email=email,
            display_name=display_name
        )
    
    def get_gmp_credentials(self, user: User) -> Tuple[str, str]:
        """
        Retourne les credentials du compte de service GMP.
        
        Args:
            user: Utilisateur authentifié via OIDC (non utilisé)
            
        Returns:
            Tuple (service_account, service_password) depuis .env
        """
        cfg = current_app.config
        service_account = cfg["GMP_SERVICE_ACCOUNT"]
        service_password = cfg["GMP_SERVICE_PASSWORD"]
        
        if not service_account or not service_password:
            logger.error("GMP service account not configured for OIDC backend")
            raise ValueError(
                "GMP_SERVICE_ACCOUNT et GMP_SERVICE_PASSWORD doivent être "
                "configurés dans .env pour AUTH_BACKEND=oidc"
            )
        
        return (service_account, service_password)
