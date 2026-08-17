"""
GMP authentication backend — Direct authentication via GMP credentials.
"""
import logging
from typing import Optional, Tuple
from .base import AuthBackend, User
from app.gvm_client import gmp_session

logger = logging.getLogger(__name__)


class GmpAuthBackend(AuthBackend):
    """
    Backend d'authentification GMP (comportement par défaut).
    
    - Authentification : Test de connexion GMP directe
    - Credentials GMP : Utilise les credentials de l'utilisateur (pass-through)
    """
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authentifie via une tentative de connexion GMP.
        
        Args:
            username: Identifiant GMP
            password: Mot de passe GMP
            
        Returns:
            User object si connexion réussie, None sinon
        """
        try:
            # Test de connexion GMP
            with gmp_session(username, password) as gmp:
                logger.info(f"GMP authentication successful for user: {username}")
                return User(
                    username=username,
                    auth_backend="gmp",
                    gmp_password=password  # Stocké pour réutilisation
                )
        except Exception as e:
            logger.warning(f"GMP authentication failed for {username}: {e}")
            return None
    
    def get_gmp_credentials(self, user: User) -> Tuple[str, str]:
        """
        Retourne les credentials de l'utilisateur (pass-through).
        
        Args:
            user: Utilisateur authentifié via GMP
            
        Returns:
            Tuple (username, password) de l'utilisateur
        """
        return (user.username, user._gmp_password)
