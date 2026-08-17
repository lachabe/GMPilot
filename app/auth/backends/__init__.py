"""
Authentication backends factory.
"""
import logging
from flask import current_app
from .base import AuthBackend, User
from .gmp import GmpAuthBackend
from .ldap import LdapAuthBackend
from .oidc import OidcAuthBackend

logger = logging.getLogger(__name__)

# Cache des instances de backends
_backend_instances = {}


def get_auth_backend(backend_name: str = None) -> AuthBackend:
    """
    Retourne l'instance du backend d'authentification configuré.
    
    Args:
        backend_name: Nom du backend ("gmp", "ldap", "oidc").
                      Si None, utilise AUTH_BACKEND depuis la config.
    
    Returns:
        Instance du backend correspondant
        
    Raises:
        ValueError: Si le backend n'est pas reconnu
    """
    if backend_name is None:
        backend_name = current_app.config.get("AUTH_BACKEND", "gmp")
    
    # Cache de l'instance
    if backend_name not in _backend_instances:
        if backend_name == "gmp":
            _backend_instances[backend_name] = GmpAuthBackend()
        elif backend_name == "ldap":
            _backend_instances[backend_name] = LdapAuthBackend()
        elif backend_name == "oidc":
            _backend_instances[backend_name] = OidcAuthBackend()
        else:
            raise ValueError(
                f"Backend d'authentification inconnu: {backend_name}. "
                f"Valeurs valides: gmp, ldap, oidc"
            )
    
    return _backend_instances[backend_name]


def get_current_backend() -> AuthBackend:
    """
    Retourne le backend configuré dans l'application.
    
    Returns:
        Instance du backend actif
    """
    return get_auth_backend()


__all__ = [
    "User",
    "AuthBackend",
    "get_auth_backend",
    "get_current_backend",
    "GmpAuthBackend",
    "LdapAuthBackend",
    "OidcAuthBackend",
]
