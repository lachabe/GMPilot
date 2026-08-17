"""
Base abstract class for authentication backends.
"""
from abc import ABC, abstractmethod
from typing import Optional, Tuple


class User:
    """
    Modèle utilisateur unifié pour tous les backends d'authentification.
    """
    def __init__(
        self,
        username: str,
        auth_backend: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        gmp_password: Optional[str] = None,
        groups: Optional[list] = None,
        permissions: Optional[dict] = None,
    ):
        self.id = username  # Flask-Login compatibility
        self.username = username
        self.email = email or f"{username}@localhost"
        self.display_name = display_name or username
        self.auth_backend = auth_backend
        self._gmp_password = gmp_password  # Seulement pour backend GMP
        self.groups = groups or []          # Groupes LDAP/OIDC
        self._permissions = permissions or {}  # {perm_key: bool}

    def has_perm(self, perm: str) -> bool:
        """Vérifie si l'utilisateur possède une permission."""
        return bool(self._permissions.get(perm, False))

    def set_permissions(self, permissions: dict):
        """Définit les permissions résolues."""
        self._permissions = permissions
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return True
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        """Flask-Login compatibility."""
        return self.id
    
    def get_gmp_credentials(self):
        """
        Retourne les credentials GMP pour cet utilisateur.
        Délègue au backend d'authentification.
        """
        from . import get_auth_backend
        backend = get_auth_backend(self.auth_backend)
        return backend.get_gmp_credentials(self)

    def to_dict(self) -> dict:
        """Sérialise l'utilisateur pour stockage en session."""
        return {
            "username": self.username,
            "auth_backend": self.auth_backend,
            "email": self.email,
            "display_name": self.display_name,
            "gmp_password": self._gmp_password,
            "groups": self.groups,
            "permissions": self._permissions,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        """Reconstruit un User depuis un dict de session."""
        return cls(
            username=data["username"],
            auth_backend=data["auth_backend"],
            email=data.get("email"),
            display_name=data.get("display_name"),
            gmp_password=data.get("gmp_password"),
            groups=data.get("groups", []),
            permissions=data.get("permissions", {}),
        )

    def __repr__(self):
        return f"<User {self.username} via {self.auth_backend}>"


class AuthBackend(ABC):
    """
    Interface abstraite pour les backends d'authentification.
    
    Chaque backend doit implémenter :
    - authenticate() : Valider les credentials utilisateur
    - get_gmp_credentials() : Fournir les credentials GMP pour les appels backend
    """
    
    @abstractmethod
    def authenticate(self, **kwargs) -> Optional[User]:
        """
        Authentifie un utilisateur avec les paramètres fournis.
        
        Returns:
            User object si succès, None sinon
        """
        raise NotImplementedError
    
    @abstractmethod
    def get_gmp_credentials(self, user: User) -> Tuple[str, str]:
        """
        Retourne les credentials GMP pour effectuer les appels backend.
        
        Args:
            user: L'utilisateur authentifié
            
        Returns:
            Tuple (username, password) pour la connexion GMP
        """
        raise NotImplementedError
