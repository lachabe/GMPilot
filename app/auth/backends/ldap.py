"""
LDAP authentication backend using ldap3.
"""
import logging
from typing import Optional, Tuple
from flask import current_app
from ldap3 import Server, Connection, ALL, SIMPLE, Tls
from ldap3.core.exceptions import LDAPException, LDAPBindError
import ssl
from .base import AuthBackend, User

logger = logging.getLogger(__name__)


class LdapAuthBackend(AuthBackend):
    """
    Backend d'authentification LDAP.
    
    - Authentification : Bind LDAP avec les credentials utilisateur
    - Credentials GMP : Utilise le compte de service configuré dans .env
    """
    
    def _get_server(self) -> Server:
        """
        Construit l'objet Server LDAP avec la config Flask.
        
        Returns:
            ldap3.Server configuré
        """
        cfg = current_app.config
        url = cfg["AUTH_LDAP_URL"]
        use_ssl = url.startswith("ldaps://")
        validate_cert = cfg["AUTH_LDAP_VALIDATE_CERT"]
        
        # Configuration TLS
        tls_config = None
        if use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED if validate_cert else ssl.CERT_NONE
            )
        
        return Server(
            url,
            use_ssl=use_ssl,
            tls=tls_config,
            get_info=ALL
        )
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authentifie via LDAP bind.
        
        Workflow:
        1. Bind avec compte readonly pour rechercher l'utilisateur
        2. Bind avec les credentials utilisateur pour validation
        3. Récupération des attributs (email, displayName)
        
        Args:
            username: Identifiant utilisateur (ex: "jdoe")
            password: Mot de passe utilisateur
            
        Returns:
            User object si authentification réussie, None sinon
        """
        cfg = current_app.config
        server = self._get_server()
        
        try:
            # Étape 1 : Bind avec compte readonly pour chercher l'utilisateur
            bind_dn = cfg["AUTH_LDAP_BIND_DN"]
            bind_pwd = cfg["AUTH_LDAP_BIND_PASSWORD"]
            
            with Connection(server, user=bind_dn, password=bind_pwd, auto_bind=True) as conn:
                # Recherche de l'utilisateur
                base_dn = cfg["AUTH_LDAP_BASE_DN"]
                user_filter = cfg["AUTH_LDAP_USER_FILTER"].format(username=username)
                
                conn.search(
                    search_base=base_dn,
                    search_filter=user_filter,
                    attributes=[
                        cfg["AUTH_LDAP_ATTR_EMAIL"],
                        cfg["AUTH_LDAP_ATTR_DISPLAYNAME"],
                        "memberOf",
                    ]
                )
                
                if not conn.entries:
                    logger.warning(f"LDAP user not found: {username}")
                    return None
                
                # Récupération du DN et des attributs
                user_entry = conn.entries[0]
                user_dn = user_entry.entry_dn
                
                # ldap3 normalise les noms d'attributs en minuscules
                attrs = user_entry.entry_attributes_as_dict
                
                email_attr = cfg["AUTH_LDAP_ATTR_EMAIL"].lower()
                name_attr = cfg["AUTH_LDAP_ATTR_DISPLAYNAME"].lower()
                
                email_list = attrs.get(email_attr, [])
                email = email_list[0] if email_list else None
                
                name_list = attrs.get(name_attr, [])
                display_name = name_list[0] if name_list else None
                
                # Récupération des groupes memberOf (DNs complets)
                groups = [str(g) for g in next((v for k, v in attrs.items() if k.lower() == "memberof"), [])]
                logger.info(f"LDAP groups fetched for {username}: {len(groups)} groups, first={groups[0] if groups else 'none'}")
            
            # Étape 2 : Bind avec les credentials utilisateur pour validation
            # + récupération de memberOf avec les droits de l'utilisateur lui-même
            with Connection(server, user=user_dn, password=password, auto_bind=True) as user_conn:
                logger.info(f"LDAP authentication successful for user: {username}")
                # Re-chercher memberOf avec le bind utilisateur (accès à ses propres attributs)
                from ldap3 import BASE, ALL_ATTRIBUTES
                user_conn.search(
                    search_base=user_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["memberOf"],
                )
                logger.info(f"LDAP user bind search result: entries={len(user_conn.entries)}, response={user_conn.result}")
                if user_conn.entries:
                    user_attrs = user_conn.entries[0].entry_attributes_as_dict
                    logger.info(f"LDAP user attrs keys: {list(user_attrs.keys())}")
                    groups = [str(g) for g in next((v for k, v in user_attrs.items() if k.lower() == "memberof"), [])]
                logger.info(f"LDAP groups for {username}: {len(groups)} (via user bind)")
                return User(
                    username=username,
                    auth_backend="ldap",
                    email=str(email) if email else None,
                    display_name=str(display_name) if display_name else None,
                    groups=groups,
                )
        
        except LDAPBindError as e:
            logger.warning(f"LDAP bind failed for {username}: {e}")
            return None
        except LDAPException as e:
            logger.error(f"LDAP error during authentication for {username}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during LDAP authentication for {username}: {e}")
            return None
    
    def get_gmp_credentials(self, user: User) -> Tuple[str, str]:
        """
        Retourne les credentials du compte de service GMP.
        
        Args:
            user: Utilisateur authentifié via LDAP (non utilisé)
            
        Returns:
            Tuple (service_account, service_password) depuis .env
        """
        cfg = current_app.config
        service_account = cfg["GMP_SERVICE_ACCOUNT"]
        service_password = cfg["GMP_SERVICE_PASSWORD"]
        
        if not service_account or not service_password:
            logger.error("GMP service account not configured for LDAP backend")
            raise ValueError(
                "GMP_SERVICE_ACCOUNT et GMP_SERVICE_PASSWORD doivent être "
                "configurés dans .env pour AUTH_BACKEND=ldap"
            )
        
        return (service_account, service_password)
