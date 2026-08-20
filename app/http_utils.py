"""Utilitaires HTTP partagés — sécurité des redirections."""
from urllib.parse import urlparse

from flask import request


def safe_redirect_back(fallback: str) -> str:
    """Chemin du referrer s'il pointe vers le MÊME hôte, sinon `fallback`.

    request.referrer est un header contrôlé par le client : l'utiliser tel quel
    dans redirect() ouvre un open-redirect. On n'accepte qu'un referrer same-host
    et on n'en retourne que le chemin (jamais un netloc externe).
    """
    referrer = request.referrer
    if referrer:
        parsed = urlparse(referrer)
        host = urlparse(request.host_url)
        if parsed.netloc == host.netloc and parsed.scheme in ("http", "https"):
            if parsed.path and parsed.path.startswith("/"):
                return parsed.path
    return fallback
