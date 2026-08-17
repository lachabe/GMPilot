# Installation de GMPilot

## Prérequis

- Python 3.11 ou supérieur
- GVM / OpenVAS installé et fonctionnel (Greenbone Community Edition recommandée)
- Accès au socket GVM (`/run/gvmd/gvmd.sock`) ou à l'API TCP (port 9390)

---

## 1. Cloner le projet

```bash
git clone https://github.com/votre-org/gmpilot.git
cd gmpilot
```

## 2. Environnement virtuel

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# ou
.venv\Scripts\activate         # Windows
```

## 3. Dépendances Python

```bash
pip install -r requirements.txt
pip install defusedxml          # Recommandé (sécurité XML)
```

## 4. Configuration

### Option A — Assistant interactif (recommandé)

```bash
python configure.py
```

L'assistant pose quelques questions (connexion GVM, backend d'authentification,
paramètres applicatifs), puis génère `.env`, `config/app_settings.json` (et
`config/roles/role-admin.json` en LDAP/OIDC) et initialise la base SQLite. Il ne
remplace aucun fichier existant sans confirmation. Voir les détails ci-dessous
pour ajuster manuellement.

### Option B — Manuelle

Copier le fichier d'exemple et l'adapter :

```bash
cp .env.example .env
```

Éditer `.env` selon votre environnement. Les variables minimales obligatoires :

```env
SECRET_KEY=une-clé-secrète-aléatoire-longue

# Connexion GVM
GVM_CONNECTION_TYPE=socket
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock

# Backend d'authentification : gmp | ldap | oidc
AUTH_BACKEND=gmp
```

### Authentification GMP (défaut)

Les utilisateurs se connectent avec leurs comptes GVM directement. Aucune configuration supplémentaire requise.

### Authentification LDAP

```env
AUTH_BACKEND=ldap
AUTH_LDAP_URL=ldaps://ad.example.com:636
AUTH_LDAP_BIND_DN=CN=svc-gmpilot,OU=ServiceAccounts,DC=example,DC=com
AUTH_LDAP_BIND_PASSWORD=mot-de-passe
AUTH_LDAP_BASE_DN=OU=Users,DC=example,DC=com
AUTH_LDAP_USER_FILTER=(sAMAccountName={username})   # Active Directory
# AUTH_LDAP_USER_FILTER=(uid={username})             # OpenLDAP

# Compte de service GVM (requis pour LDAP/OIDC)
GMP_SERVICE_ACCOUNT=gvm-readonly
GMP_SERVICE_PASSWORD=mot-de-passe-gvm
```

### Authentification OIDC

```env
AUTH_BACKEND=oidc
AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/production
AUTH_OIDC_CLIENT_ID=gmpilot
AUTH_OIDC_CLIENT_SECRET=secret
AUTH_OIDC_REDIRECT_URI=https://gmpilot.example.com/auth/callback
GMP_SERVICE_ACCOUNT=gvm-readonly
GMP_SERVICE_PASSWORD=mot-de-passe-gvm
```

## 5. Assets statiques

Les fichiers Tabler (CSS/JS/fonts) doivent être présents dans `app/static/vendor/`. Si le dossier est vide, utiliser le script fourni :

```bash
python download_static.py
```

## 6. Configuration des rôles

Un rôle administrateur est fourni par défaut dans `config/roles/role-admin.json`. Adapter le matching LDAP/OIDC selon votre annuaire :

```json
{
  "matching": {
    "ldap": {
      "enabled": true,
      "groups": ["CN=MonGroupe,OU=...,DC=example,DC=com"]
    }
  }
}
```

Pour le backend GMP, tous les utilisateurs authentifiés ont un accès complet (pas de rôles nécessaires).

Le paramètre `deny_if_no_role` dans `config/app_settings.json` contrôle si les utilisateurs sans rôle peuvent se connecter :

```json
{ "deny_if_no_role": true }
```

## 7. Lancement

### Développement

```bash
python run.py
```

L'application est accessible sur `http://localhost:5000`.

### Production (Gunicorn)

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 "app:create_app()"
```

> **Note** : GMPilot utilise des tâches de fond en mémoire. En production, limiter à **1-2 workers** pour éviter les conflits d'état entre processus.

### Derrière un reverse proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name gmpilot.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 8. Premier démarrage

1. Se connecter avec un compte GVM (backend `gmp`) ou un compte LDAP/OIDC ayant le rôle admin
2. Aller dans **Cache** → **Tout rafraîchir (GMP)** pour peupler les caches locaux
3. Aller dans **Cache** → **Télécharger nouvelles CVE** pour enrichir les vulnérabilités
4. Consulter **Vulnérabilités** pour voir les résultats enrichis

## Structure des dossiers de cache

```
cache/
├── vulns/          # Cache XML par rapport de scan (un fichier par tâche)
├── cve/            # Cache JSON par CVE (depuis EUVD)
├── anssi/          # Cache des alertes/avis CERT-FR
│   ├── alertes/
│   └── avis/
├── kev.json        # Catalogue KEV (CISA)
└── anssi_index.json
```

Ces dossiers sont créés automatiquement au premier rafraîchissement.

---

## Mise à jour

```bash
git pull
pip install -r requirements.txt
python run.py
```

Aucune migration de base de données (pas de BDD — tout est en fichiers JSON/XML/YAML).
