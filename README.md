# GMPilot

Interface web de pilotage de **GVM / OpenVAS** via le protocole GMP (Greenbone Management Protocol).

GMPilot s'appuie sur l'écosystème [Greenbone](https://www.greenbone.net/) pour la gestion des vulnérabilités, et ajoute une couche d'interface, d'enrichissement et de priorisation contextuelle.

---

## Fonctionnalités

### Gestion des scans
- Visualisation et pilotage des tâches de scan GVM
- Démarrage, arrêt et reprise des scans
- Gestion des cibles, planifications, scanners et listes de ports

### Vulnérabilités
- Vue tabulaire avec filtres (sévérité, score, vendor/produit, exploitation active)
- Vue Synthèse par vendor/produit avec sous-tableaux triables
- Enrichissement automatique depuis [EUVD (ENISA)](https://euvd.enisa.europa.eu/) : EPSS, exploitation active, CVE détaillées
- Intégration du catalogue [KEV (CISA)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Intégration des alertes et avis [CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/)
- Export du corps de ticket GLPI (HTML + texte brut)

### Scoring contextualisé
- Moteur de scoring configurable par critères pondérés (CVSS, EPSS, KEV, ANSSI, tags hôtes, QoD)
- Éditeur visuel de configuration via `/settings/scoring`
- Formule personnalisable avec validation syntaxique AST
- Prévisualisation live sur des vulnérabilités réelles

### Système de rôles
- Contrôle d'accès granulaire (38 permissions organisées par section)
- Matching par groupes LDAP (`memberOf`) ou claims OIDC
- Union des permissions sur plusieurs rôles
- Refus de connexion configurable si aucun rôle attribué
- Interface de gestion via `/admin/roles`

### Cache local
- Cache XML par objet GVM (tâches, cibles, hôtes, planifications, etc.)
- Cache vulnérabilités par rapport de scan
- Cache CVE depuis EUVD avec cleanup automatique des CVE obsolètes
- Polling asynchrone avec mise à jour partielle du DOM

### Authentification
- **GMP** : credentials GVM directs
- **LDAP** : bind utilisateur + compte de service GVM
- **OIDC** : OpenID Connect (Keycloak, Azure AD, etc.)

---

## Stack technique

| Composant | Version |
|-----------|---------|
| Python | 3.11+ |
| Flask | 3.0.3 |
| Flask-Login | 0.6.3 |
| Flask-WTF | 1.2.1 |
| python-gvm | 24.8.0 |
| PyYAML | 6.0.1 |
| ldap3 | ≥ 2.9.0 |
| authlib | ≥ 1.3.0 |
| defusedxml | ≥ 0.7.1 |
| python-dotenv | 1.0.1 |

---

## Crédits et licences tierces

### Backend
- **[Greenbone Community Edition](https://www.greenbone.net/)** — solution de scan de vulnérabilités sur laquelle GMPilot s'appuie. GMPilot n'est pas affilié à Greenbone Networks GmbH.
- **[python-gvm](https://github.com/greenbone/python-gvm)** — client Python officiel pour le protocole GMP. Licence GPLv3.
- **[Flask](https://flask.palletsprojects.com/)** — framework web. Licence BSD.
- **[ldap3](https://github.com/cannatag/ldap3)** — client LDAP Python. Licence LGPLv3.
- **[Authlib](https://authlib.org/)** — client OIDC/OAuth2. Licence BSD.
- **[defusedxml](https://github.com/tiran/defusedxml)** — parsing XML sécurisé. Licence PSF.

### Frontend
- **[Tabler 1.4.0](https://tabler.io/)** — framework UI basé sur Bootstrap 5. Licence MIT.
- **[Tabler Icons 3.26.0](https://tabler.io/icons)** — bibliothèque d'icônes SVG. Licence MIT.
- **[Chart.js 4.4.1](https://www.chartjs.org/)** — graphiques. Licence MIT.

### Sources de données
- **[ENISA EUVD](https://euvd.enisa.europa.eu/)** — base de données européenne des vulnérabilités (CVE, EPSS, exploitation).
- **[CERT-FR / ANSSI](https://www.cert.ssi.gouv.fr/)** — alertes et avis de sécurité français.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — catalogue des vulnérabilités exploitées activement.

### Logo
- Le logo GMPilot est un tricératops recolorisé en cyan Tabler, inspiré du logo T-Rex de Greenbone.  
  Forme originale issue de [FreesSVG.org — Green Baby Dino](https://freesvg.org/green-baby-dino-vector-image) — domaine public (CC0).

---

## Structure du projet

```
GMPilot/
├── app/
│   ├── auth/                  # Backends d'auth + système de rôles
│   │   ├── backends/          # GMP, LDAP, OIDC
│   │   ├── permissions.py     # 38 permissions + décorateur @require_perm
│   │   └── roles.py           # Chargement/résolution des rôles JSON
│   ├── blueprints/            # Routes Flask par domaine
│   │   ├── admin/             # Gestion des rôles
│   │   ├── assets/            # Hôtes et tags
│   │   ├── cache/             # Gestion des caches locaux
│   │   ├── scans/             # Tâches de scan
│   │   ├── settings/          # Configuration scoring
│   │   ├── vulns/             # Vulnérabilités
│   │   └── ...
│   ├── scoring/               # Moteur de scoring contextualisé
│   ├── static/
│   │   ├── css/gmpilot.css    # Styles custom
│   │   ├── js/                # Scripts par page
│   │   └── img/logo.svg       # Logo tricératops
│   └── templates/             # Templates Jinja2
├── config/
│   ├── app_settings.json      # Paramètres globaux (deny_if_no_role)
│   ├── roles/                 # Rôles JSON (role-{id}.json)
│   └── scoring.yaml           # Configuration du scoring
├── .env                       # Variables d'environnement (non versionné)
├── .env.example               # Modèle de configuration
├── requirements.txt
└── run.py
```

---

## Licence

Voir [LICENCE.md](LICENCE.md).
