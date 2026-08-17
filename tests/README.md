# Tests GMPilot

Suite de tests unitaires — le **filet de régression** à enrichir à chaque nouvelle
implémentation.

## Lancer

```bash
.venv/bin/python -m pytest            # toute la suite
.venv/bin/python -m pytest tests/test_statuses.py -v
```

(Installer les deps de dev : `pip install -r requirements-dev.txt`.)

## Principes

Les tests ciblent la **logique pure** et les fonctions qui prennent une connexion
explicite. On évite volontairement :

- de booter Flask (l'import de `app.config` déclenche `load_dotenv` → lit le `.env`) ;
- toute dépendance à GVM, au réseau, ou au vrai `cache/gmpilot.db`.

Concrètement, on teste des modules importables sans config : `app.statuses`,
`app.scoring`, et les fonctions de `app.db` qui reçoivent une connexion en argument
(ex. `set_findings_status`, `_migrate_schema`).

## Fixtures partagées (`conftest.py`)

| Fixture | Rôle |
|---|---|
| `mem_db` | Connexion SQLite en mémoire avec le schéma réel (`SCHEMA_SQL`). |
| `insert_finding` | Insère un finding minimal, renvoie son id. |
| `iso_statuses` | Isole `config/statuses.json` dans un fichier temporaire. |

## Ajouter des tests

Déposer `tests/test_<domaine>.py`, réutiliser les fixtures ci-dessus. Pour tester
une fonction touchant la BDD, la faire prendre une `conn` en argument (ou passer
`mem_db`) plutôt que d'appeler `get_db()` (qui exige un contexte Flask).

## Fichiers actuels

- `test_statuses.py` — slug (sûreté SQL), ordre canonique, normalisation,
  load/save, classifieurs de comportement.
- `test_db_status.py` — `set_findings_status` (fusion/report de valeurs entre
  statuts, reset du statut de base) + helpers `IN (...)`.
- `test_db_migration.py` — `_migrate_schema` (ajout de colonnes + reprise des
  anciens champs FP/traitement, idempotence).
- `test_scoring.py` — `_safe_eval` (calcul autorisé + rejet d'injection de code).
