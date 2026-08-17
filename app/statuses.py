"""
statuses.py — Définitions dynamiques des statuts de findings et de leurs comportements.

Un statut = (id, libellé, icône, couleur) + 3 flags de comportement orthogonaux :
  - scope        : 'open'  → visible dans Synthèse/Brute (findings « ouverts »)
                   'closed' → basculé dans la vue Résolues (findings « fermés »)
  - sticky       : True  → statut préservé si le finding réapparaît dans un scan
                   False → réactivé en 'active' à la réapparition
  - auto_resolve : True  → passe automatiquement en 'resolved' s'il disparaît des scans
                   False → conservé tel quel même absent des scans

+ des champs custom à saisir quand on applique le statut (clé, libellé, type, obligatoire).

Les statuts INTÉGRÉS (active / in_progress / resolved) sont `fixed` : non supprimables et
leurs 3 flags sont verrouillés (leur libellé/icône/couleur/champs restent personnalisables).
Le faux positif est fourni par défaut mais entièrement éditable/supprimable.
"""
import os
import re
import json
import logging
import unicodedata

logger = logging.getLogger(__name__)


def slug(s: str) -> str:
    """Identifiant sûr (a-z 0-9 _) — garantit une injection SQL littérale sans risque.
    Translittère les accents (é→e) pour des ids lisibles."""
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9_]+", "_", s.strip().lower()).strip("_")

# id du statut de base (findings neufs / réactivés)
BASE_STATUS = "active"

# Statuts intégrés (seed). Pour les `fixed`, les flags scope/sticky/auto_resolve
# sont verrouillés (réappliqués au chargement, quoi que contienne le fichier).
_BUILTIN = [
    {"id": "active", "label": "Actif", "icon": "ti-alert-circle", "color": "secondary",
     "fixed": True, "base": True, "scope": "open", "sticky": False, "auto_resolve": True,
     "fields": []},
    {"id": "in_progress", "label": "En cours de traitement", "icon": "ti-progress", "color": "blue",
     "fixed": True, "scope": "open", "sticky": True, "auto_resolve": True,
     "fields": [{"key": "ticket_number", "label": "N° de ticket", "type": "text", "required": True}]},
    {"id": "false_positive", "label": "Faux positif", "icon": "ti-eye-off", "color": "orange",
     "fixed": False, "scope": "closed", "sticky": True, "auto_resolve": False,
     "fields": [{"key": "reason", "label": "Raison", "type": "textarea", "required": False}]},
    {"id": "resolved", "label": "Résolu", "icon": "ti-shield-check", "color": "green",
     "fixed": True, "scope": "closed", "sticky": False, "auto_resolve": False,
     "fields": []},
]

# Flags de comportement verrouillés pour les statuts intégrés `fixed`
_LOCKED = {
    "active":      {"scope": "open",   "sticky": False, "auto_resolve": True,  "base": True, "fixed": True},
    "in_progress": {"scope": "open",   "sticky": True,  "auto_resolve": True,  "fixed": True},
    "resolved":    {"scope": "closed", "sticky": False, "auto_resolve": False, "fixed": True},
}

# Ancres d'ordre : positions figées, quel que soit l'ordre stocké/soumis.
# active en 1er, in_progress en 2e, resolved en dernier ; le reste au milieu.
_ANCHOR_TOP = ["active", "in_progress"]
_ANCHOR_BOTTOM = ["resolved"]


def _canonical_order(statuses: list[dict]) -> list[dict]:
    """Réordonne en épinglant les ancres (active/in_progress en tête, resolved en fin),
    les autres statuts conservant leur ordre relatif au milieu."""
    by_id = {s["id"]: s for s in statuses}
    anchors = set(_ANCHOR_TOP) | set(_ANCHOR_BOTTOM)
    top = [by_id[i] for i in _ANCHOR_TOP if i in by_id]
    bottom = [by_id[i] for i in _ANCHOR_BOTTOM if i in by_id]
    middle = [s for s in statuses if s["id"] not in anchors]
    return top + middle + bottom

_ALLOWED_FIELD_TYPES = {"text", "textarea", "date", "number", "select", "user"}


def _path() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "config", "statuses.json")


def _normalize_field(f: dict) -> dict | None:
    key = (f.get("key") or "").strip()
    if not key:
        return None
    ftype = f.get("type") if f.get("type") in _ALLOWED_FIELD_TYPES else "text"
    out = {
        "key": key,
        "label": (f.get("label") or key).strip(),
        "type": ftype,
        "required": bool(f.get("required")),
    }
    if ftype == "select":
        opts = f.get("options") or []
        out["options"] = [str(o).strip() for o in opts if str(o).strip()]
    return out


def _normalize_status(s: dict) -> dict | None:
    sid = slug(s.get("id") or "")
    if not sid:
        return None
    scope = s.get("scope") if s.get("scope") in ("open", "closed") else "open"
    out = {
        "id": sid,
        "label": (s.get("label") or sid).strip(),
        "icon": (s.get("icon") or "ti-circle").strip(),
        "color": (s.get("color") or "secondary").strip(),
        "fixed": bool(s.get("fixed")),
        "base": bool(s.get("base")),
        "scope": scope,
        "sticky": bool(s.get("sticky")),
        "auto_resolve": bool(s.get("auto_resolve")),
        "fields": [nf for nf in (_normalize_field(f) for f in (s.get("fields") or [])) if nf],
    }
    # Verrouille les flags des statuts intégrés
    if sid in _LOCKED:
        out.update(_LOCKED[sid])
    return out


def load_statuses() -> list[dict]:
    """Retourne la liste ordonnée des définitions de statuts (intégrés garantis présents)."""
    raw = None
    p = _path()
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            logger.warning(f"[STATUSES] Lecture impossible ({e}) — seed par défaut")
    if not isinstance(raw, list):
        raw = [dict(s) for s in _BUILTIN]

    builtins_by_id = {b["id"]: b for b in _BUILTIN}
    out, seen = [], set()
    for s in raw:
        sid = slug(s.get("id") or "")
        if not sid or sid in seen:
            continue
        # Entrée partielle d'un statut intégré → hérite de ses défauts (ex. FP reste 'closed')
        if sid in builtins_by_id:
            base = dict(builtins_by_id[sid])
            base.update({k: v for k, v in s.items() if k != "id" and v is not None})
            s = base
        ns = _normalize_status(s)
        if ns:
            out.append(ns)
            seen.add(ns["id"])

    # Garantir la présence des statuts verrouillés (réinsérés depuis le seed si absents)
    for b in _BUILTIN:
        if b["id"] in _LOCKED and b["id"] not in seen:
            out.append(_normalize_status(dict(b)))
            seen.add(b["id"])
    return _canonical_order(out)


def save_statuses(statuses: list[dict]) -> bool:
    """Persiste les définitions (après normalisation + garantie des intégrés)."""
    norm, seen = [], set()
    for s in statuses:
        ns = _normalize_status(s)
        if ns and ns["id"] not in seen:
            norm.append(ns)
            seen.add(ns["id"])
    for b in _BUILTIN:
        if b["id"] in _LOCKED and b["id"] not in seen:
            norm.append(_normalize_status(dict(b)))
            seen.add(b["id"])
    norm = _canonical_order(norm)
    try:
        p = _path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(norm, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"[STATUSES] Sauvegarde impossible: {e}")
        return False


def statuses_by_id() -> dict:
    return {s["id"]: s for s in load_statuses()}


def get_status(sid: str) -> dict | None:
    return statuses_by_id().get(sid)


# ── Classifieurs par comportement (utilisés par les requêtes / l'import) ──────
def open_status_ids() -> list[str]:
    return [s["id"] for s in load_statuses() if s["scope"] == "open"]


def closed_status_ids() -> list[str]:
    return [s["id"] for s in load_statuses() if s["scope"] == "closed"]


def sticky_status_ids() -> list[str]:
    return [s["id"] for s in load_statuses() if s["sticky"]]


def auto_resolve_status_ids() -> list[str]:
    return [s["id"] for s in load_statuses() if s["auto_resolve"]]
