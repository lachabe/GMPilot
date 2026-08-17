"""Tests de app.statuses — module central des statuts dynamiques.

Couvre : slug (sûreté d'injection SQL), ordre canonique des ancres, normalisation
+ verrouillage des statuts intégrés, roundtrip load/save, classifieurs.
"""
import json

from app import statuses as st


# ── slug : identifiant sûr pour injection littérale ────────────────────────────
class TestSlug:
    def test_translittere_accents(self):
        assert st.slug("Mitigé") == "mitige"
        assert st.slug("Faux positif") == "faux_positif"

    def test_minuscule_et_espaces(self):
        assert st.slug("En Cours") == "en_cours"

    def test_supprime_caracteres_dangereux(self):
        # Toute tentative d'injection doit se réduire à [a-z0-9_].
        dangereux = st.slug("'; DROP TABLE findings;--")
        assert "'" not in dangereux
        assert ";" not in dangereux
        assert " " not in dangereux
        assert all(c.islower() or c.isdigit() or c == "_" for c in dangereux)

    def test_vide(self):
        assert st.slug("") == ""
        assert st.slug(None) == ""


# ── ordre canonique : ancres épinglées ─────────────────────────────────────────
class TestCanonicalOrder:
    def test_ancres_epinglees_milieu_preserve(self):
        mixed = [
            {"id": "resolved"}, {"id": "mitige"}, {"id": "active"},
            {"id": "false_positive"}, {"id": "in_progress"}, {"id": "accepte"},
        ]
        out = [s["id"] for s in st._canonical_order(mixed)]
        assert out[0] == "active"
        assert out[1] == "in_progress"
        assert out[-1] == "resolved"
        # ordre relatif du milieu conservé tel que soumis
        assert out[2:-1] == ["mitige", "false_positive", "accepte"]

    def test_ancre_manquante_geree(self):
        out = [s["id"] for s in st._canonical_order([{"id": "foo"}, {"id": "active"}])]
        assert out == ["active", "foo"]


# ── normalisation + verrouillage des statuts intégrés ──────────────────────────
class TestNormalisation:
    def test_champ_sans_cle_ignore(self):
        s = st._normalize_status({"id": "x", "fields": [{"label": "vide"}, {"key": "k", "label": "K"}]})
        assert [f["key"] for f in s["fields"]] == ["k"]

    def test_options_uniquement_pour_select(self):
        s = st._normalize_status({"id": "x", "fields": [
            {"key": "sel", "type": "select", "options": ["a", "", "b"]},
            {"key": "txt", "type": "text", "options": ["z"]},
        ]})
        sel, txt = s["fields"]
        assert sel["options"] == ["a", "b"]          # vides filtrés
        assert "options" not in txt                   # pas d'options hors select

    def test_flags_verrouilles_pour_in_progress(self):
        # Le fichier tente de rendre in_progress 'closed' → doit rester 'open'.
        s = st._normalize_status({"id": "in_progress", "scope": "closed", "sticky": False})
        assert s["scope"] == "open"
        assert s["sticky"] is True
        assert s["fixed"] is True

    def test_type_inconnu_devient_text(self):
        s = st._normalize_status({"id": "x", "fields": [{"key": "k", "type": "wtf"}]})
        assert s["fields"][0]["type"] == "text"


# ── load/save (isolés via fixture iso_statuses) ────────────────────────────────
class TestLoadSave:
    def test_defauts_sans_fichier(self, iso_statuses):
        ids = [s["id"] for s in st.load_statuses()]
        for builtin in ("active", "in_progress", "false_positive", "resolved"):
            assert builtin in ids
        # ancres correctement placées
        assert ids[0] == "active" and ids[1] == "in_progress" and ids[-1] == "resolved"

    def test_roundtrip_statut_custom(self, iso_statuses):
        custom = {"id": "mitige", "label": "Mitigé", "icon": "ti-shield", "color": "teal",
                  "scope": "open", "sticky": True, "auto_resolve": False,
                  "fields": [{"key": "note", "label": "Note", "type": "textarea"}]}
        assert st.save_statuses([custom]) is True
        loaded = st.statuses_by_id()
        assert "mitige" in loaded
        assert loaded["mitige"]["label"] == "Mitigé"
        assert loaded["mitige"]["fields"][0]["key"] == "note"
        # les intégrés verrouillés sont réinjectés même absents du fichier
        for builtin in ("active", "in_progress", "resolved"):
            assert builtin in loaded

    def test_entree_partielle_integre_herite_defauts(self, iso_statuses):
        # false_positive donné partiellement (sans scope) → doit rester 'closed'.
        iso_statuses.write_text(json.dumps([{"id": "false_positive", "label": "FP"}]), encoding="utf-8")
        fp = st.get_status("false_positive")
        assert fp["scope"] == "closed"
        assert fp["sticky"] is True

    def test_save_deduplique(self, iso_statuses):
        st.save_statuses([{"id": "dup"}, {"id": "dup", "label": "second"}])
        ids = [s["id"] for s in st.load_statuses()]
        assert ids.count("dup") == 1


# ── classifieurs de comportement ───────────────────────────────────────────────
class TestClassifieurs:
    def test_defauts(self, iso_statuses):
        assert set(st.open_status_ids()) == {"active", "in_progress"}
        assert set(st.closed_status_ids()) == {"false_positive", "resolved"}
        assert set(st.sticky_status_ids()) == {"in_progress", "false_positive"}
        assert set(st.auto_resolve_status_ids()) == {"active", "in_progress"}

    def test_statut_custom_classe(self, iso_statuses):
        st.save_statuses([{"id": "accepte", "scope": "closed", "sticky": True, "auto_resolve": False}])
        assert "accepte" in st.closed_status_ids()
        assert "accepte" in st.sticky_status_ids()
        assert "accepte" not in st.auto_resolve_status_ids()
