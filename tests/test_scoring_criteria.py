"""Tests de app.scoring : génération de formule et valeur par critère.

_get_criterion_value est le cœur du scoring contextualisé : pour chaque source
(severity/epss/qod/kev/anssi/host_tag) il renvoie une valeur normalisée dans [0,1].
"""
import pytest

from app.scoring import generate_formula_from_criteria, _get_criterion_value


class TestGenerateFormula:
    def test_vide(self):
        assert generate_formula_from_criteria([]) == "0"

    def test_ponderation(self):
        f = generate_formula_from_criteria([
            {"id": "sev", "weight": 3},
            {"id": "kev", "weight": 1},
        ])
        assert "/ 4 * 100" in f          # total_weight = 3 + 1
        assert "sev" in f and "kev" in f

    def test_poids_total_nul(self):
        assert generate_formula_from_criteria([{"id": "x", "weight": 0}]) == "0"


class TestCriterionSeverity:
    def test_scale_0_1(self):
        crit = {"source": "severity", "normalize": "scale_0_1"}
        assert _get_criterion_value(crit, {"severity": 7.5}, [], {}, {}) == 0.75
        # bornage
        assert _get_criterion_value(crit, {"severity": 15}, [], {}, {}) == 1.0

    def test_threshold(self):
        crit = {"source": "severity", "normalize": "threshold", "values": [
            {"threshold": 9.0, "value": 1.0},
            {"threshold": 7.0, "value": 0.6},
            {"default": 0.1},
        ]}
        assert _get_criterion_value(crit, {"severity": 9.5}, [], {}, {}) == 1.0
        assert _get_criterion_value(crit, {"severity": 7.2}, [], {}, {}) == 0.6
        assert _get_criterion_value(crit, {"severity": 3.0}, [], {}, {}) == 0.1


class TestCriterionEpss:
    def test_absent_renvoie_defaut(self):
        crit = {"source": "epss", "normalize": "scale_0_1", "values": [{"default": 0.2}]}
        assert _get_criterion_value(crit, {}, [], {}, {}) == 0.2

    def test_valeur(self):
        crit = {"source": "epss", "normalize": "scale_0_1"}
        assert _get_criterion_value(crit, {"euvd_epss": 0.42}, [], {}, {}) == pytest.approx(0.42)


class TestCriterionQod:
    def test_pourcentage_texte(self):
        crit = {"source": "qod", "normalize": "scale_0_1"}
        assert _get_criterion_value(crit, {"qod": "80%"}, [], {}, {}) == 0.8
        assert _get_criterion_value(crit, {"qod": 70}, [], {}, {}) == 0.7


class TestCriterionKev:
    def test_present(self):
        crit = {"source": "kev", "values": [{"match": True, "value": 1.0}, {"match": False, "value": 0.0}]}
        vuln = {"all_cves": ["CVE-2024-0001"]}
        assert _get_criterion_value(crit, vuln, [], {"CVE-2024-0001": {}}, {}) == 1.0

    def test_absent(self):
        crit = {"source": "kev", "values": [{"match": True, "value": 1.0}, {"match": False, "value": 0.0}]}
        vuln = {"all_cves": ["CVE-2024-9999"]}
        assert _get_criterion_value(crit, vuln, [], {"CVE-2024-0001": {}}, {}) == 0.0


class TestCriterionAnssi:
    def test_alerte_prioritaire_sur_avis(self):
        crit = {"source": "anssi", "values": [
            {"match": "alerte", "value": 1.0}, {"match": "avis", "value": 0.5}, {"default": 0.0}]}
        vuln = {"all_cves": ["CVE-A", "CVE-B"]}
        anssi = {"CVE-A": {"type": "avis"}, "CVE-B": {"type": "alerte"}}
        assert _get_criterion_value(crit, vuln, [], {}, anssi) == 1.0

    def test_aucun_match(self):
        crit = {"source": "anssi", "values": [{"match": "alerte", "value": 1.0}, {"default": 0.3}]}
        assert _get_criterion_value(crit, {"all_cves": ["CVE-X"]}, [], {}, {}) == 0.3


class TestCriterionHostTag:
    def test_tag_present(self):
        crit = {"source": "host_tag", "tag_name": "exposed",
                "values": [{"match": True, "value": 1.0}, {"match": False, "value": 0.0}]}
        assert _get_criterion_value(crit, {}, ["exposed"], {}, {}) == 1.0
        assert _get_criterion_value(crit, {}, ["internal"], {}, {}) == 0.0


def test_source_inconnue_renvoie_defaut():
    crit = {"source": "bidon", "values": [{"default": 0.9}]}
    assert _get_criterion_value(crit, {}, [], {}, {}) == 0.9
