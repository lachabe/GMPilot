"""Tests de caractérisation de _group_by_vendor_product (vue Vulnérabilités).

Fonction pure : liste de vulns enrichies + cache ANSSI → arborescence
vendor → produit (+ groupe « Non classifié » pour les vulns sans vendor EUVD).
Verrouille le comportement avant refactor.
"""

from app.blueprints.vulns import _group_by_vendor_product


def _by_vendor(groups):
    return {g["vendor"]: g for g in groups}


def _by_product(group):
    return {p["product"]: p for p in group["products"]}


class TestGrouping:
    def test_arborescence_et_tri(self):
        results = [
            {"euvd_vendor": "Acme", "euvd_product": "Widget", "severity": 7.0,
             "ctx_score": 50, "host": "10.0.0.1", "port": "443/tcp",
             "all_cves": ["CVE-1"], "solution": "patch A", "euvd_exploited": 1},
            {"euvd_vendor": "Acme", "euvd_product": "Widget", "severity": 9.0,
             "ctx_score": 80, "host": "10.0.0.2", "port": "80/tcp",
             "cve": "CVE-2", "solution": "patch B"},
            {"euvd_vendor": "Acme", "euvd_product": "Gadget", "severity": 5.0, "host": "10.0.0.1"},
            {"euvd_vendor": "Beta", "euvd_product": "Thing", "severity": 3.0},
        ]
        anssi = {"CVE-1": {"type": "alerte", "ref": "CERTFR-1", "url": "http://x"}}
        groups = _group_by_vendor_product(results, anssi)

        # tri vendors par sévérité max desc
        assert [g["vendor"] for g in groups] == ["Acme", "Beta"]
        acme = _by_vendor(groups)["Acme"]
        assert acme["total_vulns"] == 3
        assert acme["max_severity"] == 9.0
        assert acme["exploited_count"] == 1
        # tri produits par sévérité max desc (produits normalisés en minuscules)
        assert [p["product"] for p in acme["products"]] == ["widget", "gadget"]

        widget = _by_product(acme)["widget"]
        assert len(widget["vulns"]) == 2
        assert widget["all_cves"] == ["CVE-1", "CVE-2"]          # union all_cves + cve, trié
        assert widget["hosts_ports"] == ["10.0.0.1:443/tcp", "10.0.0.2:80/tcp"]
        assert sorted(widget["solutions"]) == ["patch A", "patch B"]
        assert widget["max_score"] == 80
        assert widget["exploited_count"] == 1
        assert widget["anssi_refs"] == ["ALERTE|CERTFR-1|http://x"]

        gadget = _by_product(acme)["gadget"]
        assert gadget["hosts_ports"] == ["10.0.0.1"]              # host sans port
        assert gadget["all_cves"] == []

    def test_non_classifie_par_nvt(self):
        results = [
            {"euvd_vendor": "", "nvt_name": "OpenSSH faible", "severity": 6.0,
             "host": "10.0.0.9", "all_cves": ["CVE-9"]},
            {"euvd_vendor": "", "nvt_name": "OpenSSH faible", "severity": 4.0, "host": "10.0.0.10"},
            {"euvd_vendor": "", "name": "TLS obsolète", "severity": 2.0},
        ]
        groups = _group_by_vendor_product(results, {})
        assert len(groups) == 1
        nc = groups[0]
        assert nc["vendor"] == "Non classifié"
        assert nc["unclassified"] is True
        assert nc["total_vulns"] == 3
        prods = _by_product(nc)
        # regroupé par nvt_name / name
        assert "OpenSSH faible" in prods and "TLS obsolète" in prods
        assert prods["OpenSSH faible"]["nvt_group"] is True
        assert len(prods["OpenSSH faible"]["vulns"]) == 2
        assert prods["OpenSSH faible"]["max_severity"] == 6.0

    def test_mix_classifie_et_non(self):
        results = [
            {"euvd_vendor": "Acme", "euvd_product": "W", "severity": 8.0},
            {"euvd_vendor": "", "nvt_name": "X", "severity": 1.0},
        ]
        groups = _group_by_vendor_product(results, {})
        vendors = [g["vendor"] for g in groups]
        assert "Acme" in vendors and "Non classifié" in vendors

    def test_vide(self):
        assert _group_by_vendor_product([], {}) == []
