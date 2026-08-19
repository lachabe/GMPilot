"""Tests de caractérisation de enrich_vuln_with_euvd.

Les deux accès cache (read_cve_cache / read_kev_cache) sont mockés → fonction
testable sans disque. Verrouille le comportement avant refactor.
"""
import pytest

from app.blueprints.cache import enrich_vuln_with_euvd


@pytest.fixture
def patch_cache(monkeypatch):
    """Retourne un configurateur (cve_map, kev) → patche les deux caches."""
    import app.blueprints.cache as C

    def _apply(cve_map=None, kev=None):
        monkeypatch.setattr(C, "read_cve_cache", lambda c: (cve_map or {}).get(c))
        monkeypatch.setattr(C, "read_kev_cache", lambda: (kev or {}))
    return _apply


class TestEnrich:
    def test_sans_cve(self, patch_cache):
        patch_cache()
        v = enrich_vuln_with_euvd({"cve": "—"})
        assert v["all_cves"] == []
        assert v["euvd_vendor"] == "—"
        assert v["euvd_data"] is None
        assert v["euvd_exploited"] is False

    def test_cve_non_cachee(self, patch_cache):
        patch_cache(cve_map={})  # read_cve_cache renvoie None
        v = enrich_vuln_with_euvd({"cve": "CVE-2024-0001"})
        assert v["all_cves"] == ["CVE-2024-0001"]
        assert v["euvd_data"] is None
        assert v["cve"] == "CVE-2024-0001"
        assert v["euvd_url"].endswith("/CVE-2024-0001")

    def test_enrichissement_complet(self, patch_cache):
        euvd = {
            "id": "EUVD-1", "epss": 0.42, "exploitedSince": "2024-01-01",
            "enisaIdVendor": [{"vendor": {"name": "acme"}}],
            "enisaIdProduct": [{"product": {"name": "widget"}, "product_version": "1.2"}],
            "baseScore": 9.1, "references": "http://a\nhttp://b",
        }
        patch_cache(cve_map={"CVE-2024-0001": euvd})
        v = enrich_vuln_with_euvd({"cves": ["CVE-2024-0001"]})
        assert v["euvd_vendor"] == "Acme"           # title case
        assert v["euvd_product"] == "Widget"
        assert v["euvd_product_version"] == "1.2"
        assert v["euvd_epss"] == 0.42
        assert v["euvd_exploited"] is True
        assert v["euvd_exploited_since"] == "2024-01-01"
        assert v["euvd_references"] == ["http://a", "http://b"]
        assert v["euvd_data"] == euvd

    def test_epss_pourcentage_normalise(self, patch_cache):
        patch_cache(cve_map={"CVE-2024-0002": {"epss": 42}})
        v = enrich_vuln_with_euvd({"cve": "CVE-2024-0002"})
        assert v["euvd_epss"] == 0.42

    def test_exploite_via_kev(self, patch_cache):
        patch_cache(cve_map={"CVE-2024-0003": {"id": "x"}},
                    kev={"CVE-2024-0003": {"dateAdded": "2023-05-05"}})
        v = enrich_vuln_with_euvd({"cve": "CVE-2024-0003"})
        assert v["euvd_exploited"] is True
        assert v["euvd_exploited_since"] == "2023-05-05"

    def test_vendor_vide_normalise(self, patch_cache):
        patch_cache(cve_map={"CVE-2024-0004": {"enisaIdVendor": [{"vendor": {"name": "n/a"}}]}})
        v = enrich_vuln_with_euvd({"cve": "CVE-2024-0004"})
        assert v["euvd_vendor"] == "—"
