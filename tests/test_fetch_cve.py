"""Tests de caractérisation de fetch_cve_from_euvd (EUVD + fallback MITRE).

`_api_get_json` (HTTP) est mocké → on teste le dispatch EUVD/MITRE et le parsing
de la réponse MITRE sans réseau.
"""
import pytest

from app.blueprints.cache import fetch_cve_from_euvd


@pytest.fixture
def mock_api(monkeypatch):
    import app.blueprints.cache as C

    def _apply(euvd=(None, None), mitre=(None, None)):
        def fake(url, label="", throttle=True):
            return mitre if "cveawg.mitre.org" in url else euvd
        monkeypatch.setattr(C, "_api_get_json", fake)
    return _apply


class TestFetch:
    def test_euvd_hit(self, mock_api):
        mock_api(euvd=({"id": "EUVD-1", "_source": "euvd"}, None))
        data, err = fetch_cve_from_euvd("cve-2024-0001")
        assert err is None
        assert data == {"id": "EUVD-1", "_source": "euvd"}

    def test_mitre_fallback_published(self, mock_api):
        raw = {
            "cveMetadata": {"state": "PUBLISHED", "datePublished": "2024-01-01"},
            "containers": {"cna": {
                "descriptions": [{"lang": "fr", "value": "desc fr"}, {"lang": "en", "value": "desc en"}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.1, "vectorString": "AV:N"}}],
            }},
        }
        mock_api(euvd=(None, "miss"), mitre=(raw, None))
        data, err = fetch_cve_from_euvd("CVE-2024-0002")
        assert err is None
        assert data["id"] == "CVE-2024-0002"
        assert data["description"] == "desc en"        # préfère l'anglais
        assert data["baseScore"] == 9.1
        assert data["baseScoreVector"] == "AV:N"
        assert data["_source"] == "mitre"
        assert data["_state"] == "PUBLISHED"
        assert data["datePublished"] == "2024-01-01"

    def test_mitre_sans_anglais_prend_le_premier(self, mock_api):
        raw = {"cveMetadata": {"state": "PUBLISHED"},
               "containers": {"cna": {"descriptions": [{"lang": "fr", "value": "seulement fr"}]}}}
        mock_api(euvd=(None, "m"), mitre=(raw, None))
        data, _ = fetch_cve_from_euvd("CVE-2024-0005")
        assert data["description"] == "seulement fr"
        assert data["baseScore"] is None

    def test_mitre_non_published(self, mock_api):
        mock_api(euvd=(None, "m"), mitre=({"cveMetadata": {"state": "REJECTED"}}, None))
        data, err = fetch_cve_from_euvd("CVE-2024-0004")
        assert err is None
        assert data["description"] == "CVE REJECTED"
        assert data["baseScore"] is None

    def test_les_deux_echouent(self, mock_api):
        mock_api(euvd=(None, "euvd-err"), mitre=(None, "mitre-err"))
        data, err = fetch_cve_from_euvd("CVE-2024-0003")
        assert data is None
        assert "mitre-err" in err
