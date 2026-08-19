"""Tests de _parse_cpe_product (parsing d'un produit CPE de l'API NVD)."""
from app.blueprints.cache import _parse_cpe_product


def test_produit_complet():
    p = {"cpe": {"cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                 "titles": [{"lang": "fr", "title": "Widget FR"}, {"lang": "en", "title": "Acme Widget"}],
                 "created": "2020-01-01", "lastModified": "2021-02-02"}}
    assert _parse_cpe_product(p) == (
        "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        "a", "acme", "widget", "1.0", "", "Acme Widget", "2020-01-01", "2021-02-02")


def test_version_et_update_wildcard_vidés():
    p = {"cpe": {"cpeName": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "titles": []}}
    t = _parse_cpe_product(p)
    assert t[4] == ""   # version *
    assert t[5] == ""   # update *


def test_update_non_wildcard_conservé():
    p = {"cpe": {"cpeName": "cpe:2.3:a:v:p:1.0:sp1:*:*:*:*:*:*", "titles": []}}
    assert _parse_cpe_product(p)[5] == "sp1"


def test_nom_invalide_renvoie_none():
    assert _parse_cpe_product({"cpe": {"cpeName": "cpe:2.3:a"}}) is None


def test_titre_fallback_premier_si_pas_anglais():
    p = {"cpe": {"cpeName": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", "titles": [{"lang": "fr", "title": "FR only"}]}}
    assert _parse_cpe_product(p)[6] == "FR only"
