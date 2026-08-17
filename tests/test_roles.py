"""Tests de app.auth.roles : sécurité des chemins, CRUD rôles, résolution de
permissions, et app_settings. Les chemins fichiers sont isolés en tmp.
"""
import json
import types

import pytest

from app.auth import roles as R


@pytest.fixture
def iso_roles(tmp_path, monkeypatch):
    """Isole config/roles/ et config/app_settings.json dans des tmp."""
    roles_dir = tmp_path / "roles"
    roles_dir.mkdir()
    monkeypatch.setattr(R, "_roles_dir", lambda: str(roles_dir))
    monkeypatch.setattr(R, "_app_settings_path", lambda: str(tmp_path / "app_settings.json"))
    return roles_dir


class TestSafeRolePath:
    def test_id_valide(self, iso_roles):
        p = R._safe_role_path("admin")
        assert p is not None and p.endswith("role-admin.json")

    @pytest.mark.parametrize("bad", ["../evil", "a/b", "..", "", "a b", "rôle", "a.b", "/etc/passwd"])
    def test_ids_dangereux_rejetes(self, iso_roles, bad):
        assert R._safe_role_path(bad) is None


class TestRoleCrud:
    def test_roundtrip(self, iso_roles):
        role = {"id": "ops", "name": "Ops", "permissions": {"vulns.read": True}}
        assert R.save_role(role) is True
        loaded = R.get_role("ops")
        assert loaded["name"] == "Ops"
        assert loaded["permissions"]["vulns.read"] is True
        assert R.delete_role("ops") is True
        assert R.get_role("ops") is None

    def test_save_id_invalide_echoue(self, iso_roles):
        assert R.save_role({"id": "../x"}) is False

    def test_delete_absent(self, iso_roles):
        assert R.delete_role("inexistant") is False

    def test_load_all_roles(self, iso_roles):
        R.save_role({"id": "a", "permissions": {}})
        R.save_role({"id": "b", "permissions": {}})
        ids = {r["id"] for r in R.load_all_roles()}
        assert ids == {"a", "b"}


class TestResolvePermissions:
    def test_gmp_admin_total(self, iso_roles):
        perms, matched = R.resolve_permissions(types.SimpleNamespace(groups=[]), "gmp")
        assert matched is True
        assert all(perms.values())

    def test_ldap_groupe_matche(self, iso_roles):
        R.save_role({"id": "ops", "permissions": {"vulns.read": True},
                     "matching": {"ldap": {"enabled": True, "groups": ["CN=Ops"]}}})
        user = types.SimpleNamespace(groups=["CN=Ops"], username="u")
        perms, matched = R.resolve_permissions(user, "ldap")
        assert matched is True
        assert perms["vulns.read"] is True

    def test_ldap_aucun_groupe(self, iso_roles):
        R.save_role({"id": "ops", "permissions": {"vulns.read": True},
                     "matching": {"ldap": {"enabled": True, "groups": ["CN=Ops"]}}})
        user = types.SimpleNamespace(groups=["CN=Autre"], username="u")
        perms, matched = R.resolve_permissions(user, "ldap")
        assert matched is False
        assert perms["vulns.read"] is False

    def test_ldap_role_desactive_ignore(self, iso_roles):
        R.save_role({"id": "ops", "permissions": {"vulns.read": True},
                     "matching": {"ldap": {"enabled": False, "groups": ["CN=Ops"]}}})
        user = types.SimpleNamespace(groups=["CN=Ops"], username="u")
        _, matched = R.resolve_permissions(user, "ldap")
        assert matched is False


class TestAppSettings:
    def test_defauts_sans_fichier(self, iso_roles):
        s = R.app_settings()
        assert s["deny_if_no_role"] is True
        assert s["remediation_warn_days"] == 30

    def test_roundtrip_merge_defauts(self, iso_roles):
        assert R.save_app_settings({"ticket_url": "http://glpi/x", "remediation_warn_days": 45}) is True
        s = R.app_settings()
        assert s["ticket_url"] == "http://glpi/x"
        assert s["remediation_warn_days"] == 45
        assert s["deny_if_no_role"] is True   # défaut conservé
