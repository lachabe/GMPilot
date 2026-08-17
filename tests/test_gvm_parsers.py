"""Tests des helpers/parseurs purs de app.gvm_client (XML GMP → dict/list)."""
import xml.etree.ElementTree as ET

import pytest

from app.gvm_client import (
    _text, _attr, _safe_float, _parse_tags_str,
    build_filter, parse_pagination, parse_tasks, parse_results,
)


class TestHelpers:
    def test_safe_float(self):
        assert _safe_float("3.5") == 3.5
        assert _safe_float(None) == 0.0
        assert _safe_float("pas un nombre") == 0.0
        assert _safe_float("inf") == 0.0          # infini rejeté → défaut
        assert _safe_float("x", default=1.0) == 1.0

    def test_text_et_attr(self):
        el = ET.fromstring('<root><name>bob</name><nvt oid="1.2.3"/></root>')
        assert _text(el, "name") == "bob"
        assert _text(el, "absent") == ""
        assert _attr(el, "nvt", "oid") == "1.2.3"
        assert _attr(el, "absent", "oid") == ""

    def test_parse_tags_str(self):
        assert _parse_tags_str("k1=v1|k2=v2") == {"k1": "v1", "k2": "v2"}
        assert _parse_tags_str("") == {}
        assert _parse_tags_str("sanségal") == {}


class TestBuildFilter:
    def test_pagination_de_base(self):
        assert build_filter(page=1, per_page=50) == "rows=50 first=1"
        assert build_filter(page=3, per_page=20) == "rows=20 first=41"

    def test_tri_desc_et_extra(self):
        f = build_filter(extra="name~foo", page=1, per_page=10, sort_field="severity", sort_order="desc")
        assert "rows=10" in f and "first=1" in f
        assert "sort~=severity" in f
        assert "name~foo" in f

    def test_tri_asc(self):
        f = build_filter(sort_field="name", sort_order="asc")
        assert "sort=name" in f            # pas de ~ en ascendant


class TestParsePagination:
    def test_calcul_pages(self):
        xml = ET.fromstring('<root filtered="120" full="200" start="41" max="20"/>')
        p = parse_pagination(xml)
        assert p["total"] == 120
        assert p["total_all"] == 200
        assert p["per_page"] == 20
        assert p["page"] == 3                # start 41, max 20 → page 3
        assert p["total_pages"] == 6         # ceil(120/20)
        assert p["has_prev"] is True
        assert p["has_next"] is True

    def test_page_unique(self):
        xml = ET.fromstring('<root filtered="5" start="1" max="50"/>')
        p = parse_pagination(xml)
        assert p["page"] == 1 and p["total_pages"] == 1
        assert p["has_prev"] is False and p["has_next"] is False


class TestParseResults:
    def _xml(self):
        return ET.fromstring("""
        <results>
          <result id="r1">
            <severity>9.5</severity><host>10.0.0.1</host><port>443/tcp</port>
            <threat>Critical</threat><nvt><name>NVT haut</name></nvt>
            <refs><ref type="cve" id="CVE-2024-0001"/></refs>
          </result>
          <result id="r2">
            <severity>2.0</severity><host>10.0.0.2</host><port>80/tcp</port>
            <threat>Low</threat><nvt><name>NVT bas</name></nvt>
          </result>
        </results>""")

    def test_filtre_min_severity(self):
        res = parse_results(self._xml(), min_severity=5.0)
        assert len(res) == 1
        assert res[0]["id"] == "r1"

    def test_tri_desc_et_cve(self):
        res = parse_results(self._xml(), min_severity=0.0)
        assert [r["id"] for r in res] == ["r1", "r2"]   # trié par sévérité desc
        assert res[0]["cve"] == "CVE-2024-0001"
        assert res[1]["cve"] == "—"                       # pas de ref CVE


class TestParseTasks:
    def test_extraction(self):
        xml = ET.fromstring("""
        <tasks>
          <task id="t1"><name>Scan hebdo</name><status>Done</status>
            <progress>100</progress></task>
        </tasks>""")
        tasks = parse_tasks(xml)
        assert len(tasks) == 1
        assert tasks[0]["id"] == "t1"
        assert tasks[0]["name"] == "Scan hebdo"
        assert tasks[0]["status"] == "Done"
