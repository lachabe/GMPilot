"""Tests de caractérisation de _parse_for_cache (XML GMP → liste de dicts JSON).

Couvre les parsers inline (feeds/scanners/schedules) + le dispatch et la clé
inconnue. Verrouille le comportement avant refactor.
"""
import xml.etree.ElementTree as ET

from app.blueprints.cache import _parse_for_cache


def _x(s):
    return ET.fromstring(s)


class TestParseForCache:
    def test_feeds(self):
        out = _parse_for_cache("feeds", _x(
            "<r><feed><type>NVT</type><name>Greenbone</name><version>202601</version>"
            "<description>d</description><currently_syncing/></feed></r>"))
        assert out == [{"type": "NVT", "name": "Greenbone", "version": "202601",
                        "description": "d", "syncing": True}]

    def test_feeds_defauts(self):
        out = _parse_for_cache("feeds", _x("<r><feed><name>F</name></feed></r>"))
        assert out[0]["type"] == "—"
        assert out[0]["syncing"] is False

    def test_scanners_type_mappe(self):
        out = _parse_for_cache("scanners", _x(
            '<r><scanner id="s1"><name>OpenVAS</name><host>local</host><port>9390</port>'
            "<type>2</type><comment>c</comment></scanner></r>"))
        assert out == [{"id": "s1", "name": "OpenVAS", "host": "local", "port": "9390",
                        "type": "OpenVAS", "comment": "c"}]

    def test_scanners_type_inconnu_passe_tel_quel(self):
        out = _parse_for_cache("scanners", _x('<r><scanner id="s2"><type>99</type></scanner></r>'))
        assert out[0]["type"] == "99"
        assert out[0]["host"] == "local"

    def test_schedules_ical(self):
        ical = "BEGIN:VEVENT\nDTSTART:20260115T093000Z\nRRULE:FREQ=WEEKLY\nEND:VEVENT"
        out = _parse_for_cache("schedules", _x(
            f'<r><schedule id="sc1"><name>Hebdo</name><timezone>UTC</timezone>'
            f"<tasks><count>3</count></tasks><icalendar>{ical}</icalendar></schedule></r>"))
        assert out[0]["next_time"] == "2026-01-15 09:30 UTC"
        assert out[0]["frequency"] == "Hebdomadaire"
        assert out[0]["tasks"] == "3"

    def test_schedules_sans_ical(self):
        out = _parse_for_cache("schedules", _x('<r><schedule id="sc2"><name>N</name></schedule></r>'))
        assert out[0]["next_time"] == "—"
        assert out[0]["frequency"] == "Unique"

    def test_cle_inconnue(self):
        assert _parse_for_cache("bidon", _x("<r/>")) == []

    def test_dispatch_tasks(self):
        out = _parse_for_cache("tasks", _x('<r><task id="t1"><name>T</name><status>Done</status></task></r>'))
        assert out[0]["id"] == "t1"
