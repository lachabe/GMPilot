"""Tests de caractérisation de _version_in_range_raw (matching de version EUVD).

Verrouille le comportement OBSERVÉ (source de vérité) avant/après refactor. Ce
n'est PAS une spec idéale : on fige l'existant pour garantir un refactor sans
régression.

Note : ('0.3.1', '< 0.3.2') → NOT_AFFECTED est le comportement actuel — le
format « < X » espacé (2 tokens) est interprété comme version exacte. Caractérisé
tel quel, non « corrigé » (ce serait un changement de comportement à part).
"""
import pytest

from app.blueprints.cache import (
    _version_in_range_raw,
    MATCH_AFFECTED as A,
    MATCH_NOT_AFFECTED as N,
    MATCH_UNKNOWN as U,
)

CASES = [
    # exact
    (A, "4.1.0", "4.1.0"),
    (N, "4.1.1", "4.1.0"),
    # deux tokens "LOW <HIGH" / "LOW <=HIGH"
    (A, "26.2.46", "0 <26.2.47"),
    (N, "26.2.47", "0 <26.2.47"),
    (A, "9.0.5400.0", "9.0 ≤9.0.5400.0"),
    (N, "9.0.5400.1", "9.0 ≤9.0.5400.0"),
    # "< X" espacé → traité comme exact (comportement actuel)
    (N, "0.3.1", "< 0.3.2"),
    (A, "0.3.2", "< 0.3.2"),
    # virgule : bornes ET
    (A, "10.5.0", ">= 10.0.0, < 11.0.0"),
    (N, "11.0.0", ">= 10.0.0, < 11.0.0"),
    (N, "9.0", ">= 10.0.0, < 11.0.0"),
    # virgule : énumération de séries
    (A, "2.7.5", "affects 2.7, 3.5, 3.6, 3.7"),
    (N, "4.0", "affects 2.7, 3.5, 3.6, 3.7"),
    # "prior to X"
    (A, "2.17.1186", "prior to 2.17.1187"),
    (N, "2.17.1187", "prior to 2.17.1187"),
    # "X and earlier" / "X and newer"
    (A, "3.0", "3.0 and earlier"),
    (N, "3.1", "3.0 and earlier"),
    (A, "2.3.12", "2.3.12 and newer"),
    (N, "2.3.11", "2.3.12 and newer"),
    # "all X.x before Y"
    (A, "10.5", "all 10.x before 10.10"),
    (N, "10.10", "all 10.x before 10.10"),
    (N, "18.4", "all 10.x before 10.10"),
    # "X - Y"
    (A, "2.5", "2.0 - 3.0"),
    (N, "3.5", "2.0 - 3.0"),
    # wildcard "X.Y <X.Y.*" / "X.Y <Z.W.*"
    (A, "10.6.5", "10.6 <10.6.*"),
    (N, "10.7.0", "10.6 <10.6.*"),
    (A, "11.2", "11.1 <11.4.*"),
    (N, "11.4", "11.1 <11.4.*"),
    (N, "11.0", "11.1 <11.4.*"),
    # "Éditeur X.Y.Z" → version exacte
    (A, "2.10.34", "GIMP 2.10.34"),
    (N, "2.10.35", "GIMP 2.10.34"),
    # indéterminé
    (U, "1.0", ""),
    (U, "1.0", "-"),
    (U, "", "4.0"),
    (U, "notaversion", "4.0"),
    (U, "1.0", "git-abc123"),
    # "before X" (2 tokens, low non numérique)
    (A, "1.5", "before 2.0"),
    (N, "2.0", "before 2.0"),
]


@pytest.mark.parametrize("expected, version, range_str", CASES)
def test_version_in_range_raw(expected, version, range_str):
    assert _version_in_range_raw(version, range_str) == expected
