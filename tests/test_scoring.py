"""Tests de app.scoring._safe_eval — évaluateur d'expressions sans eval().

Frontière de sécurité : seuls constantes numériques et opérateurs +-*/**  sont
autorisés ; toute construction Python (appel, nom, attribut, liste…) doit lever.
"""
import pytest

from app.scoring import _safe_eval


class TestCalcul:
    @pytest.mark.parametrize("expr, attendu", [
        ("(1 + 2) * 3", 9.0),
        ("10 / 4", 2.5),
        ("-5 + 2", -3.0),
        ("2 ** 3", 8.0),
        ("100 * 0.5", 50.0),
        ("+7", 7.0),
    ])
    def test_expressions_valides(self, expr, attendu):
        assert _safe_eval(expr) == pytest.approx(attendu)


class TestRejetInjection:
    @pytest.mark.parametrize("expr", [
        "__import__('os').system('id')",   # appel de fonction
        "os.system('id')",                  # attribut
        "x + 1",                            # nom libre
        "[1, 2, 3]",                        # littéral liste
        "1 and 2",                          # BoolOp
        "(lambda: 1)()",                    # lambda
        "'a' * 3",                          # constante non numérique
    ])
    def test_construction_interdite_leve(self, expr):
        with pytest.raises(ValueError):
            _safe_eval(expr)
