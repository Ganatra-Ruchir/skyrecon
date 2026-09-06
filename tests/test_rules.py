import pytest

from app.detect import rules


def test_basic_operators():
    facts = {"severity": "high", "bytes_out": 20000, "payload": "PowerShell -EncodedCommand ZQ=="}
    assert rules.evaluate('severity == "high"', facts)
    assert rules.evaluate("bytes_out > 10000", facts)
    assert not rules.evaluate("bytes_out < 10000", facts)
    assert rules.evaluate('payload contains "powershell"', facts)
    assert rules.evaluate('severity in ["high","critical"]', facts)


def test_boolean_composition():
    facts = {"a": 1, "b": 0, "t": True}
    assert rules.evaluate("a == 1 and not b == 1", facts)
    assert rules.evaluate("(a == 5 or a == 1) and t", facts)
    assert not rules.evaluate("a == 5 or b == 5", facts)


def test_regex_matching():
    facts = {"payload": "GET /x.exe HTTP/1.1"}
    assert rules.evaluate(r'payload matches "\.(exe|dll)"', facts)


def test_rule_language_cannot_execute_code():
    for hostile in [
        '__import__("os").system("id")',
        'open("/etc/passwd").read()',
        "().__class__.__bases__[0].__subclasses__()",
        "eval('1+1')",
    ]:
        with pytest.raises(rules.RuleError):
            rules.evaluate(hostile, {})


def test_oversized_rule_rejected():
    with pytest.raises(rules.RuleError):
        rules.evaluate("a == 1 and " * 500 + "a == 1", {})


def test_missing_field_is_falsey_not_an_error():
    assert rules.evaluate('nonexistent == null', {}) is True
    assert rules.evaluate("nonexistent > 5", {}) is False


def test_builtin_rules_all_compile():
    for spec in rules.BUILTIN_RULES:
        ok, err = rules.validate_expression(spec["expression"])
        assert ok, f"{spec['name']}: {err}"
