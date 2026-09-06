"""
Detection rule engine.

Rules are written in a tiny expression language and evaluated by a hand-written
parser — never `eval`. Untrusted rule text therefore cannot execute code, which
matters because rule authoring is delegated to analysts, not just admins.

    severity == "high" and bytes_out > 10000
    ioc_type in ["url","domain"] and dga > 0.6
    src_ip startswith "10." and not internal
    payload contains "powershell -enc"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_TOKEN = re.compile(r"""
      (?P<ws>\s+)
    | (?P<number>-?\d+(?:\.\d+)?)
    | (?P<string>"[^"]*"|'[^']*')
    | (?P<op>==|!=|>=|<=|>|<)
    | (?P<punct>[()\[\],])
    | (?P<word>[A-Za-z_][A-Za-z0-9_.]*)
""", re.X)

_KEYWORDS = {"and", "or", "not", "in", "contains", "startswith", "endswith",
             "matches", "true", "false", "null"}
MAX_LENGTH = 2000
MAX_TOKENS = 400


class RuleError(ValueError):
    """Malformed rule. Reported to the author, never executed."""


@dataclass
class Token:
    kind: str
    value: Any


def tokenize(text: str) -> list[Token]:
    if len(text) > MAX_LENGTH:
        raise RuleError("rule is too long")
    out: list[Token] = []
    i = 0
    while i < len(text):
        m = _TOKEN.match(text, i)
        if not m:
            raise RuleError(f"unexpected character at position {i}: {text[i]!r}")
        i = m.end()
        kind = m.lastgroup
        raw = m.group()
        if kind == "ws":
            continue
        if kind == "number":
            out.append(Token("number", float(raw) if "." in raw else int(raw)))
        elif kind == "string":
            out.append(Token("string", raw[1:-1]))
        elif kind == "op":
            out.append(Token("op", raw))
        elif kind == "punct":
            out.append(Token("punct", raw))
        else:
            low = raw.lower()
            out.append(Token("kw", low) if low in _KEYWORDS else Token("field", raw))
        if len(out) > MAX_TOKENS:
            raise RuleError("rule has too many tokens")
    return out


class _Parser:
    """Recursive descent: or > and > not > comparison > primary."""

    def __init__(self, tokens: list[Token], facts: dict) -> None:
        self.t = tokens
        self.i = 0
        self.facts = facts

    def peek(self) -> Token | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def eat(self) -> Token:
        if self.i >= len(self.t):
            raise RuleError("unexpected end of rule")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, kind: str, value: Any = None) -> Token:
        tok = self.eat()
        if tok.kind != kind or (value is not None and tok.value != value):
            raise RuleError(f"expected {value or kind}, found {tok.value!r}")
        return tok

    # -- grammar ---------------------------------------------------------
    def parse(self) -> bool:
        result = self.or_expr()
        if self.peek() is not None:
            raise RuleError(f"unexpected trailing input near {self.peek().value!r}")
        return bool(result)

    def or_expr(self):
        left = self.and_expr()
        while (tok := self.peek()) and tok.kind == "kw" and tok.value == "or":
            self.eat()
            right = self.and_expr()
            left = bool(left) or bool(right)
        return left

    def and_expr(self):
        left = self.not_expr()
        while (tok := self.peek()) and tok.kind == "kw" and tok.value == "and":
            self.eat()
            right = self.not_expr()
            left = bool(left) and bool(right)
        return left

    def not_expr(self):
        tok = self.peek()
        if tok and tok.kind == "kw" and tok.value == "not":
            self.eat()
            return not bool(self.not_expr())
        return self.comparison()

    def comparison(self):
        left = self.primary()
        tok = self.peek()
        if tok is None:
            return left
        if tok.kind == "op":
            op = self.eat().value
            right = self.primary()
            return self._compare(op, left, right)
        if tok.kind == "kw" and tok.value in {"in", "contains", "startswith",
                                              "endswith", "matches"}:
            op = self.eat().value
            right = self.primary()
            return self._textual(op, left, right)
        return left

    def primary(self):
        tok = self.eat()
        if tok.kind in {"number", "string"}:
            return tok.value
        if tok.kind == "kw":
            if tok.value == "true":
                return True
            if tok.value == "false":
                return False
            if tok.value == "null":
                return None
            if tok.value == "not":
                return not bool(self.primary())
            raise RuleError(f"unexpected keyword {tok.value!r}")
        if tok.kind == "field":
            return self.facts.get(tok.value)
        if tok.kind == "punct" and tok.value == "(":
            val = self.or_expr()
            self.expect("punct", ")")
            return val
        if tok.kind == "punct" and tok.value == "[":
            items = []
            if (nxt := self.peek()) and not (nxt.kind == "punct" and nxt.value == "]"):
                items.append(self.primary())
                while (nxt := self.peek()) and nxt.kind == "punct" and nxt.value == ",":
                    self.eat()
                    items.append(self.primary())
            self.expect("punct", "]")
            return items
        raise RuleError(f"unexpected token {tok.value!r}")

    # -- operators -------------------------------------------------------
    @staticmethod
    def _compare(op: str, left, right):
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        try:
            lf, rf = float(left), float(right)
        except (TypeError, ValueError):
            return False
        return {">": lf > rf, "<": lf < rf, ">=": lf >= rf, "<=": lf <= rf}[op]

    @staticmethod
    def _textual(op: str, left, right):
        if op == "in":
            if isinstance(right, list | tuple):
                return left in right
            return str(left or "") in str(right or "")
        ls, rs = str(left or "").lower(), str(right or "").lower()
        if op == "contains":
            return rs in ls
        if op == "startswith":
            return ls.startswith(rs)
        if op == "endswith":
            return ls.endswith(rs)
        if op == "matches":
            try:
                return re.search(rs, ls, re.I) is not None
            except re.error as exc:
                raise RuleError(f"invalid regular expression: {exc}") from exc
        return False


def evaluate(expression: str, facts: dict) -> bool:
    """True when the rule matches these facts. Raises RuleError on bad syntax."""
    if not expression or not expression.strip():
        return False
    return _Parser(tokenize(expression), facts).parse()


def validate_expression(expression: str) -> tuple[bool, str | None]:
    """Syntax-check a rule against dummy facts before saving it."""
    probe = {
        "severity": "medium", "confidence": 50, "bytes_out": 0, "bytes_in": 0,
        "duration_ms": 0, "ioc_type": "domain", "dga": 0.0, "tld_risk": 0.0,
        "entropy": 0.0, "source": "test", "payload": "", "src_ip": "",
        "dst_ip": "", "internal": False, "risk": 0.0, "tags": "", "kind": "log",
    }
    try:
        evaluate(expression, probe)
        return True, None
    except RuleError as exc:
        return False, str(exc)


BUILTIN_RULES = [
    {
        "name": "Executable delivered over plain HTTP",
        "description": "Direct download of a binary without TLS — classic dropper behaviour.",
        "severity": "high",
        "expression": r'payload matches "http://[^\s]*\.(exe|scr|dll|hta|ps1|bat)"',
        "mitre_techniques": "T1105,T1204.002",
    },
    {
        "name": "Algorithmically generated domain",
        "description": "High-entropy hostname on a low-reputation TLD, typical of C2 rendezvous.",
        "severity": "high",
        "expression": "dga > 0.6 and tld_risk > 0.5",
        "mitre_techniques": "T1568.002",
    },
    {
        "name": "Encoded PowerShell in payload",
        "description": "Base64-encoded command lines are the standard way to hide a stager.",
        "severity": "critical",
        "expression": r'payload contains "powershell" and payload matches "-e(nc|ncodedcommand)?\s"',
        "mitre_techniques": "T1059.001,T1027",
    },
    {
        "name": "Large outbound transfer to new destination",
        "description": "Volume consistent with staged exfiltration.",
        "severity": "medium",
        "expression": "bytes_out > 5000000 and bytes_in < 100000",
        "mitre_techniques": "T1041,T1030",
    },
    {
        "name": "Credential-phishing lure",
        "description": "Login-themed URL on a throwaway domain.",
        "severity": "high",
        "expression": r'ioc_type == "url" and (payload contains "login" or payload contains "verify") and tld_risk > 0.5',
        "mitre_techniques": "T1566.002",
    },
    {
        "name": "Beacon-like callback to a known indicator",
        "description": (
            "Small, short, regular connections are only interesting when the far "
            "end is already suspect — otherwise every intranet request looks like a beacon."
        ),
        "severity": "medium",
        "expression": 'duration_ms < 1200 and bytes_out < 2048 and bytes_out > 0 and ioc_type != ""',
        "mitre_techniques": "T1071.001",
    },
]
