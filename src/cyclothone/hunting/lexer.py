from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Tok(str, Enum):
    TABLE = "TABLE"
    PIPE = "PIPE"
    IDENT = "IDENT"
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOL = "BOOL"
    OP = "OP"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COMMA = "COMMA"
    EOF = "EOF"


@dataclass(frozen=True, slots=True)
class Token:
    kind: Tok
    value: str
    pos: int


TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
  | (?P<PIPE>\|)
  | (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<COMMA>,)
  | (?P<OP>==|!=|>=|<=|>|<|~|!~)
  | (?P<STRING>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')
  | (?P<NUMBER>-?\d+(?:\.\d+)?)
  | (?P<IDENT>[A-Za-z_][A-Za-z0-9_\.\*]*)
    """,
    re.VERBOSE,
)

TABLES = {
    "events", "detections", "cases", "case_actions", "commands", "iocs",
    "indicators", "canary_triggers", "agent_actions", "audit_log",
}


def tokenize(src: str) -> list[Token]:
    if len(src) > 8000:
        raise SyntaxError("query exceeds 8000 characters")
    tokens: list[Token] = []
    i = 0
    while i < len(src):
        match = TOKEN_RE.match(src, i)
        if not match:
            raise SyntaxError(f"unexpected char at {i}: {src[i]!r}")
        kind = match.lastgroup
        value = match.group()
        if kind != "WS":
            if kind == "IDENT" and value.lower() in TABLES and not tokens:
                tokens.append(Token(Tok.TABLE, value.lower(), i))
            elif kind == "IDENT" and value.lower() in {"true", "false"}:
                tokens.append(Token(Tok.BOOL, value.lower(), i))
            elif kind == "IDENT":
                tokens.append(Token(Tok.IDENT, value, i))
            elif kind == "STRING":
                tokens.append(Token(Tok.STRING, value[1:-1], i))
            elif kind == "NUMBER":
                tokens.append(Token(Tok.NUMBER, value, i))
            else:
                tokens.append(Token(Tok(kind), value, i))
        i = match.end()
    tokens.append(Token(Tok.EOF, "", i))
    return tokens
