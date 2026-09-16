from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.hunting.lexer import Token, Tok, tokenize


@dataclass(frozen=True, slots=True)
class Node:
    pass


@dataclass(frozen=True, slots=True)
class Predicate(Node):
    field: str
    op: str
    value: Any


@dataclass(frozen=True, slots=True)
class And(Node):
    clauses: tuple[Node, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Or(Node):
    clauses: tuple[Node, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Query:
    table: str
    where: Node | None
    commands: list[Command] = field(default_factory=list)
    limit: int = 500
    order_by: str | None = None
    order_desc: bool = True


class Parser:
    """Small, non-SQL grammar for tenant-scoped hunting queries."""

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.i = 0

    def peek(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        token = self.tokens[self.i]
        self.i += 1
        return token

    def expect(self, kind: Tok) -> Token:
        token = self.advance()
        if token.kind != kind:
            raise SyntaxError(f"expected {kind.value}, got {token.kind.value} ({token.value!r})")
        return token

    def parse(self) -> Query:
        table = self.expect(Tok.TABLE).value
        where: Node | None = None
        if self.peek().kind == Tok.IDENT and self.peek().value.lower() == "where":
            self.advance()
            where = self.parse_expr()
        commands: list[Command] = []
        while self.peek().kind == Tok.PIPE:
            self.advance()
            commands.append(self.parse_command())
        if self.peek().kind != Tok.EOF:
            raise SyntaxError(f"unexpected token at {self.peek().pos}: {self.peek().value!r}")
        query = Query(table=table, where=where, commands=commands)
        self._apply_commands(query)
        return query

    def parse_expr(self) -> Node:
        clauses = [self.parse_term()]
        while self.peek().kind == Tok.IDENT and self.peek().value.lower() == "or":
            self.advance()
            clauses.append(self.parse_term())
        return clauses[0] if len(clauses) == 1 else Or(tuple(clauses))

    def parse_term(self) -> Node:
        clauses = [self.parse_factor()]
        while self.peek().kind == Tok.IDENT and self.peek().value.lower() == "and":
            self.advance()
            clauses.append(self.parse_factor())
        return clauses[0] if len(clauses) == 1 else And(tuple(clauses))

    def parse_factor(self) -> Node:
        if self.peek().kind == Tok.LPAREN:
            self.advance()
            node = self.parse_expr()
            self.expect(Tok.RPAREN)
            return node
        return self.parse_predicate()

    def parse_predicate(self) -> Predicate:
        field = self.expect(Tok.IDENT).value
        op = self.expect(Tok.OP).value
        return Predicate(field, op, self._parse_value())

    def parse_command(self) -> Command:
        name = self.expect(Tok.IDENT).value.lower()
        if name not in {"limit", "sort", "order"}:
            raise SyntaxError(f"unsupported command: {name}")
        args: dict[str, Any] = {}
        pos = 0
        while self.peek().kind in (Tok.IDENT, Tok.STRING, Tok.NUMBER, Tok.BOOL):
            if (
                self.peek().kind == Tok.IDENT
                and self.i + 1 < len(self.tokens)
                and self.tokens[self.i + 1].kind == Tok.OP
                and self.tokens[self.i + 1].value == "=="
            ):
                key = self.advance().value
                self.advance()
                args[key] = self._parse_value()
            else:
                if name in {"sort", "order"} and self.peek().kind == Tok.IDENT:
                    args[f"arg{pos}"] = self.advance().value
                else:
                    args[f"arg{pos}"] = self._parse_value()
                pos += 1
            if self.peek().kind == Tok.COMMA:
                self.advance()
            else:
                break
        return Command(name, args)

    def _parse_value(self) -> Any:
        token = self.advance()
        if token.kind == Tok.STRING:
            return token.value
        if token.kind == Tok.NUMBER:
            return float(token.value) if "." in token.value else int(token.value)
        if token.kind == Tok.BOOL:
            return token.value == "true"
        raise SyntaxError(f"expected value, got {token.kind.value}")

    @staticmethod
    def _apply_commands(query: Query) -> None:
        for command in query.commands:
            if command.name == "limit":
                value = command.args.get("arg0") or command.args.get("n")
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    query.limit = max(1, min(int(value), 5000))
            elif command.name in {"sort", "order"}:
                field = command.args.get("arg0") or command.args.get("by")
                direction = command.args.get("arg1") or command.args.get("dir") or "desc"
                if not isinstance(field, str):
                    raise SyntaxError("sort/order requires a field")
                if str(direction).lower() not in {"asc", "desc"}:
                    raise SyntaxError("sort direction must be asc or desc")
                query.order_by = field
                query.order_desc = str(direction).lower() == "desc"


def parse(src: str) -> Query:
    return Parser(tokenize(src)).parse()
