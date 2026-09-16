from __future__ import annotations

import time
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status

from sentinel.hunting.parser import And, Node, Or, Predicate, parse
from sentinel.storage.supabase_client import supabase


ALLOWED_FIELDS: dict[str, set[str]] = {
    "events": {"id", "device_id", "event_type", "ts", "sha256", "payload", "parent_id"},
    "detections": {"id", "device_id", "detector", "score", "verdict", "mitre_technique", "reasons", "evidence", "created_at", "processed_by_playbooks", "processed_by_autocase"},
    "cases": {"id", "case_number", "title", "category", "severity", "status", "device_id", "created_at", "financial_loss", "currency"},
    "case_actions": {"id", "case_id", "device_id", "action", "status", "issued_by", "created_at", "executed_at", "error"},
    "commands": {"id", "device_id", "action", "status", "issued_by", "issued_at", "executed_at", "error"},
    "iocs": {"id", "ioc_type", "value", "severity", "source", "created_at"},
    "indicators": {"id", "ioc_type", "value", "severity", "confidence", "source", "tags", "first_seen", "last_seen"},
    "canary_triggers": {"id", "device_id", "canary_id", "template_id", "trigger_kind", "actor_process", "actor_user", "source_ip", "created_at", "response_status"},
    "agent_actions": {"id", "agent_id", "kind", "tool_name", "risk_score", "blocked", "ts"},
    "audit_log": {"id", "actor", "action", "resource", "resource_id", "ts", "ip"},
}

OPS = {"==": "eq", "!=": "neq", ">": "gt", ">=": "gte", "<": "lt", "<=": "lte", "~": "ilike", "!~": "not_ilike"}
DEFAULT_ORDER = {
    "events": "ts", "detections": "created_at", "cases": "created_at", "case_actions": "created_at",
    "commands": "issued_at", "iocs": "created_at", "indicators": "last_seen", "canary_triggers": "created_at",
    "agent_actions": "ts", "audit_log": "ts",
}


class QueryExecutor:
    MAX_LIMIT = 5000
    DEFAULT_LIMIT = 500

    async def run(self, tenant_id: UUID, source: str) -> tuple[list[dict[str, Any]], int]:
        try:
            query = parse(source)
        except SyntaxError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid hunting query") from exc

        table = query.table
        fields = ALLOWED_FIELDS.get(table)
        if fields is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"table not queryable: {table}")

        self._validate_node(query.where, table)
        order_by = query.order_by or DEFAULT_ORDER.get(table)
        if order_by and order_by not in fields:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"field not orderable: {order_by}")

        limit = min(query.limit or self.DEFAULT_LIMIT, self.MAX_LIMIT)
        selected = ",".join(sorted(fields))

        async def _do():
            client = await supabase._ensure()
            builder = client.table(table).select(selected).eq("tenant_id", str(tenant_id))
            if query.where is not None:
                builder = self._apply(builder, query.where, table)
            if order_by:
                builder = builder.order(order_by, desc=query.order_desc if query.order_by else True)
            return await builder.limit(limit).execute()

        started = time.perf_counter()
        try:
            response = await supabase._retry(_do, attempts=2)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "query execution failed") from exc
        elapsed = int((time.perf_counter() - started) * 1000)
        return list(response.data or []), elapsed

    def _validate_node(self, node: Node | None, table: str) -> None:
        if node is None:
            return
        if isinstance(node, Predicate):
            if node.field not in ALLOWED_FIELDS[table]:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"field not filterable: {node.field}")
            if node.op not in OPS:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unsupported op: {node.op}")
            return
        if isinstance(node, (And, Or)):
            if isinstance(node, Or) and not node.clauses:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty OR clause")
            for clause in node.clauses:
                self._validate_node(clause, table)
            return
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid clause")

    def _apply(self, query: Any, node: Node, table: str) -> Any:
        if isinstance(node, Predicate):
            return self._apply_predicate(query, node, table)
        if isinstance(node, And):
            for clause in node.clauses:
                query = self._apply(query, clause, table)
            return query
        if isinstance(node, Or):
            if not node.clauses:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty OR clause")
            return query.or_(",".join(self._to_or_clause(c, table) for c in node.clauses))
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid clause")

    def _apply_predicate(self, query: Any, predicate: Predicate, table: str) -> Any:
        if predicate.field not in ALLOWED_FIELDS[table]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"field not filterable: {predicate.field}")
        operation = OPS.get(predicate.op)
        if operation is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unsupported op: {predicate.op}")
        value = predicate.value
        if operation == "ilike" and isinstance(value, str):
            value = f"%{value}%"
        if operation == "not_ilike" and isinstance(value, str):
            return query.not_.ilike(predicate.field, f"%{value}%")
        return getattr(query, operation)(predicate.field, value)

    def _to_or_clause(self, node: Node, table: str) -> str:
        if isinstance(node, Predicate):
            if node.field not in ALLOWED_FIELDS[table]:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"field not filterable: {node.field}")
            operation = OPS.get(node.op)
            if operation is None:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unsupported op: {node.op}")
            if isinstance(node.value, str):
                escaped = node.value.replace("\\", "\\\\").replace('"', '\\"')
                value = f'"{escaped}"'
            elif isinstance(node.value, bool):
                value = "true" if node.value else "false"
            elif isinstance(node.value, (int, float)):
                value = str(node.value)
            else:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported predicate value")
            if operation == "ilike" and isinstance(node.value, str):
                value = f'"%{node.value.replace(chr(92), chr(92)+chr(92)).replace(chr(34), chr(92)+chr(34))}%"'
            if operation == "not_ilike" and isinstance(node.value, str):
                value = f'"%{node.value.replace(chr(92), chr(92)+chr(92)).replace(chr(34), chr(92)+chr(34))}%"'
                operation = "not.ilike"
            return f"{node.field}.{operation}.{value}"
        if isinstance(node, And):
            return "and(" + ",".join(self._to_or_clause(c, table) for c in node.clauses) + ")"
        if isinstance(node, Or):
            return "or(" + ",".join(self._to_or_clause(c, table) for c in node.clauses) + ")"
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid OR clause")
