from __future__ import annotations

from copy import deepcopy
from typing import Any

class JSONPatch:
    _OPS = frozenset({'set', 'del'})

    @staticmethod
    def diff(old: Any, new: Any, path: str = '$') -> list[dict[str, Any]]:
        if type(old) is not type(new):
            return [{'op': 'set', 'path': path, 'value': deepcopy(new)}]
        if isinstance(old, dict):
            ops: list[dict[str, Any]] = []
            for key in sorted(set(new) - set(old), key=str):
                JSONPatch._validate_key(key)
                ops.append({'op': 'set', 'path': f'{path}.{key}', 'value': deepcopy(new[key])})
            for key in sorted(set(old) - set(new), key=str):
                JSONPatch._validate_key(key)
                ops.append({'op': 'del', 'path': f'{path}.{key}'})
            for key in sorted(set(old) & set(new), key=str):
                JSONPatch._validate_key(key)
                ops.extend(JSONPatch.diff(old[key], new[key], f'{path}.{key}'))
            return ops
        if isinstance(old, list):
            return [] if old == new else [{'op': 'set', 'path': path, 'value': deepcopy(new)}]
        return [] if old == new else [{'op': 'set', 'path': path, 'value': deepcopy(new)}]

    @staticmethod
    def apply(doc: Any, ops: list[dict[str, Any]]) -> Any:
        result = deepcopy(doc)
        for op in ops:
            if not isinstance(op, dict) or op.get('op') not in JSONPatch._OPS:
                raise ValueError('unsupported patch operation')
            path = op.get('path')
            if not isinstance(path, str) or not path.startswith('$'):
                raise ValueError('invalid patch path')
            parts = JSONPatch._parts(path)
            if not parts:
                if op['op'] != 'set': raise ValueError('root delete is invalid')
                result = deepcopy(op.get('value')); continue
            if not isinstance(result, dict): raise ValueError('patch root must be an object')
            if op['op'] == 'set': JSONPatch._set(result, parts, deepcopy(op.get('value')))
            else: JSONPatch._delete(result, parts)
        return result

    @staticmethod
    def _parts(path: str) -> list[str]:
        if path == '$': return []
        if not path.startswith('$.'): raise ValueError('invalid patch path')
        parts = path[2:].split('.')
        if any(not p for p in parts): raise ValueError('invalid patch path')
        for part in parts: JSONPatch._validate_key(part)
        return parts

    @staticmethod
    def _validate_key(key: Any) -> None:
        if not isinstance(key, str) or not key or '.' in key or '\x00' in key:
            raise ValueError('state keys must be non-empty and contain no dots/NUL')

    @staticmethod
    def _set(root: dict[str, Any], parts: list[str], value: Any) -> None:
        target = root
        for part in parts[:-1]:
            child = target.get(part)
            if child is None: child = {}; target[part] = child
            if not isinstance(child, dict): raise ValueError('patch traverses non-object state')
            target = child
        target[parts[-1]] = value

    @staticmethod
    def _delete(root: dict[str, Any], parts: list[str]) -> None:
        target: Any = root
        for part in parts[:-1]:
            target = target.get(part) if isinstance(target, dict) else None
            if target is None: return
            if not isinstance(target, dict): raise ValueError('patch traverses non-object state')
        if isinstance(target, dict): target.pop(parts[-1], None)