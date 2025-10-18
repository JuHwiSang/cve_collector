from __future__ import annotations

from typing import Iterable, Protocol, Type, TypeVar
import json
from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


class CachePort(Protocol):
    def get(self, key: str) -> bytes | None:
        """Return cached bytes for key, or None if missing/expired."""

    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None:
        """Store bytes with optional TTL in seconds."""

    def clear(self, prefix: str | None = None) -> None:
        """Clear cached entries. Without prefix, clears all. With prefix, clears only matching keys."""

    def iter_keys(self, prefix: str) -> Iterable[str]:
        """Iterate over keys in the current namespace matching the given prefix."""
        ...

    def get_json(self, key: str) -> dict | list | None:
        """Return cached JSON (dict or list) decoded from bytes, or None if missing."""
        raw = self.get(key)
        if raw is None:
            return None
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, (dict, list)):
            raise TypeError("CachePort.get_json invariant violated: expected JSON object/array")
        return data

    def set_json(self, key: str, value: dict | list, ttl_seconds: int | None = None) -> None:
        """Serialize value as JSON and store as bytes with optional TTL."""
        data = json.dumps(value).encode("utf-8")
        self.set(key, data, ttl_seconds)

    def get_model(self, key: str, model_cls: Type[ModelT]) -> ModelT | None:
        """Load JSON and validate into a pydantic model. Returns None if missing."""
        data = self.get_json(key)
        if data is None:
            return None
        return model_cls.model_validate(data)

    def set_model(self, key: str, model: BaseModel, ttl_seconds: int | None = None) -> None:
        """Serialize a pydantic model into JSON and store."""
        self.set_json(key, model.model_dump(), ttl_seconds)


