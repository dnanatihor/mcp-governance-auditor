"""Sqlite classification cache (§10.4)."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from mcp_gov_audit.models import LLMFieldVerdict


def cache_key(
    *,
    prompt_version: str,
    model_id: str,
    tool_name: str,
    normalized_path: str,
    value_preview: str,
) -> str:
    raw = "|".join((prompt_version, model_id, tool_name, normalized_path, value_preview))
    return hashlib.sha256(raw.encode()).hexdigest()


class ClassificationCache:
    """Read-through cache of raw model verdicts. The confidence threshold is applied later."""

    def __init__(self, cache_dir: Path, *, read: bool = True) -> None:
        self.cache_dir = cache_dir
        self.read = read
        self.path = cache_dir / "classifications.sqlite"
        cache_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS classifications (
                    cache_key TEXT PRIMARY KEY,
                    field_path TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    mixed_layers INTEGER NOT NULL,
                    evidence TEXT NOT NULL
                )
                """
            )

    def get(self, key: str) -> LLMFieldVerdict | None:
        if not self.read:
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT field_path, layer, confidence, mixed_layers, evidence
                FROM classifications WHERE cache_key = ?
                """,
                (key,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        return LLMFieldVerdict(
            field_path=str(row[0]),
            layer=row[1],
            confidence=float(row[2]),
            mixed_layers=bool(row[3]),
            evidence=str(row[4]),
        )

    def put(self, key: str, verdict: LLMFieldVerdict) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO classifications (
                    cache_key, field_path, layer, confidence, mixed_layers, evidence
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    field_path = excluded.field_path,
                    layer = excluded.layer,
                    confidence = excluded.confidence,
                    mixed_layers = excluded.mixed_layers,
                    evidence = excluded.evidence
                """,
                (
                    key,
                    verdict.field_path,
                    verdict.layer,
                    verdict.confidence,
                    int(verdict.mixed_layers),
                    verdict.evidence,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection
