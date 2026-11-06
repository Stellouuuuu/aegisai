"""SQLite persistence. Plain SQL behind one class so PostgreSQL can replace it later."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    app_type TEXT NOT NULL DEFAULT 'chatbot',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    config TEXT NOT NULL,
    modules TEXT NOT NULL,
    depth TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    security_score INTEGER,
    requests_sent INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL,
    error TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id),
    scenario_id TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    retested_at TEXT
);
"""

ASSESSMENT_FIELDS = {
    "status", "progress", "security_score", "requests_sent",
    "duration_seconds", "error", "finished_at",
}


def now() -> str:
    return datetime.now(UTC).isoformat()


class Storage:
    def __init__(self, path: str) -> None:
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)
            cols = {r["name"] for r in c.execute("PRAGMA table_info(projects)")}
            if "user_id" not in cols:  # databases created before accounts existed
                c.execute("ALTER TABLE projects ADD COLUMN user_id INTEGER REFERENCES users(id)")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # users and sessions
    def create_user(self, email: str, password_hash: str) -> dict[str, Any] | None:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?,?,?)",
                    (email, password_hash, now()),
                )
                uid = cur.lastrowid
        except sqlite3.IntegrityError:
            return None
        return self.get_user(uid)  # type: ignore[arg-type]

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None

    def create_session(self, user_id: int, token_hash: str, expires_at: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO sessions VALUES (?,?,?)", (token_hash, user_id, expires_at))

    def user_for_session(self, token_hash: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash=? AND s.expires_at > ?",
                (token_hash, now()),
            ).fetchone()
        return dict(row) if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    # projects
    def create_project(
        self, user_id: int, name: str, description: str, app_type: str
    ) -> dict[str, Any]:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO projects (user_id, name, description, app_type, created_at)"
                " VALUES (?,?,?,?,?)",
                (user_id, name, description, app_type, now()),
            )
            pid = cur.lastrowid
        return self.get_project(pid)  # type: ignore[arg-type, return-value]

    def get_project(self, project_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None

    def list_projects(self, user_id: int) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM projects WHERE user_id=? ORDER BY id DESC", (user_id,))
            return [dict(r) for r in rows]

    # assessments
    @staticmethod
    def _assessment(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["config"] = json.loads(d["config"])
        d["modules"] = json.loads(d["modules"])
        return d

    def create_assessment(
        self, project_id: int, config: dict[str, Any], modules: list[str], depth: str
    ) -> dict[str, Any]:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO assessments (project_id, config, modules, depth, status, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (project_id, json.dumps(config), json.dumps(modules), depth, "pending", now()),
            )
            aid = cur.lastrowid
        return self.get_assessment(aid)  # type: ignore[arg-type, return-value]

    def get_assessment(self, assessment_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        return self._assessment(row) if row else None

    def list_assessments(self, project_id: int) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM assessments WHERE project_id=? ORDER BY id DESC", (project_id,)
            )
            return [self._assessment(r) for r in rows]

    def update_assessment(self, assessment_id: int, **fields: Any) -> None:
        bad = set(fields) - ASSESSMENT_FIELDS
        if bad:
            raise ValueError(f"Unknown assessment fields: {bad}")
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as c:
            c.execute(
                f"UPDATE assessments SET {cols} WHERE id=?", (*fields.values(), assessment_id)
            )

    # findings
    @staticmethod
    def _finding(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    def add_findings(self, assessment_id: int, findings: list[dict[str, Any]]) -> None:
        with self._conn() as c:
            c.executemany(
                "INSERT INTO findings (assessment_id, scenario_id, data) VALUES (?,?,?)",
                [(assessment_id, f["id"], json.dumps(f)) for f in findings],
            )

    def list_findings(self, assessment_id: int) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM findings WHERE assessment_id=? ORDER BY id", (assessment_id,)
            )
            return [self._finding(r) for r in rows]

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._finding(row) if row else None

    def update_finding(self, finding_id: int, data: dict[str, Any] | None, status: str) -> None:
        with self._conn() as c:
            if data is None:
                c.execute("UPDATE findings SET status=?, retested_at=? WHERE id=?",
                          (status, now(), finding_id))
            else:
                c.execute("UPDATE findings SET data=?, status=?, retested_at=? WHERE id=?",
                          (json.dumps(data), status, now(), finding_id))
