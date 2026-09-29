from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[2]


def _migration_head() -> str:
    config = Config(str(ROOT / "alembic.ini"))
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected a single Alembic head, got {heads}"
    return heads[0]


def test_alembic_upgrade_head_bootstraps_fresh_database(tmp_path):
    db_path = tmp_path / "fresh-bootstrap.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    env["PYTHONPATH"] = str(ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert db_path.exists()

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "alembic_version" in tables
        assert "users" in tables
        assert "api_endpoints" in tables
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        assert version is not None
    assert version[0] == _migration_head()


def test_alembic_upgrade_head_commits_incremental_sqlite_migration(tmp_path):
    db_path = tmp_path / "incremental-upgrade.db"
    previous_head = "20260602_run_schedule_link"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE pentest_profiles ("
            "id VARCHAR(36) NOT NULL PRIMARY KEY, "
            "name VARCHAR(255) NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE alembic_version ("
            "version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )
        conn.execute("INSERT INTO alembic_version (version_num) VALUES (?)", (previous_head,))
        conn.commit()

    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    env["PYTHONPATH"] = str(ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr

    with sqlite3.connect(db_path) as conn:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(pentest_profiles)"
            ).fetchall()
        }

    assert version is not None
    assert version[0] == _migration_head()
    assert "allow_destructive_methods" in columns
