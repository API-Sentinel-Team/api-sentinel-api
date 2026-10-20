from pathlib import Path

from sentinel_core.config import BASE_DIR

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_settings_do_not_read_the_developer_env_file():
    """A local compose .env (POSTGRES_PASSWORD, real DATABASE_URL, secrets) must not leak into tests."""
    assert BASE_DIR.resolve() != REPO_ROOT
    assert not (BASE_DIR / ".env").exists()
