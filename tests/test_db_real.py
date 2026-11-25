"""Opt-in: needs a real Postgres. Run with KVS_PG_TEST=1 and KVS_PG_PASSWORD set.

Expects Postgres on KVS_DB_HOST/KVS_DB_PORT (default 127.0.0.1:55432), user postgres.
"""
import os

import pytest

from acme import db

pytestmark = pytest.mark.skipif(os.environ.get("KVS_PG_TEST") != "1", reason="set KVS_PG_TEST=1")


@pytest.fixture(autouse=True)
def pg_env(monkeypatch):
    monkeypatch.setenv("KVS_DB_HOST", os.environ.get("KVS_DB_HOST", "127.0.0.1"))
    monkeypatch.setenv("KVS_DB_PORT", os.environ.get("KVS_DB_PORT", "55432"))
    monkeypatch.setenv("KVS_DB_NAME", "postgres")


def test_right_password():
    assert db.try_login("postgres", os.environ["KVS_PG_PASSWORD"]) is True


def test_wrong_password():
    assert db.try_login("postgres", "definitely-wrong") is False


def test_closed_port(monkeypatch):
    monkeypatch.setenv("KVS_DB_PORT", "55999")
    with pytest.raises(db.DbUnreachable):
        db.try_login("postgres", os.environ["KVS_PG_PASSWORD"])
