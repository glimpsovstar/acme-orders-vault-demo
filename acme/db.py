"""Postgres access for Acme Orders. The password here is the one under test."""
import os

import psycopg
from psycopg.rows import dict_row

CONNECT_TIMEOUT = 3


def _connect(user: str, password: str, **kwargs):
    return psycopg.connect(
        host=os.environ.get("KVS_DB_HOST", "db"),
        port=int(os.environ.get("KVS_DB_PORT", "5432")),
        dbname=os.environ.get("KVS_DB_NAME", "acme"),
        user=user,
        password=password,
        connect_timeout=CONNECT_TIMEOUT,
        **kwargs,
    )


class DbUnreachable(Exception):
    """The database could not be reached (as opposed to rejecting the login)."""


AUTH_SQLSTATES = ("28P01", "28000")
# A connect-phase failure has no sqlstate, so also read the libpq message.
AUTH_MESSAGES = ("password authentication failed", "no pg_hba.conf entry")


def is_auth_rejection(err: psycopg.OperationalError) -> bool:
    if getattr(err, "sqlstate", None) in AUTH_SQLSTATES:
        return True
    text = str(err).lower()
    return any(m in text for m in AUTH_MESSAGES)


def try_login(user: str, password: str) -> bool:
    """True when the database accepts the login, False when it rejects it.

    Raises DbUnreachable for any connectivity failure.
    """
    try:
        with _connect(user, password):
            return True
    except psycopg.OperationalError as err:
        if is_auth_rejection(err):
            return False
        raise DbUnreachable(str(err)) from err
    except Exception as err:
        raise DbUnreachable(str(err)) from err


def orders(user: str, password: str) -> list[dict]:
    """Today's orders, read with the given credentials."""
    with _connect(user, password, row_factory=dict_row) as conn:
        return list(conn.execute("SELECT * FROM orders ORDER BY order_id"))
