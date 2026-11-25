"""Reads the DB password from HCP Vault KV v2 (mount app, secret db)."""
from typing import Callable

import hvac.exceptions
import requests

from .db import DbUnreachable
from .model import SecretView, mask

MOUNT = "app"
PATH = "db"

Login = Callable[[str, str], bool]


def _noop() -> None:
    pass


class VaultSource:
    def __init__(self, client_factory: Callable[[], object], login: Login,
                 on_error: Callable[[], None] = _noop):
        """on_error runs after any Vault error, so the next read builds a fresh
        client (for example after the namespace was deleted and created again)."""
        self._factory = client_factory
        self._login = login
        self._on_error = on_error

    def _view(self, state, message, version=None, latest=None, masked=None, changed=None):
        return SecretView("vault", state, version, latest, masked, changed, message)

    def read(self, version: int | None) -> tuple[SecretView, str | None]:
        try:
            return self._read(version)
        except DbUnreachable:
            return self._view("unreachable", "Cannot reach the database"), None
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                hvac.exceptions.VaultDown):
            self._on_error()
            return self._view("unreachable", "Cannot reach Vault"), None
        except (hvac.exceptions.Forbidden, hvac.exceptions.Unauthorized,
                hvac.exceptions.InvalidRequest):
            self._on_error()
            return self._view("login_failed", "Vault login failed"), None
        except Exception:
            # The page must keep refreshing, whatever went wrong.
            self._on_error()
            return self._view("unreachable", "Cannot read from Vault"), None

    def _read(self, version):
        client = self._factory()
        if client is None:
            return self._view("not_configured", "Vault is not configured"), None
        v2 = client.secrets.kv.v2

        try:
            meta = v2.read_secret_metadata(path=PATH, mount_point=MOUNT)["data"]
        except hvac.exceptions.InvalidPath:
            # Also what a stale client sees in a namespace created again.
            self._on_error()
            return self._view("gone", "The secret is not in Vault (metadata removed)"), None

        latest = int(meta["current_version"])
        n = latest if version is None else version
        if n > latest or n < 1:
            return self._view("gone", f"Vault has no version {n}", version=n, latest=latest), None

        kept = meta.get("versions", {})
        if str(n) not in kept:
            # Past max_versions, Vault drops the oldest versions entirely.
            return self._view("gone", f"Vault no longer keeps version {n}", version=n, latest=latest), None
        info = kept[str(n)]
        changed = info.get("created_time") or None
        if info.get("destroyed"):
            return self._view("destroyed", f"Version {n} was destroyed in Vault",
                              n, latest, changed=changed), None
        if info.get("deletion_time"):
            return self._view("deleted", f"Version {n} was deleted in Vault",
                              n, latest, changed=changed), None

        resp = v2.read_secret_version(path=PATH, mount_point=MOUNT, version=n,
                                      raise_on_deleted_version=False)
        data = resp["data"]["data"]
        user, password = data["username"], data["password"]

        if self._login(user, password):
            state, message = "ok", f"Database login with v{n}: ok"
        else:
            state = "refused"
            if n < latest:
                message = (f"Database login with v{n}: refused. Version {n} is still readable "
                           f"in Vault, but the database user now has the v{latest} password.")
            else:
                message = f"Database login with v{n}: refused. The database does not accept this password."
        return self._view(state, message, n, latest, mask(password), changed), password
