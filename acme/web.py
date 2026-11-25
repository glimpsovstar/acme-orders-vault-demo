"""Acme Orders web front end: the page and its JSON endpoints.

Every response masks the password. Raw passwords stay in memory only, for the
database login and for comparing the AWS copy with the Vault versions.
"""
import os
import re
from dataclasses import asdict
from datetime import date, datetime
from decimal import Decimal

import psycopg
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from . import auth, db
from .aws_source import AwsSource
from .vault_source import MOUNT, PATH, VaultSource

BAD_VERSION = "version must be a whole number from 1"
NO_PASSWORD = ("No password in Vault yet at app/db. Run rotate to create one. "
               "If it was there before, its metadata was removed.")
NO_SYNC = "Secrets sync is not set up yet, so there is no AWS secret to read."


def _jsonable(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _vault_snapshot(factory, with_passwords: bool, on_error=lambda: None):
    """(latest, [{version, created, state}], {version: password}). Empty on any failure."""
    try:
        client = factory()
        if client is None:
            return None, [], {}
        v2 = client.secrets.kv.v2
        meta = v2.read_secret_metadata(path=PATH, mount_point=MOUNT)["data"]
        latest = int(meta["current_version"])
        versions, passwords = [], {}
        for key, info in sorted(meta.get("versions", {}).items(), key=lambda kv: int(kv[0])):
            n = int(key)
            state = "destroyed" if info.get("destroyed") else "deleted" if info.get("deletion_time") else "live"
            versions.append({"version": n, "created": info.get("created_time") or None, "state": state})
            if with_passwords and state == "live":
                resp = v2.read_secret_version(path=PATH, mount_point=MOUNT, version=n,
                                              raise_on_deleted_version=False)
                passwords[n] = resp["data"]["data"]["password"]
        return latest, versions, passwords
    except Exception:
        on_error()
        return None, [], {}


def _db_login(view) -> str | None:
    return {"ok": "accepted", "refused": "refused"}.get(view.state)


def _body(view, **extra):
    body = asdict(view)
    body["message"] = body["message"].replace(": ok", ": accepted")
    if view.source == "vault" and view.state == "gone" and view.version is None:
        body["message"] = NO_PASSWORD
    if view.source == "vault" and view.state == "refused" and view.version and view.latest \
            and view.version < view.latest:
        body["message"] += " Rotate both together."
    body["db_login"] = _db_login(view)
    body.update(extra)
    return body


def _parse_version():
    """(version or None, error response or None)."""
    raw = request.args.get("version")
    if raw is None:
        return None, None
    if not re.fullmatch(r"[1-9][0-9]{0,8}", raw):
        return None, (jsonify(error=BAD_VERSION, message=BAD_VERSION), 400)
    return int(raw), None


def create_app(*, vault_factory=None, sm_client=None, aws_name=None, login=None,
               fetch_orders=None, vault_reset=None) -> Flask:
    """Build the app. Arguments are for tests; the defaults read the environment."""
    app = Flask(__name__)
    if vault_reset is None:
        # Drop the cached Vault client after any Vault error; only the real client is cached.
        vault_reset = auth.reset if vault_factory is None else (lambda: None)
    vault_factory = vault_factory or auth.vault_client
    login = login or db.try_login
    fetch_orders = fetch_orders or db.orders
    if aws_name is None and sm_client is None:
        aws_name = os.environ.get("KVS_AWS_SECRET_NAME") or None
    sm = {"client": sm_client}
    # Last good latest credentials from Vault, so the orders list survives a
    # Vault blip. Process memory only: never logged, never in a response.
    last_good: dict = {}

    def sm_for_request():
        if not aws_name:
            return None
        if sm["client"] is None:
            import boto3
            sm["client"] = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION") or None)
        return sm["client"]

    @app.get("/")
    def index():
        return render_template("index.html", aws_name=aws_name)

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    @app.get("/api/secret")
    def secret():
        version, err = _parse_version()
        if err:
            return err
        source = request.args.get("source", "vault")
        if source == "vault":
            view, _ = VaultSource(vault_factory, login, vault_reset).read(version)
            _, versions, _ = _vault_snapshot(vault_factory, with_passwords=False, on_error=vault_reset)
            status = 404 if view.state == "gone" and version is not None else 200
            return jsonify(_body(view, versions=versions)), status
        if source == "aws":
            latest, _, passwords = _vault_snapshot(vault_factory, with_passwords=True, on_error=vault_reset)
            try:
                client = sm_for_request()
            except Exception:
                client = None  # no region or credentials config: shown as not configured
            view, _ = AwsSource(client, aws_name or "", login).read(passwords, latest)
            passwords.clear()
            body = _body(view)
            if not aws_name:
                body["message"] = NO_SYNC
            return jsonify(body)
        return jsonify(error="source must be vault or aws", message="source must be vault or aws"), 400

    @app.get("/api/orders")
    def orders():
        version, err = _parse_version()
        if err:
            return err
        box = {"rows": [], "user": None}

        def read_orders(user, password):
            """Doubles as the login check: the orders query is the database login."""
            box["user"] = user
            try:
                box["rows"] = fetch_orders(user, password)
                return True
            except psycopg.OperationalError as exc:
                if db.is_auth_rejection(exc):
                    return False
                raise db.DbUnreachable("orders query failed") from None
            except Exception:
                raise db.DbUnreachable("orders query failed") from None

        view, pw = VaultSource(vault_factory, read_orders, vault_reset).read(version)
        if version is None and pw is not None and box["user"] is not None:
            # A good latest read from Vault: remember it, in memory only.
            last_good.update(user=box["user"], password=pw, version=view.version)
        pw = None

        vault_failed = box["user"] is None and view.state in ("unreachable", "login_failed")
        if version is None and vault_failed and last_good:
            return jsonify(_orders_from_cache(read_orders, box, view))

        rows = box["rows"] if view.state == "ok" else []
        body = _body(view)
        status = 404 if view.state == "gone" and version is not None else 200
        return jsonify(
            orders=[{k: _jsonable(v) for k, v in row.items()} for row in rows],
            password_version=view.version, db_login=body["db_login"], state=view.state,
            message=body["message"], cached=False,
        ), status

    def _orders_from_cache(read_orders, box, view):
        """Vault is down or refused our login: keep serving with the last good password."""
        n = last_good["version"]
        why = f"{view.message}. Using the last good password from Vault, v{n}."
        try:
            ok = read_orders(last_good["user"], last_good["password"])
            state, db_login = ("ok", "accepted") if ok else ("refused", "refused")
            message = f"{why} Database login with v{n}: {db_login}"
        except db.DbUnreachable:
            state, db_login, message = "unreachable", None, f"{why} Cannot reach the database"
        rows = box["rows"] if state == "ok" else []
        return dict(orders=[{k: _jsonable(v) for k, v in row.items()} for row in rows],
                    password_version=n, db_login=db_login, state=state, message=message,
                    cached=True)

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.name, message=exc.name), exc.code

    @app.errorhandler(Exception)
    def oops(exc):
        # Never echo the exception: its text could hold a password.
        app.logger.error("unhandled %s on %s", type(exc).__name__, request.path)
        return jsonify(error="Something went wrong", message="Something went wrong"), 500

    return app
