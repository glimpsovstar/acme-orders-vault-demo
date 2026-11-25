"""Tests for the Acme Orders web layer. Fakes only: no network, no Postgres."""
import json
import re
from datetime import datetime, timezone
from decimal import Decimal

import hvac.exceptions
import psycopg
import pytest
import requests

from acme.web import create_app

PW = {1: "Alpha111-first-pw", 2: "Bravo222-second-pw", 3: "Tr0ub4dor&3-latest-pw"}
ROWS = [
    {"order_id": 1042, "items": "2 desk lamps", "courier": "StarTrack", "status": "Shipped",
     "total": Decimal("129.90"), "placed": datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)},
]


class FakeV2:
    def __init__(self, current=3, missing=False, deleted=(), destroyed=()):
        self.current, self.missing = current, missing
        self.deleted, self.destroyed = set(deleted), set(destroyed)

    def read_secret_metadata(self, path, mount_point):
        if self.missing:
            raise hvac.exceptions.InvalidPath()
        versions = {
            str(n): {"created_time": f"2026-11-25T0{n}:00:00.000Z",
                     "deletion_time": "2026-11-25T10:00:00Z" if n in self.deleted else "",
                     "destroyed": n in self.destroyed}
            for n in range(1, self.current + 1)
        }
        return {"data": {"current_version": self.current, "versions": versions}}

    def read_secret_version(self, path, mount_point, version=None, raise_on_deleted_version=True):
        n = version or self.current
        return {"data": {"data": {"username": "acme", "password": PW[n]}, "metadata": {"version": n}}}


class FakeClient:
    def __init__(self, v2):
        self.secrets = type("S", (), {"kv": type("K", (), {"v2": v2})()})()


class FakeSM:
    def __init__(self, n=3, error=None):
        self.n, self.error = n, error

    def get_secret_value(self, SecretId):
        if self.error:
            raise self.error
        return {"SecretString": json.dumps({"username": "acme", "password": PW[self.n]}),
                "CreatedDate": datetime(2026, 11, 25, 3, 0, tzinfo=timezone.utc)}


def accepts_latest(user, password):
    return password == PW[3]


def orders_for_latest(user, password):
    if password != PW[3]:
        raise psycopg.OperationalError(
            f'connection failed: FATAL:  password authentication failed for user "acme" ({password})')
    return ROWS


def make(v2=None, sm=None, aws_name="vault/app/db", vault_error=None, fetch_orders=orders_for_latest):
    v2 = v2 or FakeV2()

    def factory():
        if vault_error:
            raise vault_error
        return FakeClient(v2)

    app = create_app(vault_factory=factory, sm_client=sm if sm is not None else FakeSM(),
                     aws_name=aws_name, login=accepts_latest, fetch_orders=fetch_orders)
    app.testing = True
    return app.test_client()


@pytest.mark.parametrize("bad", ["abc", "0", "-1", "1.5", ""])
def test_bad_version_inputs(bad):
    c = make()
    for url in (f"/api/secret?version={bad}", f"/api/orders?version={bad}"):
        r = c.get(url)
        assert r.status_code == 400, url
        assert "version must be a whole number from 1" in r.get_json()["error"]


def test_version_beyond_latest_is_404():
    r = make().get("/api/secret?version=999")
    assert r.status_code == 404
    assert "Vault has no version 999" in r.get_json()["message"]


class AgedOutV2(FakeV2):
    """Vault keeps only versions 2 and 3 (max_versions=2)."""
    def read_secret_metadata(self, path, mount_point):
        md = super().read_secret_metadata(path, mount_point)
        del md["data"]["versions"]["1"]
        return md


def test_aged_out_version_is_404_on_both_routes():
    c = make(v2=AgedOutV2())
    for url in ("/api/secret?version=1", "/api/orders?version=1"):
        r = c.get(url)
        assert r.status_code == 404, url
        body = r.get_json()
        assert body["state"] == "gone" and body["message"] == "Vault no longer keeps version 1", url


def test_latest_ok_shape():
    body = make().get("/api/secret").get_json()
    assert body["state"] == "ok" and body["version"] == 3 and body["latest"] == 3
    assert body["db_login"] == "accepted"
    assert body["masked"] == "Tr0ub4do••••••"
    assert [v["version"] for v in body["versions"]] == [1, 2, 3]


def test_pinned_old_version_refused():
    body = make().get("/api/secret?version=1").get_json()
    assert body["state"] == "refused" and body["db_login"] == "refused"
    assert "Database login with v1: refused" in body["message"]


def test_no_password_yet():
    body = make(v2=FakeV2(missing=True)).get("/api/secret").get_json()
    assert body["state"] == "gone" and body["db_login"] is None
    assert "No password in Vault yet" in body["message"]
    orders = make(v2=FakeV2(missing=True)).get("/api/orders").get_json()
    assert orders["orders"] == [] and orders["password_version"] is None


def test_orders_ok_serialises_decimal_and_datetime():
    r = make().get("/api/orders")
    assert r.status_code == 200
    body = r.get_json()
    assert body["password_version"] == 3 and body["db_login"] == "accepted"
    assert body["orders"][0]["order_id"] == 1042
    assert body["orders"][0]["total"] == "129.90"
    assert body["orders"][0]["placed"].startswith("2026-11-25T09:00")


def test_orders_pinned_old_version_empties_and_says_why():
    body = make().get("/api/orders?version=1").get_json()
    assert body["orders"] == [] and body["db_login"] == "refused" and body["password_version"] == 1
    assert "refused" in body["message"]


def test_orders_db_down():
    def down(user, password):
        raise psycopg.OperationalError(f"connection to server failed: Connection refused {password}")
    body = make(fetch_orders=down).get("/api/orders").get_json()
    assert body["orders"] == [] and body["db_login"] is None
    assert "Cannot reach the database" in body["message"]


def test_aws_matches_latest():
    body = make().get("/api/secret?source=aws").get_json()
    assert body["source"] == "aws" and body["state"] == "ok" and body["db_login"] == "accepted"
    assert body["version"] == 3


def test_aws_waiting_for_sync():
    body = make(sm=FakeSM(n=2)).get("/api/secret?source=aws").get_json()
    assert body["state"] == "waiting" and body["db_login"] is None


def test_aws_not_configured_says_sync_not_set_up():
    body = make(aws_name=None).get("/api/secret?source=aws").get_json()
    assert body["state"] == "not_configured"
    assert "sync is not set up yet" in body["message"]


def test_vault_login_failed_and_aws_still_answers():
    c = make(vault_error=hvac.exceptions.Forbidden("permission denied"))
    assert c.get("/api/secret").get_json()["state"] == "login_failed"
    body = c.get("/api/secret?source=aws").get_json()
    assert body["state"] == "ok" and "Cannot compare with Vault right now" in body["message"]


def test_healthz():
    assert make().get("/healthz").get_json() == {"ok": True}


def test_unknown_source_is_400():
    r = make().get("/api/secret?source=gcp")
    assert r.status_code == 400


class Switch:
    """A Vault client factory that can be made to fail after some good polls."""
    def __init__(self, v2=None):
        self.v2, self.error = v2 or FakeV2(), None

    def __call__(self):
        if self.error:
            raise self.error
        return FakeClient(self.v2)


def make_switch(fetch_orders=orders_for_latest):
    sw = Switch()
    app = create_app(vault_factory=sw, sm_client=FakeSM(), aws_name="vault/app/db",
                     login=accepts_latest, fetch_orders=fetch_orders)
    app.testing = True
    return app.test_client(), sw


@pytest.mark.parametrize("err", [requests.exceptions.ConnectionError("down"),
                                 hvac.exceptions.Forbidden("token expired")])
def test_orders_survive_vault_down(err):
    c, sw = make_switch()
    assert c.get("/api/orders").get_json()["orders"]          # one good poll
    sw.error = err
    body = c.get("/api/orders").get_json()
    assert body["orders"] and body["orders"][0]["order_id"] == 1042
    assert body["password_version"] == 3 and body["db_login"] == "accepted" and body["cached"] is True
    assert "Using the last good password from Vault, v3" in body["message"]
    # The Vault panel stays honest.
    assert c.get("/api/secret").get_json()["state"] in ("unreachable", "login_failed")
    # A pinned version never falls back to the cache.
    assert c.get("/api/orders?version=3").get_json()["orders"] == []


def test_orders_cache_needs_a_good_read_first():
    c, sw = make_switch()
    sw.error = requests.exceptions.ConnectionError("down")
    body = c.get("/api/orders").get_json()
    assert body["orders"] == [] and body["cached"] is False and body["state"] == "unreachable"


def test_orders_db_down_does_not_use_cache():
    calls = []

    def flaky(user, password):
        calls.append(1)
        if len(calls) > 1:
            raise psycopg.OperationalError(f"connection refused {password}")
        return ROWS
    c, _ = make_switch(fetch_orders=flaky)
    c.get("/api/orders")
    body = c.get("/api/orders").get_json()
    assert body["orders"] == [] and body["cached"] is False and len(calls) == 2
    assert "Cannot reach the database" in body["message"]


def _cached_path_responses():
    """Orders served from the last good password, with Vault down, DB fine or DB down."""
    for fetch in (orders_for_latest, lambda u, p: (_ for _ in ()).throw(psycopg.OperationalError(f"x {p}"))):
        state = {"n": 0}

        def fetch_once_good(u, p, fetch=fetch, state=state):
            state["n"] += 1
            return ROWS if state["n"] == 1 else fetch(u, p)
        c, sw = make_switch(fetch_orders=fetch_once_good)
        c.get("/api/orders")
        sw.error = requests.exceptions.ConnectionError(f"down {PW[3]}")
        for url in ("/api/orders", "/api/secret", "/api/secret?source=aws", "/"):
            yield url, c.get(url)


def _all_responses():
    states = [
        make(), make(v2=FakeV2(deleted={2})), make(v2=FakeV2(destroyed={1})),
        make(v2=FakeV2(missing=True)), make(sm=FakeSM(n=1)), make(aws_name=None),
        make(vault_error=hvac.exceptions.InvalidRequest("bad iam")),
        make(fetch_orders=lambda u, p: (_ for _ in ()).throw(RuntimeError(f"boom {p}"))),
    ]
    urls = ["/", "/healthz", "/api/orders", "/api/orders?version=1", "/api/orders?version=abc",
            "/api/orders?version=999", "/api/secret?source=aws", "/api/secret?source=nope",
            "/api/secret?version=abc", "/api/secret?version=999", "/static/acme.js", "/nowhere"]
    urls += [f"/api/secret?version={n}" for n in (1, 2, 3)]
    for c in states:
        for url in urls:
            yield url, c.get(url)


def test_no_full_password_anywhere():
    seen = 0
    for url, r in list(_all_responses()) + list(_cached_path_responses()):
        text = r.get_data(as_text=True)
        for pw in PW.values():
            assert pw not in text, f"{url} leaked a full password"
        seen += 1
    assert seen > 50


def test_page_matches_mockup_structure():
    r = make().get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert re.search(r'class="versions"[^>]*role="group"', html)
    assert 'class="src vault"' in html and 'class="src aws"' in html
    assert "Web front end reads Vault" in html
    assert "Nightly report job reads AWS Secrets Manager" in html
    assert "<table>" in html and "<th>Order</th><th>Items</th><th>Courier</th><th>Status</th>" in html
    assert "Today's orders" in html and "Where the database password comes from" in html
    assert "vault/app/db" in html
    # Renders offline: no external URLs in the page, its CSS, or its JS.
    c = make()
    for url in ("/", "/static/acme.css", "/static/acme.js"):
        body = c.get(url).get_data(as_text=True)
        assert "http://" not in body and "https://" not in body, url
        assert "\u2014" not in body, f"em dash in {url}"
    assert c.get("/static/fonts/SchibstedGrotesk.woff2").status_code == 200
    assert c.get("/static/fonts/OFL.txt").status_code == 200


@pytest.mark.parametrize("url", ["/api/secret", "/api/secret?source=aws", "/api/orders"])
def test_vault_error_resets_client_on_every_route(url):
    resets = []

    def factory():
        raise hvac.exceptions.UnexpectedError("namespace gone")

    app = create_app(vault_factory=factory, sm_client=FakeSM(), aws_name="vault/app/db",
                     login=accepts_latest, fetch_orders=orders_for_latest,
                     vault_reset=lambda: resets.append(1))
    app.testing = True
    assert app.test_client().get(url).status_code == 200
    assert resets, "a Vault error must drop the cached client"


def test_default_app_resets_the_real_cached_client(monkeypatch):
    from acme import auth, web
    calls = []
    monkeypatch.setattr(auth, "reset", lambda: calls.append(1))

    def broken():
        raise hvac.exceptions.UnexpectedError("namespace gone")
    monkeypatch.setattr(auth, "vault_client", broken)
    app = web.create_app(sm_client=FakeSM(), aws_name="vault/app/db", login=accepts_latest)
    app.testing = True
    app.test_client().get("/api/secret")
    assert calls


def test_default_secrets_manager_client_has_short_timeouts(monkeypatch):
    """A Secrets Manager that hangs must not hold a gunicorn worker for long."""
    import boto3
    built = []

    def fake_client(service, **kwargs):
        built.append((service, kwargs))
        return FakeSM()
    monkeypatch.setattr(boto3, "client", fake_client)
    app = create_app(vault_factory=lambda: FakeClient(FakeV2()), aws_name="vault/app/db",
                     login=accepts_latest, fetch_orders=orders_for_latest)
    app.testing = True
    assert app.test_client().get("/api/secret?source=aws").get_json()["state"] == "ok"
    (service, kwargs), = built
    assert service == "secretsmanager"
    cfg = kwargs["config"]
    assert (cfg.connect_timeout, cfg.read_timeout) == (3, 5)
    assert cfg.retries == {"max_attempts": 2}
