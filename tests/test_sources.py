"""Tests for the Acme Orders secret sources. Fakes only: no network, no Postgres."""
import json
from datetime import datetime, timezone

import hvac.exceptions
import psycopg
import pytest
import requests
from botocore.exceptions import ClientError

from acme import db
from acme.aws_source import AwsSource
from acme.model import SecretView, mask
from acme.vault_source import VaultSource

PW = {1: "Alpha111pw", 2: "Bravo222pw", 3: "Tr0ub4dor&3"}
LATEST_PW = PW[3]


def meta(current=3, **overrides):
    versions = {
        str(n): {"created_time": f"2026-11-2{n}T01:02:03.000Z", "deletion_time": "", "destroyed": False}
        for n in range(1, current + 1)
    }
    for n, patch in overrides.items():
        versions[n.lstrip("v")].update(patch)
    return {"data": {"current_version": current, "versions": versions}}


class FakeV2:
    def __init__(self, metadata=None, error=None):
        self.metadata = metadata if metadata is not None else meta()
        self.error = error
        self.calls = []

    def read_secret_metadata(self, path, mount_point):
        assert (path, mount_point) == ("db", "app")
        if self.error:
            raise self.error
        if self.metadata == "missing":
            raise hvac.exceptions.InvalidPath()
        return self.metadata

    def read_secret_version(self, path, mount_point, version=None, raise_on_deleted_version=True):
        assert (path, mount_point) == ("db", "app")
        assert raise_on_deleted_version is False
        n = version or int(self.metadata["data"]["current_version"])
        self.calls.append(n)
        return {"data": {"data": {"username": "acme", "password": PW[n]}, "metadata": {"version": n}}}


class FakeClient:
    def __init__(self, v2):
        self.secrets = type("S", (), {"kv": type("K", (), {"v2": v2})()})()


def vault(v2=None, login=lambda u, p: p == LATEST_PW):
    v2 = v2 or FakeV2()
    return VaultSource(lambda: FakeClient(v2), login), v2


def test_mask():
    assert mask("Tr0ub4dor&3") == "Tr0ub4do••••••"
    assert mask("short") == "••••••"
    assert mask("12345678") == "••••••"


def test_latest_ok():
    src, _ = vault()
    view, raw = src.read(None)
    assert isinstance(view, SecretView)
    assert (view.source, view.state, view.version, view.latest) == ("vault", "ok", 3, 3)
    assert view.masked == "Tr0ub4do••••••"
    assert view.changed == "2026-11-23T01:02:03.000Z"
    assert raw == LATEST_PW
    assert LATEST_PW not in repr(view)


def test_pinned_old_version_refused():
    src, _ = vault()
    view, raw = src.read(1)
    assert view.state == "refused"
    assert (view.version, view.latest) == (1, 3)
    assert view.message == (
        "Database login with v1: refused. Version 1 is still readable in Vault, "
        "but the database user now has the v3 password."
    )
    assert raw == PW[1]


def test_pinned_deleted_version():
    src, v2 = vault(FakeV2(meta(v2={"deletion_time": "2026-11-25T02:00:00Z"})))
    view, raw = src.read(2)
    assert (view.state, view.version, view.latest) == ("deleted", 2, 3)
    assert raw is None and view.masked is None
    assert 2 not in v2.calls


def test_pinned_destroyed_version():
    src, _ = vault(FakeV2(meta(v1={"destroyed": True})))
    view, raw = src.read(1)
    assert (view.state, view.version) == ("destroyed", 1)
    assert raw is None and view.masked is None


def test_latest_deleted():
    src, _ = vault(FakeV2(meta(v3={"deletion_time": "2026-11-25T02:00:00Z"})))
    view, raw = src.read(None)
    assert (view.state, view.version, view.latest) == ("deleted", 3, 3)
    assert raw is None


def test_metadata_gone():
    src, _ = vault(FakeV2("missing"))
    view, raw = src.read(None)
    assert view.state == "gone"
    assert raw is None


def test_version_beyond_latest():
    src, _ = vault()
    view, raw = src.read(9)
    assert (view.state, view.version, view.latest) == ("gone", 9, 3)
    assert view.message == "Vault has no version 9"
    assert raw is None


def test_aged_out_version_is_gone_without_a_login():
    """Past max_versions, Vault drops the oldest versions from the metadata."""
    md = meta()
    del md["data"]["versions"]["1"]
    logins = []
    src, v2 = vault(FakeV2(md), login=lambda u, p: logins.append(p) or True)
    view, raw = src.read(1)
    assert (view.state, view.version, view.latest) == ("gone", 1, 3)
    assert view.message == "Vault no longer keeps version 1"
    assert raw is None and view.masked is None
    assert v2.calls == [] and logins == []


@pytest.mark.parametrize("err", [
    requests.exceptions.ConnectionError("boom"),
    requests.exceptions.ReadTimeout("no answer within the client timeout"),
    hvac.exceptions.VaultDown("sealed"),
])
def test_vault_down_does_not_break_page(err):
    src, _ = vault(FakeV2(error=err))
    view, raw = src.read(None)
    assert view.state == "unreachable"
    assert view.message == "Cannot reach Vault"
    assert raw is None


def test_vault_down_in_factory():
    def factory():
        raise requests.exceptions.ConnectionError("boom")
    view, _ = VaultSource(factory, lambda u, p: True).read(None)
    assert view.state == "unreachable"


@pytest.mark.parametrize("err", [hvac.exceptions.Forbidden(), hvac.exceptions.Unauthorized()])
def test_login_failed(err):
    src, _ = vault(FakeV2(error=err))
    view, _ = src.read(None)
    assert (view.state, view.message) == ("login_failed", "Vault login failed")


def test_login_failed_in_factory():
    def factory():
        raise hvac.exceptions.Forbidden("iam login denied")
    view, _ = VaultSource(factory, lambda u, p: True).read(None)
    assert (view.state, view.message) == ("login_failed", "Vault login failed")


def test_not_configured():
    view, raw = VaultSource(lambda: None, lambda u, p: True).read(None)
    assert view.state == "not_configured" and raw is None


def test_unexpected_error_never_escapes():
    src, _ = vault(FakeV2(error=RuntimeError("weird")))
    view, raw = src.read(None)
    assert view.state == "unreachable" and raw is None


# ---- AWS ----

def aws_error(code, message="x"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "GetSecretValue")


class FakeSM:
    def __init__(self, password=None, error=None):
        self.password, self.error = password, error

    def get_secret_value(self, SecretId):
        assert SecretId == "acme/db"
        if self.error:
            raise self.error
        return {
            "SecretString": json.dumps({"username": "acme", "password": self.password}),
            "CreatedDate": datetime(2026, 11, 25, 3, 0, tzinfo=timezone.utc),
        }


def aws(sm, login=lambda u, p: p == LATEST_PW):
    return AwsSource(sm, "acme/db", login)


def test_aws_matches_latest():
    view, raw = aws(FakeSM(LATEST_PW)).read(PW, 3)
    assert (view.source, view.state, view.version, view.latest) == ("aws", "ok", 3, 3)
    assert "matches Vault v3" in view.message
    assert view.masked == "Tr0ub4do••••••"
    assert view.changed == "2026-11-25T03:00:00+00:00"
    assert raw == LATEST_PW


def test_aws_behind_vault_shows_waiting():
    view, raw = aws(FakeSM(PW[2])).read(PW, 3)
    assert view.state == "waiting"
    assert (view.version, view.latest) == (2, 3)
    assert view.message == "Waiting for sync (AWS has v2, Vault has v3)"


def test_aws_matches_no_readable_version_login_ok():
    view, _ = aws(FakeSM("Zulu999pwx"), login=lambda u, p: True).read(PW, 3)
    assert view.state == "ok"
    assert "does not match a readable Vault version" in view.message


def test_aws_matches_no_readable_version_login_refused():
    view, _ = aws(FakeSM("Zulu999pwx"), login=lambda u, p: False).read(PW, 3)
    assert view.state == "refused"
    assert "does not match a readable Vault version" in view.message


def test_aws_login_refused_even_when_matching_latest():
    view, _ = aws(FakeSM(LATEST_PW), login=lambda u, p: False).read(PW, 3)
    assert view.state == "refused"


def test_aws_secret_missing():
    view, raw = aws(FakeSM(error=aws_error("ResourceNotFoundException"))).read(PW, 3)
    assert (view.state, view.message) == ("gone", "Not in AWS Secrets Manager")
    assert raw is None


def test_aws_marked_for_deletion():
    err = aws_error("InvalidRequestException",
                    "You can't perform this operation on the secret because it was marked for deletion.")
    view, _ = aws(FakeSM(error=err)).read(PW, 3)
    assert view.state == "deleted"


def test_aws_unreachable_and_not_configured():
    from botocore.exceptions import EndpointConnectionError
    view, _ = aws(FakeSM(error=EndpointConnectionError(endpoint_url="https://x"))).read(PW, 3)
    assert view.state == "unreachable"
    view, _ = AwsSource(None, "acme/db", lambda u, p: True).read(PW, 3)
    assert view.state == "not_configured"


# ---- fix round 1 ----

def raising_login(u, p):
    raise db.DbUnreachable("down")


def test_vault_db_unreachable():
    src, _ = vault(login=raising_login)
    view, _ = src.read(None)
    assert (view.state, view.message) == ("unreachable", "Cannot reach the database")


def test_aws_db_unreachable():
    view, _ = aws(FakeSM(LATEST_PW), login=raising_login).read(PW, 3)
    assert (view.state, view.message) == ("unreachable", "Cannot reach the database")


def test_vault_invalid_request_is_login_failed():
    def factory():
        raise hvac.exceptions.InvalidRequest("iam login 400")
    view, _ = VaultSource(factory, lambda u, p: True).read(None)
    assert view.state == "login_failed"


def test_aws_no_vault_info():
    view, _ = aws(FakeSM(LATEST_PW)).read({}, None)
    assert view.state == "ok"
    assert "Cannot compare with Vault right now" in view.message


def test_aws_vault_latest_deleted_still_waiting():
    readable = {1: PW[1], 2: PW[2]}
    view, _ = aws(FakeSM(PW[2])).read(readable, 3)
    assert view.state == "waiting"
    assert view.message == "Waiting for sync (AWS has v2, Vault has v3)"


@pytest.mark.parametrize("message,expected", [
    ('connection failed: connection to server at "127.0.0.1", port 5432 failed: '
     'FATAL:  password authentication failed for user "acme"', False),
    ('connection failed: FATAL:  no pg_hba.conf entry for host "10.0.0.1", user "acme"', False),
    ('connection failed: connection to server at "127.0.0.1", port 55999 failed: Connection refused', "down"),
    ("connection failed: timeout expired", "down"),
])
def test_try_login_classification(monkeypatch, message, expected):
    err = psycopg.OperationalError(message)
    assert err.sqlstate is None

    def fake_connect(**kw):
        raise err
    monkeypatch.setattr(db.psycopg, "connect", fake_connect)
    if expected == "down":
        with pytest.raises(db.DbUnreachable):
            db.try_login("acme", "x")
    else:
        assert db.try_login("acme", "x") is expected


def test_try_login_non_psycopg_error_is_unreachable(monkeypatch):
    def fake_connect(**kw):
        raise OSError("no route")
    monkeypatch.setattr(db.psycopg, "connect", fake_connect)
    with pytest.raises(db.DbUnreachable):
        db.try_login("acme", "x")


@pytest.mark.parametrize("exc", [psycopg.errors.InvalidPassword("bad"),
                                 psycopg.errors.InvalidAuthorizationSpecification("bad")])
def test_try_login_sqlstate_rejection(monkeypatch, exc):
    def fake_connect(**kw):
        raise exc
    monkeypatch.setattr(db.psycopg, "connect", fake_connect)
    assert db.try_login("acme", "x") is False


def test_try_login_ok(monkeypatch):
    class Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(db.psycopg, "connect", lambda **kw: Conn())
    assert db.try_login("acme", "x") is True


class CachingFactory:
    """Mimics auth.vault_client: hands out one cached client until reset()."""
    def __init__(self, v2s):
        self.v2s, self.built, self.client = list(v2s), 0, None

    def __call__(self):
        if self.client is None:
            self.client = FakeClient(self.v2s[self.built])
            self.built += 1
        return self.client

    def reset(self):
        self.client = None


@pytest.mark.parametrize("err", [
    hvac.exceptions.Forbidden(),
    hvac.exceptions.InvalidPath(),
    requests.exceptions.ConnectionError("boom"),
    hvac.exceptions.UnexpectedError("namespace gone"),
])
def test_vault_error_drops_cached_client(err):
    stale = FakeV2(error=err) if not isinstance(err, hvac.exceptions.InvalidPath) else FakeV2(metadata="missing")
    factory = CachingFactory([stale, FakeV2()])
    src = VaultSource(factory, lambda u, p: p == LATEST_PW, factory.reset)
    first, _ = src.read(None)
    assert first.state != "ok"
    second, _ = src.read(None)
    assert factory.built == 2
    assert second.state == "ok"


def test_db_unreachable_keeps_cached_client():
    factory = CachingFactory([FakeV2(), FakeV2()])
    def login(u, p):
        raise db.DbUnreachable("down")
    src = VaultSource(factory, login, factory.reset)
    view, _ = src.read(None)
    assert view.state == "unreachable" and factory.client is not None and factory.built == 1
