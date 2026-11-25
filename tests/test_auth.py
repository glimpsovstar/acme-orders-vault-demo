"""Tests for acme.auth: AWS IAM login to Vault, renewal, and the local dev token file."""
import os
from types import SimpleNamespace

import hvac.exceptions
import pytest

from acme import auth


class FakeAws:
    def __init__(self, owner):
        self.owner = owner

    def iam_login(self, access_key, secret_key, session_token=None, header_value=None,
                  role=None, use_token=True, region="us-east-1", mount_point="aws"):
        self.owner.logins.append(dict(access_key=access_key, session_token=session_token,
                                      header_value=header_value, role=role, region=region,
                                      mount_point=mount_point, use_token=use_token))
        if self.owner.fail_login:
            raise self.owner.fail_login
        self.owner.token = "hvs.fake"
        return {"auth": {"client_token": "hvs.fake", "lease_duration": self.owner.ttl, "renewable": True}}


class FakeHvac:
    """Stands in for hvac.Client; records each client built."""
    def __init__(self):
        self.built, self.logins, self.renewals = [], [], 0
        self.fail_login, self.fail_renew, self.ttl = None, None, 3600

    def __call__(self, url=None, token=None, namespace=None):
        owner = self
        client = SimpleNamespace(url=url, token=token, namespace=namespace)
        client.auth = SimpleNamespace(aws=FakeAws(owner))

        def renew_self():
            owner.renewals += 1
            if owner.fail_renew:
                raise owner.fail_renew
            return {"auth": {"lease_duration": owner.ttl, "renewable": True}}
        client.auth.token = SimpleNamespace(renew_self=renew_self)
        self.built.append(client)
        return client


@pytest.fixture
def env(monkeypatch):
    for k in ("KVS_DEV_VAULT_TOKEN_FILE", "KVS_IAM_SERVER_ID", "VAULT_NAMESPACE", "KVS_IAM_STS_REGION"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example:8200")
    monkeypatch.setenv("AWS_REGION", "ap-southeast-2")
    fake = FakeHvac()
    monkeypatch.setattr(auth.hvac, "Client", fake)
    creds = SimpleNamespace(access_key="AKIAFAKE", secret_key="fake-secret", token="fake-session")
    monkeypatch.setattr(auth, "_aws_credentials", lambda: creds)
    clock = [1000.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock[0])
    auth.reset()
    yield fake, clock, monkeypatch
    auth.reset()


def test_no_vault_addr_means_not_configured(env, monkeypatch):
    monkeypatch.delenv("VAULT_ADDR")
    assert auth.vault_client() is None


def test_iam_login_arguments(env):
    fake, _, mp = env
    mp.setenv("KVS_IAM_SERVER_ID", "vault.example")
    mp.setenv("VAULT_NAMESPACE", "admin/acme-demo")
    client = auth.vault_client()
    assert client.namespace == "admin/acme-demo"
    assert fake.logins == [dict(access_key="AKIAFAKE", session_token="fake-session",
                                header_value="vault.example", role="acme-orders",
                                region="us-east-1", mount_point="aws", use_token=True)]


def test_header_value_omitted_when_unset(env):
    fake, _, _ = env
    auth.vault_client()
    assert fake.logins[0]["header_value"] is None


def test_client_reused_then_renewed_then_relogin(env):
    fake, clock, _ = env
    first = auth.vault_client()
    assert auth.vault_client() is first and len(fake.logins) == 1 and fake.renewals == 0
    clock[0] += 3600 - 30          # inside the renewal window
    assert auth.vault_client() is first and fake.renewals == 1
    fake.fail_renew = hvac.exceptions.Forbidden("expired")
    clock[0] += 3600 - 30
    second = auth.vault_client()
    assert second is not first and len(fake.logins) == 2


def test_failed_iam_login_propagates_for_login_failed(env):
    fake, _, _ = env
    fake.fail_login = hvac.exceptions.InvalidRequest("entry for role acme-orders not found")
    with pytest.raises(hvac.exceptions.InvalidRequest):
        auth.vault_client()


def test_no_aws_credentials_is_a_login_failure(env, monkeypatch):
    monkeypatch.setattr(auth, "_aws_credentials", lambda: None)
    with pytest.raises(hvac.exceptions.InvalidRequest):
        auth.vault_client()


def test_dev_token_file_skips_iam(env, tmp_path):
    fake, _, mp = env
    f = tmp_path / "token"
    f.write_text("hvs.devtoken\n")
    os.chmod(f, 0o600)
    mp.setenv("KVS_DEV_VAULT_TOKEN_FILE", str(f))
    client = auth.vault_client()
    assert client.token == "hvs.devtoken" and fake.logins == []


@pytest.mark.parametrize("sts_region", [None, ""])
def test_login_signed_for_us_east_1_when_sts_region_unset_or_empty(env, sts_region):
    """AWS_REGION is for Secrets Manager; the global STS request is signed for us-east-1."""
    fake, _, mp = env
    if sts_region is not None:
        mp.setenv("KVS_IAM_STS_REGION", sts_region)
    mp.setenv("AWS_REGION", "ap-southeast-2")
    auth.vault_client()
    assert fake.logins[0]["region"] == "us-east-1"


def test_sts_region_override(env):
    fake, _, mp = env
    mp.setenv("KVS_IAM_STS_REGION", "ap-southeast-2")
    auth.vault_client()
    assert fake.logins[0]["region"] == "ap-southeast-2"
