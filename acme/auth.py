"""Vault login for the web front end: AWS IAM auth with the instance role.

The box holds no Vault secret. The client is cached, renewed before its token
expires, and replaced by a fresh IAM login when renewal fails.

KVS_DEV_VAULT_TOKEN_FILE is for local development against a dev-mode Vault
only. Never set it in compose.yaml or on a shared or production host.
"""
import os
import threading
import time
from pathlib import Path

import boto3
import hvac
import hvac.exceptions

ROLE = "acme-orders"
MOUNT = "aws"
RENEW_BEFORE = 60  # seconds before expiry
DEFAULT_TIMEOUT = 5  # seconds; hvac's own default is 30, as long as a gunicorn worker's

_lock = threading.Lock()
_client = None
_expires = 0.0


def reset() -> None:
    """Forget the cached client (tests, or after a config change)."""
    global _client, _expires
    with _lock:
        _client, _expires = None, 0.0


def _timeout() -> float:
    """Seconds each Vault request may take: KVS_VAULT_TIMEOUT, or 5."""
    try:
        value = float(os.environ.get("KVS_VAULT_TIMEOUT") or DEFAULT_TIMEOUT)
    except ValueError:
        return DEFAULT_TIMEOUT
    if value <= 0:
        return DEFAULT_TIMEOUT
    return int(value) if value.is_integer() else value


def _aws_credentials():
    creds = boto3.Session().get_credentials()
    return creds.get_frozen_credentials() if creds else None


def _iam_login(addr: str, namespace: str | None):
    creds = _aws_credentials()
    if creds is None:
        # Same outcome as Vault refusing the login: the page shows login_failed.
        raise hvac.exceptions.InvalidRequest("no AWS credentials for the IAM login")
    client = hvac.Client(url=addr, namespace=namespace, timeout=_timeout())
    resp = client.auth.aws.iam_login(
        creds.access_key, creds.secret_key, creds.token,
        header_value=os.environ.get("KVS_IAM_SERVER_ID") or None,
        role=ROLE, use_token=True,
        # hvac signs a request for the global STS endpoint (sts.amazonaws.com),
        # which must be signed for us-east-1. Not AWS_REGION.
        region=os.environ.get("KVS_IAM_STS_REGION") or "us-east-1",
        mount_point=MOUNT,
    )
    return client, int(resp["auth"]["lease_duration"])


def vault_client():
    """A logged-in hvac client, or None when VAULT_ADDR is not set.

    Raises hvac InvalidRequest or Forbidden when the IAM login is refused, which
    VaultSource reports as login_failed.
    """
    global _client, _expires
    addr = os.environ.get("VAULT_ADDR")
    if not addr:
        return None
    namespace = os.environ.get("VAULT_NAMESPACE") or None

    token_file = os.environ.get("KVS_DEV_VAULT_TOKEN_FILE")
    if token_file:
        return hvac.Client(url=addr, namespace=namespace, timeout=_timeout(),
                           token=Path(token_file).read_text().strip())

    with _lock:
        now = time.monotonic()
        if _client is not None and now < _expires - RENEW_BEFORE:
            return _client
        if _client is not None:
            try:
                resp = _client.auth.token.renew_self()
                _expires = now + int(resp["auth"]["lease_duration"])
                return _client
            except Exception:
                _client = None  # expired or not renewable: log in again
        client, ttl = _iam_login(addr, namespace)
        _client, _expires = client, now + ttl
        return _client
