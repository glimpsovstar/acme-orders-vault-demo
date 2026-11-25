"""Reads the synced DB password from AWS Secrets Manager (what the report job sees)."""
import json
from typing import Callable

from botocore.exceptions import BotoCoreError, ClientError

from .db import DbUnreachable
from .model import SecretView, mask

Login = Callable[[str, str], bool]


class AwsSource:
    def __init__(self, sm_client, name: str, login: Login):
        self._sm = sm_client
        self._name = name
        self._login = login

    def _view(self, state, message, version=None, latest=None, masked=None, changed=None):
        return SecretView("aws", state, version, latest, masked, changed, message)

    def read(self, vault_versions: dict[int, str], latest: int | None) -> tuple[SecretView, str | None]:
        try:
            return self._read(vault_versions, latest)
        except ClientError as err:
            return self._client_error(err), None
        except DbUnreachable:
            return self._view("unreachable", "Cannot reach the database"), None
        except BotoCoreError:
            return self._view("unreachable", "Cannot reach AWS Secrets Manager"), None
        except Exception:
            return self._view("unreachable", "Cannot read from AWS Secrets Manager"), None

    def _client_error(self, err: ClientError) -> SecretView:
        code = err.response.get("Error", {}).get("Code", "")
        text = err.response.get("Error", {}).get("Message", "")
        if code == "ResourceNotFoundException":
            return self._view("gone", "Not in AWS Secrets Manager")
        if code == "InvalidRequestException" and "marked for deletion" in text:
            return self._view("deleted", "Marked for deletion in AWS Secrets Manager")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ExpiredTokenException"):
            return self._view("login_failed", "AWS access denied")
        return self._view("unreachable", "Cannot read from AWS Secrets Manager")

    def _read(self, vault_versions, latest):
        if self._sm is None:
            return self._view("not_configured", "AWS Secrets Manager is not configured"), None

        resp = self._sm.get_secret_value(SecretId=self._name)
        stamp = resp.get("CreatedDate")
        changed = stamp.isoformat() if hasattr(stamp, "isoformat") else (stamp or None)

        try:
            data = json.loads(resp["SecretString"])
            user, password = data["username"], data["password"]
        except (KeyError, TypeError, ValueError):
            return self._view("not_configured",
                              "The AWS secret is not JSON with username and password",
                              changed=changed), None

        matches = [n for n, pw in vault_versions.items() if pw == password]
        matched = max(matches) if matches else None
        masked = mask(password)

        if latest is not None and matched is not None and matched < latest:
            return self._view("waiting", f"Waiting for sync (AWS has v{matched}, Vault has v{latest})",
                              matched, latest, masked, changed), password

        if latest is None:
            note = "Cannot compare with Vault right now"
        elif matched is None:
            note = "The AWS password does not match a readable Vault version"
        else:
            note = f"AWS matches Vault v{matched}"
        ok = self._login(user, password)
        message = f"{note}. Database login: {'ok' if ok else 'refused'}"
        return self._view("ok" if ok else "refused", message, matched, latest, masked, changed), password
