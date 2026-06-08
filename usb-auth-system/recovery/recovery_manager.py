import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from pathlib import Path

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.runtime_paths import get_app_base_dir, resolve_app_path


logger = logging.getLogger(__name__)


class RecoveryError(Exception):
    pass


class RecoveryManager:
    KDF_ITERATIONS = 600000
    AAD_PREFIX = b"USBDEF_SERVER_RECOVERY_V1"
    REQUIRED_ENV_KEYS = (
        "SUPABASE_RECOVERY_BASE_URL",
        "SUPABASE_ANON_KEY",
    )

    def __init__(self, project_root: Path | None = None, timeout: float = 10.0):
        self.project_root = get_app_base_dir()
        self.data_dir = resolve_app_path("data/recovery")
        self.blob_path = self.data_dir / "recovery_blob.json"
        self.consumed_flag_path = self.data_dir / "recovery_consumed.flag"
        self.env_path = resolve_app_path(".env")
        self.env_file_found = False
        self.env_read_error = ""
        self.env_values: dict[str, str] = {}
        self.timeout = timeout
        self.last_error = ""

        self._load_dotenv()
        self._refresh_recovery_config()

    def has_recovery_blob(self) -> bool:
        return self.blob_path.exists()

    def is_recovery_consumed(self) -> bool:
        if self.consumed_flag_path.exists():
            return True

        if not self.blob_path.exists():
            return False

        try:
            return self._load_blob().get("status") == "consumed"
        except RecoveryError:
            return False

    def get_recovery_status(self) -> str:
        if self.is_recovery_consumed():
            return "consumed"

        if self.has_recovery_blob():
            return "active"

        return "not_created"

    def create_recovery_blob(self, veracrypt_password: str) -> str:
        self.last_error = ""

        status = self.get_recovery_status()
        if status == "active":
            raise RecoveryError("Recovery key already exists.")
        if status == "consumed":
            raise RecoveryError("Recovery key has already been consumed.")

        base_url = self._require_recovery_config()
        recovery_key = self._generate_recovery_key()
        normalized_key = self._normalize_recovery_key(recovery_key)
        salt = secrets.token_bytes(16)
        derived_key_material = self._derive_key_material(
            normalized_key,
            salt,
            self.KDF_ITERATIONS,
        )

        recovery_id = self._sha256_hex(b"RECOVERY_ID" + derived_key_material)
        consume_token = self._sha256_hex(b"CONSUME_TOKEN" + derived_key_material)
        endpoint_url = self._endpoint_url("create_recovery", base_url)
        logger.debug("Calling recovery endpoint: create_recovery")
        response = self._post_json(
            endpoint_url,
            {
                "recovery_id": recovery_id,
                "consume_token": consume_token,
            },
        )
        server_share = self._server_share_from_response(response)
        encryption_key = hashlib.sha256(
            b"RECOVERY_ENC" + derived_key_material + server_share
        ).digest()

        nonce = secrets.token_bytes(12)
        aad = self.AAD_PREFIX + recovery_id.encode("ascii")
        password_bytes = veracrypt_password.encode("utf-8")

        try:
            ciphertext = AESGCM(encryption_key).encrypt(nonce, password_bytes, aad)
        finally:
            password_bytes = None

        blob = {
            "version": 1,
            "mode": "server_side_one_time",
            "status": "active",
            "kdf": "pbkdf2-sha256",
            "iterations": self.KDF_ITERATIONS,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "recovery_id": recovery_id,
            "server": base_url,
        }
        self._write_blob(blob)
        return recovery_key

    def recover_password(self, recovery_key: str) -> str | None:
        self.last_error = ""

        if self.is_recovery_consumed():
            self.last_error = "Recovery key has already been consumed."
            return None

        if not self.has_recovery_blob():
            self.last_error = "Recovery key has not been created."
            return None

        try:
            self._require_recovery_config()
            blob = self._load_blob()
            self._validate_blob(blob)

            normalized_key = self._normalize_recovery_key(recovery_key)
            salt = bytes.fromhex(blob["salt"])
            iterations = int(blob["iterations"])
            derived_key_material = self._derive_key_material(
                normalized_key,
                salt,
                iterations,
            )

            recovery_id = self._sha256_hex(b"RECOVERY_ID" + derived_key_material)
            if not hmac.compare_digest(recovery_id, blob["recovery_id"]):
                self.last_error = "Recovery key does not match this recovery blob."
                return None

            consume_token = self._sha256_hex(b"CONSUME_TOKEN" + derived_key_material)
            endpoint_url = self._endpoint_url("consume_recovery", blob["server"])
            logger.debug("Calling recovery endpoint: consume_recovery")
            response = self._post_json(
                endpoint_url,
                {
                    "recovery_id": recovery_id,
                    "consume_token": consume_token,
                },
            )
            server_share = self._server_share_from_response(response)
            encryption_key = hashlib.sha256(
                b"RECOVERY_ENC" + derived_key_material + server_share
            ).digest()

            nonce = bytes.fromhex(blob["nonce"])
            ciphertext = bytes.fromhex(blob["ciphertext"])
            aad = self.AAD_PREFIX + recovery_id.encode("ascii")

            try:
                password_bytes = AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)
            except InvalidTag:
                self.mark_consumed()
                self.last_error = "Recovery decrypt failed."
                return None

            try:
                password = password_bytes.decode("utf-8")
            except UnicodeDecodeError:
                self.mark_consumed()
                self.last_error = "Recovered password is not valid UTF-8."
                return None
            finally:
                password_bytes = None

            self.mark_consumed()
            self.delete_blob()
            return password
        except RecoveryError as e:
            self.last_error = str(e)
            return None
        except (OSError, ValueError, json.JSONDecodeError) as e:
            self.last_error = f"Invalid local recovery data: {e}"
            return None

    def mark_consumed(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

        if self.blob_path.exists():
            try:
                blob = self._load_blob()
                blob["status"] = "consumed"
                self._write_blob(blob)
            except RecoveryError:
                pass

        self.consumed_flag_path.write_text("consumed\n", encoding="utf-8")

    def delete_blob(self):
        try:
            self.blob_path.unlink()
        except FileNotFoundError:
            pass

    def _load_dotenv(self):
        self.env_values = {}
        self.env_read_error = ""
        env_path = self.env_path
        self.env_file_found = env_path.is_file()

        if not env_path.exists():
            return

        try:
            for raw_line in env_path.read_text(encoding="utf-8-sig").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key:
                    self.env_values[key] = value
                    if key not in os.environ:
                        os.environ[key] = value
        except OSError as e:
            self.env_read_error = str(e)
            return

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        normalized = url.strip().rstrip("/")

        while True:
            for suffix in ("/create_recovery", "/consume_recovery"):
                if normalized.endswith(suffix):
                    normalized = normalized[: -len(suffix)].rstrip("/")
                    break
            else:
                return normalized

    def _endpoint_url(self, endpoint: str, base_url: str | None = None) -> str:
        normalized_base_url = self._normalize_base_url(
            self.base_url if base_url is None else base_url
        )
        return f"{normalized_base_url}/{endpoint.strip('/')}"

    def _refresh_recovery_config(self) -> None:
        self.base_url = self._normalize_base_url(
            self.env_values.get("SUPABASE_RECOVERY_BASE_URL", "")
        )
        self.anon_key = self.env_values.get("SUPABASE_ANON_KEY", "").strip()

    def get_configuration_diagnostics(self) -> list[str]:
        self._load_dotenv()
        self._refresh_recovery_config()
        return [
            f"Recovery .env path: {self.env_path}",
            f"Recovery .env found: {'yes' if self.env_file_found else 'no'}",
            (
                "SUPABASE_RECOVERY_BASE_URL found: "
                f"{'yes' if bool(self.base_url) else 'no'}"
            ),
            f"SUPABASE_ANON_KEY found: {'yes' if bool(self.anon_key) else 'no'}",
        ]

    def _require_recovery_config(self) -> str:
        self._load_dotenv()
        self._refresh_recovery_config()

        if not self.env_file_found:
            raise RecoveryError(
                f"Recovery configuration file was not found at: {self.env_path}"
            )

        if self.env_read_error:
            raise RecoveryError(
                f"Recovery configuration file could not be read at: {self.env_path}"
            )

        missing = [
            key
            for key in self.REQUIRED_ENV_KEYS
            if not self.env_values.get(key, "").strip()
        ]
        if missing:
            raise RecoveryError(
                "Recovery configuration is incomplete. "
                "SUPABASE_RECOVERY_BASE_URL or SUPABASE_ANON_KEY is missing."
            )

        return self.base_url

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}

        if self.anon_key:
            headers["apikey"] = self.anon_key
            headers["Authorization"] = f"Bearer {self.anon_key}"

        return headers

    def _post_json(self, url: str, payload: dict) -> dict:
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise RecoveryError(f"Recovery server request failed: {e}") from e

        try:
            data = response.json()
        except ValueError as e:
            raise RecoveryError("Recovery server returned invalid JSON.") from e

        if response.status_code != 200:
            error = data.get("error", f"HTTP {response.status_code}")
            raise RecoveryError(f"Recovery server rejected request: {error}")

        if not data.get("ok"):
            error = data.get("error", "unknown_error")
            raise RecoveryError(f"Recovery server rejected request: {error}")

        return data

    def _server_share_from_response(self, response: dict) -> bytes:
        server_share_hex = response.get("server_share")
        if not isinstance(server_share_hex, str):
            raise RecoveryError("Recovery server response missing server_share.")

        try:
            server_share = bytes.fromhex(server_share_hex)
        except ValueError as e:
            raise RecoveryError("Recovery server returned invalid server_share.") from e

        if len(server_share) != 32:
            raise RecoveryError("Recovery server returned invalid server_share length.")

        return server_share

    def _write_blob(self, blob: dict):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temp_path = self.blob_path.with_suffix(".json.tmp")
        temp_path.write_text(
            json.dumps(blob, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temp_path.replace(self.blob_path)

    def _load_blob(self) -> dict:
        try:
            with self.blob_path.open("r", encoding="utf-8-sig") as f:
                blob = json.load(f)
        except FileNotFoundError as e:
            raise RecoveryError("Recovery blob does not exist.") from e
        except (OSError, json.JSONDecodeError) as e:
            raise RecoveryError(f"Failed to read recovery blob: {e}") from e

        if not isinstance(blob, dict):
            raise RecoveryError("Recovery blob is invalid.")

        return blob

    def _validate_blob(self, blob: dict):
        required = {
            "version",
            "mode",
            "status",
            "kdf",
            "iterations",
            "salt",
            "nonce",
            "ciphertext",
            "recovery_id",
            "server",
        }
        missing = required.difference(blob)
        if missing:
            raise RecoveryError(f"Recovery blob missing fields: {', '.join(sorted(missing))}")

        if blob["version"] != 1:
            raise RecoveryError("Unsupported recovery blob version.")
        if blob["mode"] != "server_side_one_time":
            raise RecoveryError("Unsupported recovery blob mode.")
        if blob["status"] != "active":
            raise RecoveryError("Recovery blob is not active.")
        if blob["kdf"] != "pbkdf2-sha256":
            raise RecoveryError("Unsupported recovery KDF.")

        salt = bytes.fromhex(blob["salt"])
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])

        if len(salt) != 16:
            raise RecoveryError("Recovery blob has invalid salt length.")
        if len(nonce) != 12:
            raise RecoveryError("Recovery blob has invalid nonce length.")
        if len(ciphertext) <= 16:
            raise RecoveryError("Recovery blob has invalid ciphertext length.")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", blob["recovery_id"]):
            raise RecoveryError("Recovery blob has invalid recovery_id.")
        if not isinstance(blob["server"], str) or not blob["server"].strip():
            raise RecoveryError("Recovery blob has invalid server URL.")

    def _generate_recovery_key(self) -> str:
        raw_key = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        groups = [raw_key[i:i + 4] for i in range(0, len(raw_key), 4)]
        return "RK-" + "-".join(groups)

    def _normalize_recovery_key(self, recovery_key: str) -> str:
        normalized = recovery_key.upper().replace(" ", "").replace("-", "")

        if normalized.startswith("RK"):
            normalized = normalized[2:]

        if not re.fullmatch(r"[A-Z2-7]{32}", normalized):
            raise RecoveryError("Recovery key format is invalid.")

        return normalized

    def _derive_key_material(self, normalized_key: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(normalized_key.encode("ascii"))

    def _sha256_hex(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
