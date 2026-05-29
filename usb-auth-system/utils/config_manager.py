from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_PATH = DATA_DIR / "app_config.json"

SETUP_STEPS = (
    "welcome",
    "check_veracrypt",
    "detect_hardware",
    "enroll_fingerprint",
    "create_workspace",
    "provision_secret",
    "setup_recovery",
    "finish",
)


class ConfigManager:
    def __init__(self, config_path: Path | str | None = None):
        self.config_path = Path(config_path) if config_path else CONFIG_PATH
        self.data_dir = self.config_path.parent

    def get_default_config(self) -> dict[str, Any]:
        return get_default_config()

    def load_config(self) -> dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        default_config = self.get_default_config()

        try:
            with self.config_path.open("r", encoding="utf-8-sig") as file:
                loaded_config = json.load(file)
        except FileNotFoundError:
            self.save_config(default_config)
            return default_config
        except (OSError, json.JSONDecodeError):
            self.save_config(default_config)
            return default_config

        if not isinstance(loaded_config, dict):
            self.save_config(default_config)
            return default_config

        merged_config = _strip_unsupported_release_keys(
            _merge_defaults(default_config, loaded_config)
        )
        if merged_config != loaded_config:
            self.save_config(merged_config)

        return merged_config

    def save_config(self, config: Mapping[str, Any]) -> dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        normalized_config = _strip_unsupported_release_keys(dict(config))
        temp_path = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(normalized_config, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(self.config_path)
        return normalized_config

    def is_setup_completed(self) -> bool:
        return bool(self.load_config().get("setup_completed", False))

    def mark_setup_step(self, step: Any) -> dict[str, Any]:
        step_value = _step_value(step)
        if step_value not in SETUP_STEPS:
            raise ValueError(f"Unknown setup step: {step_value}")

        config = self.load_config()
        config["setup_step"] = step_value
        return self.save_config(config)

    def mark_setup_completed(self) -> dict[str, Any]:
        config = self.load_config()
        config["setup_completed"] = True
        config["setup_step"] = "finish"
        return self.save_config(config)

    def update_section(self, section: str, values: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise TypeError("values must be a mapping")

        config = self.load_config()
        existing_section = config.get(section)
        if not isinstance(existing_section, dict):
            existing_section = {}

        existing_section.update(values)
        config[section] = existing_section
        return self.save_config(config)

def get_default_config() -> dict[str, Any]:
    return {
        "app_version": "0.1.0",
        "setup_completed": False,
        "setup_step": "welcome",
        "veracrypt": {
            "installed": False,
            "executable_path": "",
        },
        "hardware": {
            "device_bound": False,
            "device_id": "",
            "detected_port": "",
            "ed25519_public_key_path": "keys/esp_ed25519_public.bin",
            "x25519_public_key_path": "keys/esp_x25519_public.bin",
        },
        "fingerprint": {
            "enrolled": False,
            "fingerprint_id": "",
        },
        "workspace": {
            "container_created": False,
            "container_path": "",
            "mount_letter": "X",
        },
        "provisioning": {
            "password_generated": False,
            "password_provisioned_to_device": False,
        },
        "recovery": {
            "enabled": False,
            "recovery_blob_path": "data/recovery_blob.json",
            "consumed_flag_path": "data/recovery_consumed.flag",
        },
    }


def load_config() -> dict[str, Any]:
    return _default_manager().load_config()


def save_config(config: Mapping[str, Any]) -> dict[str, Any]:
    return _default_manager().save_config(config)


def is_setup_completed() -> bool:
    return _default_manager().is_setup_completed()


def mark_setup_step(step: Any) -> dict[str, Any]:
    return _default_manager().mark_setup_step(step)


def mark_setup_completed() -> dict[str, Any]:
    return _default_manager().mark_setup_completed()


def update_section(section: str, values: Mapping[str, Any]) -> dict[str, Any]:
    return _default_manager().update_section(section, values)


def _default_manager() -> ConfigManager:
    return ConfigManager()


def _merge_defaults(
    default_config: dict[str, Any],
    loaded_config: dict[str, Any],
) -> dict[str, Any]:
    merged_config = copy.deepcopy(default_config)

    for key, value in loaded_config.items():
        if (
            key in merged_config
            and isinstance(merged_config[key], dict)
            and isinstance(value, dict)
        ):
            merged_config[key] = _merge_defaults(merged_config[key], value)
        else:
            merged_config[key] = value

    return merged_config


def _strip_unsupported_release_keys(config: dict[str, Any]) -> dict[str, Any]:
    normalized_config = dict(config)
    normalized_config.pop("developer" + "_mode", None)
    return normalized_config


def _step_value(step: Any) -> str:
    return str(getattr(step, "value", step))
