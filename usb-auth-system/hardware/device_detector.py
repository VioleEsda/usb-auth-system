from dataclasses import dataclass
import time
from pathlib import Path

import serial
from serial.tools import list_ports

from utils.runtime_paths import resolve_app_path

ED25519_PUBLIC_KEY_PATH = resolve_app_path("keys/esp_ed25519_public.bin")


@dataclass
class HardwareDetectionResult:
    matched: bool = False
    responded: bool = False
    device_id: str = ""
    port: str = ""
    error: str = ""


def load_expected_device_id(key_path: Path | str | None = None) -> str:
    public_key_path = (
        resolve_app_path(key_path) if key_path else ED25519_PUBLIC_KEY_PATH
    )
    if not public_key_path.exists():
        raise FileNotFoundError(f"Missing key file: {public_key_path}")

    public_key_bytes = public_key_path.read_bytes()
    if len(public_key_bytes) != 32:
        raise ValueError(
            f"Invalid key file length: expected 32 bytes, got {len(public_key_bytes)} bytes"
        )

    return public_key_bytes.hex().upper()


def detect_trusted_hardware_key(
    key_path: Path | str | None = None,
    baudrate: int = 115200,
    timeout: float = 1.0,
) -> HardwareDetectionResult:
    try:
        expected_device_id = load_expected_device_id(key_path)
    except (FileNotFoundError, OSError):
        return HardwareDetectionResult(error="missing_trusted_key")
    except ValueError:
        return HardwareDetectionResult(error="invalid_trusted_key")

    return scan_hardware_key(expected_device_id, baudrate=baudrate, timeout=timeout)


def scan_hardware_key(
    expected_device_id: str,
    baudrate: int = 115200,
    timeout: float = 1.0,
) -> HardwareDetectionResult:
    expected_device_id = expected_device_id.strip().upper()
    first_response = HardwareDetectionResult()

    for port in list_ports.comports():
        ser = None

        try:
            ser = serial.Serial(port.device, baudrate, timeout=timeout)

            # ESP reset saat port dibuka.
            time.sleep(1.5)

            try:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                pass

            deadline = time.time() + 5.0
            port_done = False

            while time.time() < deadline and not port_done:
                ser.write(b"WHOAMI\n")
                ser.flush()

                read_until = time.time() + 0.7

                while time.time() < read_until and not port_done:
                    line = ser.readline().decode(errors="ignore").strip()

                    if not line:
                        continue

                    if line.startswith("DEVICE_ID:"):
                        device_id = line.split(":", 1)[1].strip().upper()
                        response = HardwareDetectionResult(
                            matched=device_id == expected_device_id,
                            responded=True,
                            device_id=device_id,
                            port=port.device,
                        )

                        ser.close()

                        if response.matched:
                            return response

                        if not first_response.responded:
                            first_response = response

                        port_done = True

                time.sleep(0.2)

            if ser.is_open:
                ser.close()

        except Exception:
            try:
                if ser and ser.is_open:
                    ser.close()
            except Exception:
                pass

    return first_response


def find_hardware_key(baudrate: int = 115200, timeout: float = 1.0) -> str | None:
    expected_device_id = load_expected_device_id()
    result = scan_hardware_key(expected_device_id, baudrate=baudrate, timeout=timeout)
    return result.port if result.matched else None
