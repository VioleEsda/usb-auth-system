import time
from pathlib import Path

import serial
from serial.tools import list_ports


PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = PROJECT_ROOT / "keys"
ED25519_PUBLIC_KEY_PATH = KEY_DIR / "esp_ed25519_public.bin"


def load_expected_device_id() -> str:
    if not ED25519_PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(f"Missing key file: {ED25519_PUBLIC_KEY_PATH}")

    return ED25519_PUBLIC_KEY_PATH.read_bytes().hex().upper()


def find_hardware_key(baudrate: int = 115200, timeout: float = 1.0) -> str | None:
    expected_device_id = load_expected_device_id()

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

            while time.time() < deadline:
                ser.write(b"WHOAMI\n")
                ser.flush()

                read_until = time.time() + 0.7

                while time.time() < read_until:
                    line = ser.readline().decode(errors="ignore").strip()

                    if not line:
                        continue

                    if line.startswith("DEVICE_ID:"):
                        device_id = line.split(":", 1)[1].strip().upper()

                        ser.close()

                        if device_id == expected_device_id:
                            return port.device

                        break

                time.sleep(0.2)

            ser.close()

        except Exception:
            try:
                if ser and ser.is_open:
                    ser.close()
            except Exception:
                pass

    return None