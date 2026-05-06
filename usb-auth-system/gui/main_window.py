import hashlib
import secrets
import threading
import time
from pathlib import Path
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QMessageBox,
)

# from hardware.mock_device import MockDevice
from hardware.serial_device import SerialDevice
from container.veracrypt_controller import VeraCryptController
from recovery.recovery_manager import RecoveryError, RecoveryManager

class MainWindow(QWidget):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    recovery_key_generated_signal = pyqtSignal(str)
    recovery_generation_failed_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.device = SerialDevice(baudrate=115200)
        self.veracrypt = VeraCryptController()
        self.project_root = Path(__file__).resolve().parents[1]
        self.recovery_manager = RecoveryManager(self.project_root)
        self.keys_dir = self.project_root / "keys"
        self.ed25519_public_key_path = self.keys_dir / "esp_ed25519_public.bin"
        self.x25519_public_key_path = self.keys_dir / "esp_x25519_public.bin"
        self.container_path = r"C:\PA\usb-auth-system\demo_container.hc"
        self.last_auth_time = 0
        self.cooldown = 3  # detik anti spam
        self.mounted = False
        self.mounted_via_recovery = False
        self.unlock_in_progress = False
        self.unlock_lock = threading.Lock()
        self.pending_recovery_generation = False
        self.recovery_generation_in_progress = False
        self.recovery_generation_lock = threading.Lock()
        self.heartbeat_in_progress = False
        self.heartbeat_lock = threading.Lock()
        self.device_lost_handled = False
        self.device_lost_lock = threading.Lock()
        self.heartbeat_fail_count = 0
        self.heartbeat_fail_limit = 2
        self.heartbeat_active_logged = False
        self.heartbeat_lost_logged = False

        # Kalau mau balik ke mock device:
        # self.device = MockDevice()

        self.setWindowTitle("USB Hardware Key Security Manager")
        self.setGeometry(200, 200, 520, 360)

        self.init_ui()
        self.initialize_device()
        self.check_veracrypt()

        self.heartbeat_timer = QTimer()
        self.heartbeat_timer.timeout.connect(self.check_device_heartbeat)
        self.heartbeat_timer.start(3000)  # cek tiap 3 detik
        self.check_device_heartbeat()

    def init_ui(self):
        self.status_label = QLabel("USB Hardware Key Status: Not Connected")

        self.unlock_button = QPushButton("Unlock Workspace")
        self.unmount_button = QPushButton("Unmount Workspace")
        self.recovery_button = QPushButton("Recovery Mode")

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.unlock_button)
        button_layout.addWidget(self.unmount_button)
        button_layout.addWidget(self.recovery_button)

        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addLayout(button_layout)
        layout.addWidget(QLabel("System Log"))
        layout.addWidget(self.log_area)

        self.setLayout(layout)

        self.log_signal.connect(self.log_area.append)
        self.status_signal.connect(self.status_label.setText)
        self.recovery_key_generated_signal.connect(self.show_generated_recovery_key)
        self.recovery_generation_failed_signal.connect(self.show_recovery_generation_error)
        self.unlock_button.clicked.connect(self.unlock_workspace)
        self.unmount_button.clicked.connect(self.unmount_workspace)
        self.recovery_button.clicked.connect(self.recovery_mode)

    def log(self, message: str):
        self.log_signal.emit(message)

    def initialize_device(self):
        if self.device.connect():
            self.device.set_callback(self.handle_serial_event)
            self.status_signal.emit("USB Hardware Key Status: Connected (Serial Device)")
            self.log("Serial device connected. Waiting for fingerprint match events.")
        else:
            self.log("Failed to connect device.")

    def check_veracrypt(self):
        if self.veracrypt.is_installed():
            self.log("VeraCrypt detected successfully.")
        else:
            self.log("VeraCrypt not detected. Please install VeraCrypt first.")

    def handle_serial_event(self, line):
        if line == "PONG":
            return

        if line == "DEVICE_DISCONNECTED":
            self.handle_device_lost()
            return

        if line.startswith("UNLOCK_BLOB:"):
            self.log("[SERIAL] UNLOCK_BLOB:<encrypted blob redacted>")
            return

        legacy_password_prefix = "PASSWORD" + ":"
        if line.startswith(legacy_password_prefix):
            self.log("[SERIAL] legacy plaintext password message ignored.")
            return

        self.log(f"[SERIAL] {line}")

        if line.startswith("MATCH_READY:"):
            parts = line.split(":")
            user_id = parts[1] if len(parts) > 1 else "unknown"
            confidence = parts[2] if len(parts) > 2 else "unknown"

            self.log(f"Fingerprint match from ID {user_id} with confidence {confidence}.")

            if self.pending_recovery_generation:
                self.handle_recovery_generation_match(user_id, confidence)
                return

            self.start_secure_unlock(user_id, confidence)

    def start_secure_unlock(self, user_id, confidence):
        with self.unlock_lock:
            if self.unlock_in_progress:
                self.log("Secure unlock already in progress.")
                return

            if self.pending_recovery_generation or self.recovery_generation_in_progress:
                return

            if time.time() - self.last_auth_time < self.cooldown:
                return

            self.unlock_in_progress = True
            self.last_auth_time = time.time()

        worker = threading.Thread(
            target=self.secure_unlock_worker,
            args=(user_id, confidence),
            daemon=True,
        )
        worker.start()

    def secure_unlock_worker(self, user_id, confidence):
        password = None

        try:
            if not self.veracrypt.is_installed():
                self.log("Cannot continue: VeraCrypt is not installed.")
                return

            self.wait_for_heartbeat_idle()
            password = self.request_encrypted_password()
            if not password:
                self.log("Cannot mount: password unavailable.")
                return

            self.log("Mounting encrypted container...")
            success, message = self.veracrypt.mount_container(password)
            self.log(message)

            if success:
                self.mounted = True
                self.mounted_via_recovery = False
                self.log("Container mounted securely.")
            else:
                self.log("Workspace unlock failed.")
        finally:
            password = None
            with self.unlock_lock:
                self.unlock_in_progress = False

    def wait_for_heartbeat_idle(self):
        while True:
            with self.heartbeat_lock:
                if not self.heartbeat_in_progress:
                    return

            time.sleep(0.05)

    def read_public_key_bytes(self, path: Path, label: str):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.log(f"Missing {label}: {path}")
            return None
        except OSError as e:
            self.log(f"Failed to read {label}: {e}")
            return None

        if len(data) != 32:
            self.log(f"Invalid {label}: expected 32 bytes, got {len(data)} bytes.")
            return None

        return data

    def request_encrypted_password(self):
        self.log("Requesting encrypted container password...")

        if not hasattr(self.device, "send_line") or not hasattr(self.device, "wait_for_prefix"):
            self.log("Connected device does not support encrypted password requests.")
            return None

        esp_x25519_bytes = self.read_public_key_bytes(
            self.x25519_public_key_path,
            "ESP X25519 public key",
        )
        if esp_x25519_bytes is None:
            return None

        esp_ed25519_bytes = self.read_public_key_bytes(
            self.ed25519_public_key_path,
            "ESP Ed25519 public key",
        )
        if esp_ed25519_bytes is None:
            return None

        challenge = secrets.token_bytes(32)
        pc_private = x25519.X25519PrivateKey.generate()
        pc_public_bytes = pc_private.public_key().public_bytes_raw()

        if hasattr(self.device, "clear_pending_lines"):
            self.device.clear_pending_lines()

        sent = self.device.send_line(
            f"UNLOCK_REQ:{challenge.hex().upper()}:{pc_public_bytes.hex().upper()}"
        )
        if not sent:
            self.log("Failed to send encrypted password request.")
            return None

        line = self.device.wait_for_prefix("UNLOCK_BLOB:", timeout=8.0)
        if not line:
            self.log("Encrypted password request timeout.")
            return None

        parts = line.split(":")
        if len(parts) != 5:
            self.log("Invalid UNLOCK_BLOB format.")
            return None

        try:
            nonce = bytes.fromhex(parts[1])
            ciphertext = bytes.fromhex(parts[2])
            tag = bytes.fromhex(parts[3])
            signature = bytes.fromhex(parts[4])
        except ValueError:
            self.log("Invalid UNLOCK_BLOB hex encoding.")
            return None

        if not nonce or not ciphertext or len(tag) != 16 or len(signature) != 64:
            self.log("Invalid UNLOCK_BLOB field lengths.")
            return None

        try:
            esp_x_pub = x25519.X25519PublicKey.from_public_bytes(esp_x25519_bytes)
            ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(esp_ed25519_bytes)
        except ValueError as e:
            self.log(f"Invalid public key file format: {e}")
            return None

        shared_secret = pc_private.exchange(esp_x_pub)
        aes_key = hashlib.sha256(shared_secret + challenge).digest()
        transcript_hash = hashlib.sha256(
            b"USBDEF_V1" + challenge + pc_public_bytes + nonce + ciphertext + tag
        ).digest()

        try:
            ed_pub.verify(signature, transcript_hash)
            self.log("Ed25519 transcript signature verified.")
        except InvalidSignature:
            self.log("Ed25519 transcript signature verification failed.")
            return None

        aad = challenge + pc_public_bytes
        try:
            password_bytes = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, aad)
            self.log("AES-GCM password decrypt OK.")
        except InvalidTag:
            self.log("AES-GCM password decrypt failed.")
            return None
        except Exception as e:
            self.log(f"AES-GCM decrypt error: {e}")
            return None

        try:
            return password_bytes.decode("utf-8")
        except UnicodeDecodeError:
            self.log("Decrypted password is not valid UTF-8.")
            return None
        finally:
            password_bytes = None

    def unlock_workspace(self):
        self.log("Unlock workspace requested.")

        if not self.device.is_connected():
            self.log("No hardware key connected.")
            return

        self.log("Waiting for MATCH_READY from the hardware key fingerprint scan.")

    def recovery_mode(self):
        self.log("Recovery mode activated.")

        status = self.recovery_manager.get_recovery_status()

        if status == "consumed":
            message = "Recovery key has already been used. Recovery is no longer available."
            self.log(message)
            QMessageBox.information(self, "Recovery Mode", message)
            return

        if status == "active":
            self.use_recovery_key()
            return

        if self.unlock_in_progress:
            QMessageBox.information(
                self,
                "Recovery Mode",
                "Secure unlock is currently in progress. Try Recovery Mode again after it finishes.",
            )
            return

        if self.pending_recovery_generation or self.recovery_generation_in_progress:
            QMessageBox.information(
                self,
                "Recovery Mode",
                "Recovery setup is already pending. Please scan fingerprint on hardware key.",
            )
            return

        response = QMessageBox.question(
            self,
            "Recovery Mode",
            "No recovery key exists. To generate one, scan your fingerprint again to authorize recovery setup.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if response != QMessageBox.StandardButton.Yes:
            return

        self.pending_recovery_generation = True
        self.log("Recovery setup pending. Please scan fingerprint on hardware key.")

    def handle_recovery_generation_match(self, user_id, confidence):
        with self.recovery_generation_lock:
            if self.recovery_generation_in_progress:
                self.log("Recovery setup already in progress.")
                return

            self.recovery_generation_in_progress = True

        worker = threading.Thread(
            target=self.recovery_generation_worker,
            args=(user_id, confidence),
            daemon=True,
        )
        worker.start()

    def recovery_generation_worker(self, user_id, confidence):
        password = None
        recovery_key = None

        try:
            if not self.device or not self.device.is_connected():
                self.log("Cannot generate recovery key: hardware key is not connected.")
                self.recovery_generation_failed_signal.emit(
                    "Cannot generate recovery key because the hardware key is not connected."
                )
                return

            self.wait_for_heartbeat_idle()
            password = self.request_encrypted_password()
            if not password:
                self.log("Cannot generate recovery key: encrypted password unavailable.")
                self.recovery_generation_failed_signal.emit(
                    "Cannot generate recovery key because the container password is unavailable."
                )
                return

            recovery_key = self.recovery_manager.create_recovery_blob(password)
        except RecoveryError as e:
            self.log(f"Recovery key generation failed: {e}")
            self.recovery_generation_failed_signal.emit(f"Recovery key generation failed:\n{e}")
            return
        except Exception as e:
            self.log(f"Recovery key generation failed: {e}")
            self.recovery_generation_failed_signal.emit("Recovery key generation failed.")
            return
        finally:
            password = None
            self.pending_recovery_generation = False
            with self.recovery_generation_lock:
                self.recovery_generation_in_progress = False

        self.log("Recovery key generated. Please store it safely.")
        self.recovery_key_generated_signal.emit(recovery_key)
        recovery_key = None

    def show_generated_recovery_key(self, recovery_key: str):
        QMessageBox.information(
            self,
            "Recovery Key Generated",
            (
                "Write this recovery key down offline. It will not be shown again. "
                "It can only be used once.\n\n"
                f"{recovery_key}"
            ),
        )
        recovery_key = None

    def show_recovery_generation_error(self, message: str):
        QMessageBox.warning(self, "Recovery Mode", message)

    def use_recovery_key(self):
        recovery_key, ok = QInputDialog.getText(
            self,
            "Use Recovery Key",
            "Enter recovery key",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return

        password = None

        try:
            password = self.recovery_manager.recover_password(recovery_key)
            recovery_key = None

            if not password:
                self.log("Recovery unlock failed.")
                if self.recovery_manager.last_error:
                    self.log(self.recovery_manager.last_error)
                QMessageBox.warning(self, "Recovery Mode", "Recovery unlock failed.")
                return

            self.log("Recovery unlock successful. Recovery key has been consumed.")
            self.log("Mounting encrypted container...")
            success, message = self.veracrypt.mount_container(password)
            self.log(message)

            if success:
                self.mounted = True
                self.mounted_via_recovery = True
                self.log("Container mounted securely.")
            else:
                self.log("Workspace unlock failed.")
        finally:
            password = None
            recovery_key = None

    def unmount_workspace(self):
        self.log("Unmount workspace requested.")

        success, message = self.veracrypt.unmount_container()
        self.log(message)
        if success:
            self.mounted = False
            self.mounted_via_recovery = False

    def closeEvent(self, event):
        try:
            self.device.close()
        except Exception:
            pass
        event.accept()

    def check_device_heartbeat(self):
        with self.heartbeat_lock:
            # Jangan ping saat proses unlock sedang berjalan,
            # supaya tidak bentrok dengan proses UNLOCK_REQ / UNLOCK_BLOB.
            if (
                self.device_lost_handled
                and (not self.device or not self.device.is_connected())
            ):
                return

            if (
                self.unlock_in_progress
                or self.recovery_generation_in_progress
                or self.heartbeat_in_progress
            ):
                return

            self.heartbeat_in_progress = True

        threading.Thread(target=self.heartbeat_worker, daemon=True).start()

    def heartbeat_worker(self):
        try:
            if self.unlock_in_progress or self.recovery_generation_in_progress:
                return

            if not self.device or not self.device.is_connected():
                self.handle_device_lost()
                return

            ok = self.device.ping(timeout=1.5)

            if ok:
                self.heartbeat_fail_count = 0
                self.device_lost_handled = False
                self.heartbeat_lost_logged = False

                if not self.heartbeat_active_logged:
                    self.log("Hardware key heartbeat active.")
                    self.heartbeat_active_logged = True

                return

            self.heartbeat_fail_count += 1

            if self.heartbeat_fail_count >= self.heartbeat_fail_limit:
                if not self.heartbeat_lost_logged:
                    self.log("Hardware key heartbeat stopped.")
                    self.heartbeat_lost_logged = True

                self.handle_device_lost()
        finally:
            with self.heartbeat_lock:
                self.heartbeat_in_progress = False

    def handle_device_lost(self):
        with self.device_lost_lock:
            if self.device_lost_handled:
                return

            self.device_lost_handled = True

        self.heartbeat_fail_count = 0
        self.status_signal.emit("USB Hardware Key Status: Not Connected")

        try:
            if self.device:
                self.device.close()
        except Exception:
            pass

        self.pending_recovery_generation = False

        if self.mounted and self.mounted_via_recovery:
            self.log("Hardware key disconnected.")
            return

        if self.mounted:
            self.log("Hardware key disconnected. Unmounting workspace...")

            success, message = self.veracrypt.unmount_container()
            self.log(message)

            if success:
                self.log("Workspace terminated because hardware key was removed.")
            else:
                self.log("Failed to unmount workspace after hardware key removal.")

            self.mounted = False
            self.mounted_via_recovery = False
            return

        self.log("Hardware key disconnected.")
