import hashlib
import secrets
import threading
import time
from pathlib import Path
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
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
from utils.config_manager import ConfigManager
from utils.runtime_paths import resolve_app_path


class LogDialog(QDialog):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(720, 420)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(self.log_text)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def set_text(self, text: str):
        self.log_text.setPlainText(text)
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def append_line(self, line: str):
        self.log_text.append(line)


class MainWindow(QWidget):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    dashboard_update_signal = pyqtSignal()
    recovery_key_generated_signal = pyqtSignal(str)
    recovery_generation_failed_signal = pyqtSignal(str)

    def __init__(self, config_manager=None):
        super().__init__()

        self.config_manager = config_manager or ConfigManager()
        self.config = self.config_manager.load_config()
        self.project_root = Path(__file__).resolve().parents[1]

        self.device = SerialDevice(baudrate=115200)
        self.veracrypt = VeraCryptController(
            exe_path=self._config_value("veracrypt", "executable_path") or None
        )
        self.recovery_manager = RecoveryManager(self.project_root)
        self.ed25519_public_key_path = self._config_app_path(
            self._config_value("hardware", "ed25519_public_key_path"),
            "keys/esp_ed25519_public.bin",
        )
        self.x25519_public_key_path = self._config_app_path(
            self._config_value("hardware", "x25519_public_key_path"),
            "keys/esp_x25519_public.bin",
        )
        self.container_path = str(
            self._config_path(
                self._config_value("workspace", "container_path"),
                self.project_root / "demo_container.hc",
            )
        )
        self.mount_letter = str(
            self._config_value("workspace", "mount_letter") or "X"
        ).strip().rstrip(":") or "X"
        self.veracrypt.container_path = self.container_path
        self.veracrypt.mount_letter = self.mount_letter
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
        self.log_dialog = None

        # Kalau mau balik ke mock device:
        # self.device = MockDevice()

        self.setWindowTitle("USB Hardware Key Security Manager")
        self.setMinimumSize(880, 520)
        self.resize(960, 580)

        self.init_ui()
        self.initialize_device()
        self.check_veracrypt()

        self.heartbeat_timer = QTimer()
        self.heartbeat_timer.timeout.connect(self.check_device_heartbeat)
        self.heartbeat_timer.start(3000)  # cek tiap 3 detik
        self.check_device_heartbeat()

    def _config_value(self, section: str, key: str):
        section_values = self.config.get(section, {})
        if not isinstance(section_values, dict):
            return None

        value = section_values.get(key)
        if isinstance(value, str):
            return value.strip()

        return value

    def _config_path(self, value, default_path: Path) -> Path:
        return self._config_runtime_path(value, default_path)

    def _config_runtime_path(self, value, default_path: Path) -> Path:
        if not value:
            return default_path

        path = Path(value)
        if path.is_absolute():
            return path

        return self.project_root / path

    def _config_app_path(self, value, default_path: str | Path) -> Path:
        if isinstance(value, str):
            value = value.strip()

        if not value:
            return resolve_app_path(default_path)

        try:
            return resolve_app_path(value)
        except TypeError:
            return resolve_app_path(default_path)

    def init_ui(self):
        self.setStyleSheet(
            """
            QWidget {
                background: #f3f6fb;
                color: #111827;
                font-size: 13px;
            }
            QLabel {
                background: transparent;
            }
            QLabel#AppTitle {
                background: transparent;
                color: #111827;
                font-size: 26px;
                font-weight: 700;
            }
            QLabel#Subtitle {
                background: transparent;
                color: #64748b;
                font-size: 13px;
            }
            QLabel#SectionLabel {
                background: transparent;
                color: #111827;
                font-size: 12px;
                font-weight: 700;
            }
            QFrame#StatusBanner,
            QFrame#DashboardCard,
            QFrame#ActionCard,
            QFrame#AdvancedCard {
                background: #ffffff;
                border: 1px solid #d9e2ec;
                border-radius: 12px;
            }
            QFrame#StatusBanner {
                background: #eff6ff;
                border-color: #bfdbfe;
            }
            QLabel#StatusLabel {
                background: transparent;
                color: #111827;
                font-weight: 600;
            }
            QLabel#CardTitle {
                background: transparent;
                color: #64748b;
                font-size: 12px;
                font-weight: 700;
            }
            QLabel#CardValue {
                background: transparent;
                color: #111827;
                font-size: 20px;
                font-weight: 700;
            }
            QLabel#CardValue[state="ok"] {
                color: #166534;
            }
            QLabel#CardValue[state="warn"] {
                color: #92400e;
            }
            QLabel#CardValue[state="muted"] {
                color: #64748b;
            }
            QTextEdit {
                background: #ffffff;
                border: 1px solid #d9e2ec;
                border-radius: 8px;
                color: #111827;
                font-family: Consolas, "Courier New", monospace;
                padding: 8px;
            }
            QPushButton {
                background: #ffffff;
                border: 1px solid #d9e2ec;
                border-radius: 8px;
                color: #111827;
                padding: 10px 14px;
            }
            QPushButton:hover {
                background: #f8fafc;
            }
            QPushButton:disabled {
                background: #eef2f7;
                border-color: #d9e2ec;
                color: #94a3b8;
            }
            QPushButton#PrimaryButton {
                background: #2563eb;
                border-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton#PrimaryButton:hover:!disabled {
                background: #1d4ed8;
            }
            QPushButton#PrimaryButton:disabled {
                background: #e5e7eb;
                border-color: #d1d5db;
                color: #94a3b8;
                font-weight: 600;
            }
            QPushButton#SecondaryButton {
                background: #ffffff;
                border-color: #cbd5e1;
                color: #111827;
            }
            QPushButton#SecondaryButton:hover {
                background: #eaf1fb;
                border-color: #94a3b8;
            }
            QPushButton#SecondaryButton:disabled {
                background: #eef2f7;
                border-color: #d9e2ec;
                color: #94a3b8;
            }
            """
        )

        self.title_label = QLabel("USB Auth Workspace")
        self.title_label.setObjectName("AppTitle")

        self.subtitle_label = QLabel(
            "Unlock and manage your encrypted VeraCrypt workspace using your trusted USB hardware key."
        )
        self.subtitle_label.setObjectName("Subtitle")
        self.subtitle_label.setWordWrap(True)

        self.status_label = QLabel("Hardware key: Not connected")
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setWordWrap(True)

        status_banner = QFrame()
        status_banner.setObjectName("StatusBanner")
        status_banner_layout = QVBoxLayout(status_banner)
        status_banner_layout.setContentsMargins(16, 13, 16, 13)
        status_banner_layout.addWidget(self.status_label)

        self.hardware_card, self.hardware_value_label = self._create_status_card(
            "Hardware Key",
            "Not connected",
        )
        self.workspace_card, self.workspace_value_label = self._create_status_card(
            "Workspace",
            "Unknown",
        )
        self.recovery_card, self.recovery_value_label = self._create_status_card(
            "Recovery",
            "Not configured",
        )

        self.unlock_button = QPushButton("Unlock Workspace")
        self.unlock_button.setObjectName("PrimaryButton")
        self.unmount_button = QPushButton("Unmount Workspace")
        self.unmount_button.setObjectName("SecondaryButton")
        self.recovery_button = QPushButton("Recovery Mode")
        self.recovery_button.setObjectName("SecondaryButton")
        self.view_log_button = QPushButton("View Technical Log")
        self.view_log_button.setObjectName("SecondaryButton")

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setPlaceholderText("Technical details and security events appear here.")

        actions_label = QLabel("Actions")
        actions_label.setObjectName("SectionLabel")

        actions_frame = QFrame()
        actions_frame.setObjectName("ActionCard")
        actions_layout = QVBoxLayout(actions_frame)
        actions_layout.setContentsMargins(16, 14, 16, 16)
        actions_layout.setSpacing(10)
        actions_layout.addWidget(actions_label)

        primary_button_layout = QHBoxLayout()
        primary_button_layout.setSpacing(8)
        primary_button_layout.addWidget(self.unlock_button)
        primary_button_layout.addWidget(self.unmount_button)
        primary_button_layout.addWidget(self.recovery_button)
        primary_button_layout.addStretch()
        actions_layout.addLayout(primary_button_layout)

        advanced_label = QLabel("Advanced")
        advanced_label.setObjectName("SectionLabel")

        advanced_frame = QFrame()
        advanced_frame.setObjectName("AdvancedCard")
        advanced_layout = QHBoxLayout(advanced_frame)
        advanced_layout.setContentsMargins(16, 14, 16, 14)
        advanced_layout.setSpacing(10)
        advanced_layout.addWidget(advanced_label)
        advanced_layout.addStretch()
        advanced_layout.addWidget(self.view_log_button)

        cards_grid = QGridLayout()
        cards_grid.setSpacing(12)
        cards_grid.addWidget(self.hardware_card, 0, 0)
        cards_grid.addWidget(self.workspace_card, 0, 1)
        cards_grid.addWidget(self.recovery_card, 0, 2)
        cards_grid.setColumnStretch(0, 1)
        cards_grid.setColumnStretch(1, 1)
        cards_grid.setColumnStretch(2, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 26, 30, 24)
        layout.setSpacing(14)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addWidget(status_banner)
        layout.addLayout(cards_grid)
        layout.addWidget(actions_frame)
        layout.addWidget(advanced_frame)
        layout.addStretch()

        self.setLayout(layout)

        self.log_signal.connect(self._append_log_message)
        self.status_signal.connect(self._handle_status_message)
        self.dashboard_update_signal.connect(self.update_dashboard_cards)
        self.recovery_key_generated_signal.connect(self.show_generated_recovery_key)
        self.recovery_generation_failed_signal.connect(self.show_recovery_generation_error)
        self.unlock_button.clicked.connect(self.unlock_workspace)
        self.unmount_button.clicked.connect(self.unmount_workspace)
        self.recovery_button.clicked.connect(self.recovery_mode)
        self.view_log_button.clicked.connect(self.open_log_dialog)

        self.update_dashboard_cards()

    def _create_status_card(self, title: str, value: str):
        frame = QFrame()
        frame.setObjectName("DashboardCard")

        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")

        value_label = QLabel(value)
        value_label.setObjectName("CardValue")
        value_label.setWordWrap(True)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addStretch()

        return frame, value_label

    def _append_log_message(self, message: str):
        self.log_area.append(message)
        if self.log_dialog is not None and self.log_dialog.isVisible():
            self.log_dialog.append_line(message)

    def _handle_status_message(self, message: str):
        self.status_label.setText(message)
        self.update_dashboard_cards()

    def open_log_dialog(self):
        if self.log_dialog is None or not self.log_dialog.isVisible():
            self.log_dialog = LogDialog("Technical Log", self)
            self.log_dialog.finished.connect(self._clear_log_dialog_reference)

        self.log_dialog.set_text(self.log_area.toPlainText())
        self.log_dialog.show()
        self.log_dialog.raise_()
        self.log_dialog.activateWindow()

    def _clear_log_dialog_reference(self):
        self.log_dialog = None

    def _set_dashboard_value(self, label: QLabel, text: str, state: str):
        label.setText(text)
        label.setProperty("state", state)
        label.style().unpolish(label)
        label.style().polish(label)

    def update_dashboard_cards(self):
        if not hasattr(self, "hardware_value_label"):
            return

        hardware_text = "Not connected"
        hardware_state = "muted"
        if self.device and self.device.is_connected():
            hardware_text = "Ready"
            hardware_state = "ok"
            if self.unlock_in_progress or self.recovery_generation_in_progress:
                hardware_text = "Connected"
                hardware_state = "warn"

        workspace_text = "Unknown"
        workspace_state = "muted"
        if self.mounted_via_recovery:
            workspace_text = "Mounted via Recovery"
            workspace_state = "warn"
        elif self.mounted:
            workspace_text = "Mounted"
            workspace_state = "ok"
        else:
            workspace_config = self.config.get("workspace", {})
            if not isinstance(workspace_config, dict):
                workspace_config = {}

            try:
                container_exists = Path(self.container_path).exists()
            except OSError:
                container_exists = False

            if workspace_config.get("container_created") is True or container_exists:
                workspace_text = "Locked"
                workspace_state = "muted"

        recovery_text = "Not configured"
        recovery_state = "muted"
        if self.pending_recovery_generation or self.recovery_generation_in_progress:
            recovery_text = "Pending"
            recovery_state = "warn"
        else:
            try:
                recovery_status = self.recovery_manager.get_recovery_status()
            except Exception:
                recovery_status = "unknown"

            if recovery_status == "active":
                recovery_text = "Available"
                recovery_state = "ok"
            elif recovery_status == "consumed":
                recovery_text = "Used"
                recovery_state = "warn"
            elif recovery_status == "not_created":
                recovery_text = "Not configured"
                recovery_state = "muted"
            else:
                recovery_text = "Unknown"
                recovery_state = "muted"

        self._set_dashboard_value(
            self.hardware_value_label,
            hardware_text,
            hardware_state,
        )
        self._set_dashboard_value(
            self.workspace_value_label,
            workspace_text,
            workspace_state,
        )
        self._set_dashboard_value(
            self.recovery_value_label,
            recovery_text,
            recovery_state,
        )

    def log(self, message: str):
        self.log_signal.emit(message)

    def initialize_device(self):
        if self.device.connect():
            self.device.set_callback(self.handle_serial_event)
            self.status_signal.emit("Hardware key: Connected and ready")
            self.log("Serial device connected. Waiting for fingerprint match events.")
        else:
            self.status_signal.emit("Hardware key: Not connected")
            self.log("Failed to connect device.")

    def check_veracrypt(self):
        installed = self.veracrypt.is_installed()
        values = {"installed": installed}
        if self.veracrypt.exe_path:
            values["executable_path"] = str(self.veracrypt.exe_path)

        self.config = self.config_manager.update_section("veracrypt", values)

        if installed:
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

        self.dashboard_update_signal.emit()
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

            self.status_signal.emit("Unlocking workspace")
            self.log("Mounting encrypted container...")
            success, message = self.veracrypt.mount_container(password)
            self.log(message)

            if success:
                self.mounted = True
                self.mounted_via_recovery = False
                self.status_signal.emit("Workspace mounted")
                self.log("Container mounted securely.")
            else:
                self.status_signal.emit("Workspace unlock failed")
                self.log("Workspace unlock failed.")
        finally:
            password = None
            with self.unlock_lock:
                self.unlock_in_progress = False
            self.dashboard_update_signal.emit()

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
            self.status_signal.emit("Hardware key: Not connected")
            self.log("No hardware key connected.")
            return

        self.status_signal.emit("Waiting for fingerprint authorization")
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
        self.dashboard_update_signal.emit()
        self.log("Recovery setup pending. Please scan fingerprint on hardware key.")

    def handle_recovery_generation_match(self, user_id, confidence):
        with self.recovery_generation_lock:
            if not self.pending_recovery_generation:
                return

            if self.recovery_generation_in_progress:
                self.log("Recovery setup already in progress.")
                return

            self.pending_recovery_generation = False
            self.recovery_generation_in_progress = True

        self.dashboard_update_signal.emit()
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
            self.config = self.config_manager.update_section(
                "recovery",
                {
                    "enabled": True,
                    "recovery_blob_path": "data/recovery_blob.json",
                    "consumed_flag_path": "data/recovery_consumed.flag",
                },
            )
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
            with self.recovery_generation_lock:
                self.recovery_generation_in_progress = False
            self.dashboard_update_signal.emit()

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
                self.status_signal.emit("Workspace mounted with recovery key")
                self.log("Container mounted securely.")
            else:
                self.status_signal.emit("Workspace unlock failed")
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
            self.status_signal.emit("Workspace unmounted")

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
        self.status_signal.emit("Hardware key: Not connected")

        try:
            if self.device:
                self.device.close()
        except Exception:
            pass

        self.pending_recovery_generation = False
        self.dashboard_update_signal.emit()

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
            self.dashboard_update_signal.emit()
            return

        self.log("Hardware key disconnected.")
