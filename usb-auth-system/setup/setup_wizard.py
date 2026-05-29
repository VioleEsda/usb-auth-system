import base64
import hashlib
import secrets
import threading
import time
from pathlib import Path

import serial
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt6.QtCore import QPropertyAnimation, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QLabel,
    QFileDialog,
    QMessageBox,
    QPushButton,
    QHBoxLayout,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from container.veracrypt_controller import VeraCryptController
from gui.main_window import MainWindow
from hardware.device_detector import detect_trusted_hardware_key
from recovery.recovery_manager import RecoveryError, RecoveryManager
from .setup_state import SetupStep


STEP_TITLES = {
    SetupStep.welcome: "Welcome",
    SetupStep.check_veracrypt: "Check VeraCrypt",
    SetupStep.detect_hardware: "Detect Hardware Key",
    SetupStep.enroll_fingerprint: "Enroll Fingerprint",
    SetupStep.create_workspace: "Create Workspace",
    SetupStep.provision_secret: "Provision Secret",
    SetupStep.setup_recovery: "Setup Recovery",
    SetupStep.finish: "Finish",
}

STEP_DESCRIPTIONS = {
    SetupStep.welcome: (
        "This wizard will configure VeraCrypt, verify your trusted USB hardware key, "
        "enroll a fingerprint, create an encrypted workspace, provision the workspace "
        "secret, and set up one-time recovery."
    ),
    SetupStep.check_veracrypt: (
        "VeraCrypt is required to create and mount the encrypted workspace used by "
        "this app."
    ),
    SetupStep.detect_hardware: (
        "The app will look for your USB hardware key and verify it against the trusted "
        "public key on this computer."
    ),
    SetupStep.enroll_fingerprint: (
        "Enroll a fingerprint directly on the hardware key so it can authorize future "
        "workspace unlocks."
    ),
    SetupStep.create_workspace: (
        "Create a VeraCrypt container that will become your encrypted workspace."
    ),
    SetupStep.provision_secret: (
        "After fingerprint authorization, the workspace secret will be securely "
        "provisioned to the hardware key."
    ),
    SetupStep.setup_recovery: (
        "Generate a one-time recovery key. It will be shown once, so write it down "
        "offline."
    ),
    SetupStep.finish: (
        "Review the setup summary. Setup can finish only when every required check "
        "passes."
    ),
}


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


class SetupWizardWindow(QWidget):
    enroll_log_signal = pyqtSignal(str)
    enroll_finished_signal = pyqtSignal(bool, str)
    workspace_finished_signal = pyqtSignal(bool, str, str)
    provision_log_signal = pyqtSignal(str)
    provision_status_signal = pyqtSignal(str, str)
    provision_finished_signal = pyqtSignal(bool, str)
    recovery_finished_signal = pyqtSignal(bool, str, str)

    def __init__(self, config_manager):
        super().__init__()

        self.config_manager = config_manager
        self.steps = list(SetupStep)
        self.current_index = self._current_index_from_config()
        self.main_window = None
        self.veracrypt_installed = None
        self.hardware_bound = None
        self.fingerprint_enrolled = None
        self.enroll_in_progress = False
        self.enroll_fingerprint_id = "1"
        self.project_root = Path(__file__).resolve().parents[1]
        self.workspace_created = None
        self.workspace_creation_in_progress = False
        self.generated_workspace_password = None
        self.selected_workspace_path = str(self.project_root / "data" / "workspace.hc")
        self.secret_provisioned = None
        self.secret_provision_in_progress = False
        self.recovery_setup_done = None
        self.recovery_setup_in_progress = False

        self.log_buffer = []
        self.log_dialog = None
        self._content_fade_animation = None
        self.spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_index = 0
        self.status_spinner_timer = QTimer(self)
        self.status_spinner_timer.timeout.connect(self._advance_status_spinner)

        self.setWindowTitle("USB Auth Setup Wizard")
        self.setMinimumSize(900, 560)
        self.resize(980, 620)
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
            QFrame#Sidebar {
                background: #ffffff;
                border-right: 1px solid #d9e2ec;
            }
            QLabel#AppTitle {
                background: transparent;
                color: #111827;
                font-size: 22px;
                font-weight: 700;
            }
            QLabel#AppSubtitle {
                background: transparent;
                color: #64748b;
                font-size: 12px;
            }
            QLabel#StepCounter {
                background: transparent;
                color: #64748b;
                font-size: 12px;
                font-weight: 600;
            }
            QLabel#StepTitle {
                background: transparent;
                color: #111827;
                font-size: 24px;
                font-weight: 700;
            }
            QLabel#StepDescription {
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
            QFrame#ContentCard {
                background: #ffffff;
                border: 1px solid #d9e2ec;
                border-radius: 14px;
            }
            QFrame#StatusCard,
            QFrame#InlineCard {
                background: #f8fafc;
                border: 1px solid #d9e2ec;
                border-radius: 10px;
            }
            QFrame#InfoCard {
                background: #eff6ff;
                border: 1px solid #bfdbfe;
                border-radius: 10px;
            }
            QLabel#InfoLabel {
                background: transparent;
                color: #1e40af;
                font-weight: 600;
            }
            QLabel#StatusIcon {
                background: transparent;
                color: #64748b;
                font-size: 18px;
                font-weight: 700;
            }
            QLabel#StatusIcon[state="loading"] {
                color: #2563eb;
            }
            QLabel#StatusIcon[state="success"] {
                color: #166534;
            }
            QLabel#StatusIcon[state="error"] {
                color: #991b1b;
            }
            QLabel#StatusLabel {
                background: transparent;
                color: #111827;
                font-weight: 600;
            }
            QLabel#WorkspacePath {
                background: transparent;
                color: #111827;
                font-weight: 600;
            }
            QFrame#StepItem {
                background: transparent;
                border: 1px solid transparent;
                border-radius: 10px;
            }
            QFrame#StepItem[state="active"] {
                background: #eff6ff;
                border-color: #bfdbfe;
            }
            QFrame#StepItem[state="completed"] {
                background: #ffffff;
                border-color: #d9e2ec;
            }
            QFrame#StepItem[state="pending"] {
                background: transparent;
                border-color: transparent;
            }
            QLabel#StepNumber {
                background: #e2e8f0;
                border-radius: 11px;
                color: #64748b;
                font-size: 11px;
                font-weight: 700;
                min-height: 22px;
                min-width: 22px;
                qproperty-alignment: AlignCenter;
            }
            QLabel#StepNumber[state="active"] {
                background: #2563eb;
                color: #ffffff;
            }
            QLabel#StepNumber[state="completed"] {
                background: #dbeafe;
                color: #2563eb;
            }
            QLabel#StepItemTitle {
                background: transparent;
                color: #111827;
                font-weight: 700;
            }
            QLabel#StepItemTitle[state="pending"] {
                color: #64748b;
                font-weight: 500;
            }
            QLabel#StepItemState {
                background: transparent;
                color: #64748b;
                font-size: 11px;
                font-weight: 600;
            }
            QLabel#ChecklistItem {
                background: #ffffff;
                border: 1px solid #d9e2ec;
                border-radius: 8px;
                color: #111827;
                padding: 8px 10px;
            }
            QLabel#ChecklistItem[state="failed"] {
                border-color: #fecaca;
                color: #991b1b;
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
                padding: 9px 14px;
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

        self.app_title_label = QLabel("USB Auth Setup")
        self.app_title_label.setObjectName("AppTitle")

        self.app_subtitle_label = QLabel("Encrypted workspace setup")
        self.app_subtitle_label.setObjectName("AppSubtitle")
        self.app_subtitle_label.setWordWrap(True)

        self.step_counter_label = QLabel()
        self.step_counter_label.setObjectName("StepCounter")

        self.step_title_label = QLabel()
        self.step_title_label.setObjectName("StepTitle")

        self.step_description_label = QLabel()
        self.step_description_label.setObjectName("StepDescription")
        self.step_description_label.setWordWrap(True)

        self.step_key_label = QLabel()
        self.step_key_label.setVisible(False)

        self.status_heading_label = QLabel("Status")
        self.status_heading_label.setObjectName("SectionLabel")

        self.status_icon_label = QLabel("")
        self.status_icon_label.setObjectName("StatusIcon")
        self.status_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_icon_label.setFixedWidth(24)

        self.step_status_label = QLabel()
        self.step_status_label.setObjectName("StatusLabel")
        self.step_status_label.setWordWrap(True)

        self.details_label = QLabel("Details")
        self.details_label.setObjectName("SectionLabel")
        self.details_label.setVisible(False)

        self.step_log_area = QTextEdit()
        self.step_log_area.setReadOnly(True)
        self.step_log_area.setVisible(False)

        self.workspace_path_label = QLabel()
        self.workspace_path_label.setObjectName("WorkspacePath")
        self.workspace_path_label.setWordWrap(True)
        self.workspace_path_label.setVisible(False)

        self.workspace_size_label = QLabel("Size:")
        self.workspace_size_label.setVisible(False)

        self.workspace_size_input = QSpinBox()
        self.workspace_size_input.setRange(10, 10240)
        self.workspace_size_input.setValue(100)
        self.workspace_size_input.setSuffix(" MB")
        self.workspace_size_input.setVisible(False)

        self.back_button = QPushButton("Back")
        self.next_button = QPushButton("Next")
        self.recheck_button = QPushButton("Recheck")
        self.choose_veracrypt_button = QPushButton("Choose VeraCrypt Location")
        self.start_enroll_button = QPushButton("Start Enroll")
        self.choose_location_button = QPushButton("Choose Location")
        self.create_workspace_button = QPushButton("Create Workspace")
        self.provision_secret_button = QPushButton("Provision Secret")
        self.setup_recovery_button = QPushButton("Generate Recovery Key")
        self.finish_button = QPushButton("Finish")
        self.view_details_button = QPushButton("View Details")
        self.back_button.setObjectName("SecondaryButton")
        self.next_button.setObjectName("PrimaryButton")
        self.recheck_button.setObjectName("SecondaryButton")
        self.choose_veracrypt_button.setObjectName("SecondaryButton")
        self.start_enroll_button.setObjectName("SecondaryButton")
        self.choose_location_button.setObjectName("SecondaryButton")
        self.create_workspace_button.setObjectName("SecondaryButton")
        self.provision_secret_button.setObjectName("SecondaryButton")
        self.setup_recovery_button.setObjectName("SecondaryButton")
        self.view_details_button.setObjectName("SecondaryButton")
        self.finish_button.setObjectName("PrimaryButton")

        self.back_button.clicked.connect(self.go_back)
        self.next_button.clicked.connect(self.go_next)
        self.recheck_button.clicked.connect(self.recheck_current_step)
        self.choose_veracrypt_button.clicked.connect(self.choose_veracrypt_location)
        self.start_enroll_button.clicked.connect(self.start_fingerprint_enroll)
        self.choose_location_button.clicked.connect(self.choose_workspace_location)
        self.create_workspace_button.clicked.connect(self.create_workspace)
        self.provision_secret_button.clicked.connect(self.start_secret_provision)
        self.setup_recovery_button.clicked.connect(self.start_recovery_setup)
        self.finish_button.clicked.connect(self.finish_setup)
        self.view_details_button.clicked.connect(self.open_details_dialog)
        self.enroll_log_signal.connect(self.append_enroll_log)
        self.enroll_finished_signal.connect(self.handle_enroll_finished)
        self.workspace_finished_signal.connect(self.handle_workspace_finished)
        self.provision_log_signal.connect(self.append_provision_log)
        self.provision_status_signal.connect(self.handle_provision_status)
        self.provision_finished_signal.connect(self.handle_secret_provision_finished)
        self.recovery_finished_signal.connect(self.handle_recovery_setup_finished)

        workspace_size_layout = QHBoxLayout()
        workspace_size_layout.setSpacing(8)
        workspace_size_layout.addWidget(self.workspace_size_label)
        workspace_size_layout.addWidget(self.workspace_size_input)
        workspace_size_layout.addStretch()

        self.step_items = []
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("Sidebar")
        self.sidebar_frame.setFixedWidth(230)
        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        sidebar_layout.setContentsMargins(18, 22, 18, 18)
        sidebar_layout.setSpacing(14)
        sidebar_layout.addWidget(self.app_title_label)
        sidebar_layout.addWidget(self.app_subtitle_label)
        sidebar_layout.addSpacing(8)

        self.steps_layout = QVBoxLayout()
        self.steps_layout.setSpacing(6)
        sidebar_layout.addLayout(self.steps_layout)
        sidebar_layout.addStretch()
        self._build_step_sidebar()

        self.content_card = QFrame()
        self.content_card.setObjectName("ContentCard")
        self.content_card.setMaximumWidth(700)
        content_card_layout = QVBoxLayout(self.content_card)
        content_card_layout.setContentsMargins(30, 28, 30, 26)
        content_card_layout.setSpacing(14)
        content_card_layout.addWidget(self.step_counter_label)
        content_card_layout.addWidget(self.step_title_label)
        content_card_layout.addWidget(self.step_description_label)

        self.status_card = QFrame()
        self.status_card.setObjectName("StatusCard")
        status_layout = QVBoxLayout(self.status_card)
        status_layout.setContentsMargins(16, 14, 16, 14)
        status_layout.setSpacing(8)
        status_layout.addWidget(self.status_heading_label)
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        status_row.addWidget(self.status_icon_label, 0, Qt.AlignmentFlag.AlignTop)
        status_row.addWidget(self.step_status_label, 1)
        status_layout.addLayout(status_row)
        content_card_layout.addWidget(self.status_card)

        self.provision_info_frame = QFrame()
        self.provision_info_frame.setObjectName("InfoCard")
        provision_info_layout = QVBoxLayout(self.provision_info_frame)
        provision_info_layout.setContentsMargins(16, 14, 16, 14)
        self.provision_info_label = QLabel(
            "Scan your fingerprint on the hardware key to authorize secure provisioning."
        )
        self.provision_info_label.setObjectName("InfoLabel")
        self.provision_info_label.setWordWrap(True)
        provision_info_layout.addWidget(self.provision_info_label)
        content_card_layout.addWidget(self.provision_info_frame)

        self.workspace_controls_frame = QFrame()
        self.workspace_controls_frame.setObjectName("InlineCard")
        workspace_controls_layout = QVBoxLayout(self.workspace_controls_frame)
        workspace_controls_layout.setContentsMargins(16, 14, 16, 14)
        workspace_controls_layout.setSpacing(10)
        workspace_controls_layout.addWidget(self.workspace_path_label)
        workspace_controls_layout.addLayout(workspace_size_layout)
        workspace_button_layout = QHBoxLayout()
        workspace_button_layout.setSpacing(8)
        workspace_button_layout.addWidget(self.choose_location_button)
        workspace_button_layout.addWidget(self.create_workspace_button)
        workspace_button_layout.addStretch()
        workspace_controls_layout.addLayout(workspace_button_layout)
        content_card_layout.addWidget(self.workspace_controls_frame)

        self.finish_checklist_frame = QFrame()
        self.finish_checklist_frame.setObjectName("InlineCard")
        self.finish_checklist_layout = QVBoxLayout(self.finish_checklist_frame)
        self.finish_checklist_layout.setContentsMargins(16, 14, 16, 14)
        self.finish_checklist_layout.setSpacing(8)
        content_card_layout.addWidget(self.finish_checklist_frame)

        self.step_actions_frame = QFrame()
        self.step_actions_frame.setObjectName("InlineCard")
        self.step_actions_layout = QHBoxLayout(self.step_actions_frame)
        self.step_actions_layout.setContentsMargins(16, 14, 16, 14)
        self.step_actions_layout.setSpacing(8)
        self.step_actions_layout.addWidget(self.recheck_button)
        self.step_actions_layout.addWidget(self.choose_veracrypt_button)
        self.step_actions_layout.addWidget(self.start_enroll_button)
        self.step_actions_layout.addWidget(self.provision_secret_button)
        self.step_actions_layout.addWidget(self.setup_recovery_button)
        self.step_actions_layout.addWidget(self.view_details_button)
        self.step_actions_layout.addStretch()
        content_card_layout.addWidget(self.step_actions_frame)
        content_card_layout.addStretch()

        nav_layout = QHBoxLayout()
        nav_layout.setSpacing(8)
        nav_layout.addStretch()
        nav_layout.addWidget(self.back_button)
        nav_layout.addWidget(self.next_button)
        nav_layout.addWidget(self.finish_button)

        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(34, 30, 34, 24)
        right_layout.setSpacing(16)
        right_layout.addWidget(self.content_card, 0, Qt.AlignmentFlag.AlignTop)
        right_layout.addStretch()
        right_layout.addLayout(nav_layout)

        right_area = QWidget()
        right_area.setLayout(right_layout)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.sidebar_frame)
        layout.addWidget(right_area, 1)

        self.setLayout(layout)
        self.show_current_step()

    def _current_index_from_config(self) -> int:
        config = self.config_manager.load_config()
        saved_step = config.get("setup_step", SetupStep.welcome.value)

        for index, step in enumerate(self.steps):
            if step.value == saved_step:
                return index

        self.config_manager.mark_setup_step(SetupStep.welcome)
        return 0

    def _set_status_indicator(self, text: str, state: str):
        self.status_icon_label.setText(text)
        self.status_icon_label.setProperty("state", state)
        self.status_icon_label.style().unpolish(self.status_icon_label)
        self.status_icon_label.style().polish(self.status_icon_label)

    def _advance_status_spinner(self):
        if not self.spinner_frames:
            return

        self.spinner_index = (self.spinner_index + 1) % len(self.spinner_frames)
        self._set_status_indicator(
            self.spinner_frames[self.spinner_index],
            "loading",
        )

    def _stop_status_spinner(self):
        if self.status_spinner_timer.isActive():
            self.status_spinner_timer.stop()

    def _set_status_idle(self, message: str):
        self._stop_status_spinner()
        self._set_status_indicator("•", "idle")
        self.step_status_label.setText(message)

    def _set_status_loading(self, message: str):
        self.spinner_index = 0
        self._set_status_indicator(self.spinner_frames[self.spinner_index], "loading")
        self.step_status_label.setText(message)
        if not self.status_spinner_timer.isActive():
            self.status_spinner_timer.start(90)

    def _set_status_success(self, message: str):
        self._stop_status_spinner()
        self._set_status_indicator("✓", "success")
        self.step_status_label.setText(message)

    def _set_status_error(self, message: str):
        self._stop_status_spinner()
        self._set_status_indicator("✕", "error")
        self.step_status_label.setText(message)

    def _build_step_sidebar(self):
        for index, step in enumerate(self.steps):
            item = QFrame()
            item.setObjectName("StepItem")
            item.setProperty("state", "pending")

            number_label = QLabel(str(index + 1))
            number_label.setObjectName("StepNumber")
            number_label.setProperty("state", "pending")
            number_label.setFixedSize(24, 24)

            title_label = QLabel(STEP_TITLES[step])
            title_label.setObjectName("StepItemTitle")
            title_label.setProperty("state", "pending")
            title_label.setWordWrap(True)

            state_label = QLabel("Pending")
            state_label.setObjectName("StepItemState")

            text_layout = QVBoxLayout()
            text_layout.setContentsMargins(0, 0, 0, 0)
            text_layout.setSpacing(2)
            text_layout.addWidget(title_label)
            text_layout.addWidget(state_label)

            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(10, 9, 10, 9)
            item_layout.setSpacing(9)
            item_layout.addWidget(number_label, 0, Qt.AlignmentFlag.AlignTop)
            item_layout.addLayout(text_layout, 1)

            self.steps_layout.addWidget(item)
            self.step_items.append(
                {
                    "frame": item,
                    "number": number_label,
                    "title": title_label,
                    "state": state_label,
                }
            )

    def _update_step_sidebar(self):
        for index, item in enumerate(self.step_items):
            if index < self.current_index:
                state = "completed"
                state_text = "Done"
            elif index == self.current_index:
                state = "active"
                state_text = "Current"
            else:
                state = "pending"
                state_text = "Pending"

            for widget_key in ("frame", "number", "title"):
                widget = item[widget_key]
                widget.setProperty("state", state)
                widget.style().unpolish(widget)
                widget.style().polish(widget)

            item["state"].setText(state_text)

    def _refresh_action_frame_visibility(self):
        visible_widgets = (
            self.recheck_button,
            self.choose_veracrypt_button,
            self.start_enroll_button,
            self.provision_secret_button,
            self.setup_recovery_button,
            self.view_details_button,
        )
        # Do not use isVisible() here; the parent frame may already be hidden,
        # which makes visible child buttons report false and keeps the frame hidden.
        self.step_actions_frame.setVisible(
            any(not widget.isHidden() for widget in visible_widgets)
        )

    def _clear_detail_log(self):
        self.log_buffer = []
        self.step_log_area.clear()
        self._sync_detail_log_dialog()

    def _set_detail_log(self, text: str):
        self.log_buffer = text.splitlines()
        self.step_log_area.setPlainText(text)
        self._sync_detail_log_dialog()

    def _append_detail_log(self, line: str):
        self.log_buffer.append(line)
        self.step_log_area.append(line)
        if self.log_dialog is not None and self.log_dialog.isVisible():
            self.log_dialog.append_line(line)

    def _detail_log_text(self) -> str:
        return "\n".join(self.log_buffer)

    def _sync_detail_log_dialog(self):
        if self.log_dialog is not None and self.log_dialog.isVisible():
            self.log_dialog.set_text(self._detail_log_text())

    def open_details_dialog(self):
        title = "Setup Summary" if self.steps[self.current_index] == SetupStep.finish else "Setup Details"
        if self.log_dialog is None or not self.log_dialog.isVisible():
            self.log_dialog = LogDialog(title, self)
            self.log_dialog.finished.connect(self._clear_log_dialog_reference)
        else:
            self.log_dialog.setWindowTitle(title)

        self.log_dialog.set_text(self._detail_log_text())
        self.log_dialog.show()
        self.log_dialog.raise_()
        self.log_dialog.activateWindow()

    def _clear_log_dialog_reference(self):
        self.log_dialog = None

    def _clear_finish_checklist(self):
        while self.finish_checklist_layout.count():
            item = self.finish_checklist_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _set_finish_checklist(self, passed_messages: list[str], failed_messages: list[str]):
        self._clear_finish_checklist()

        for message in passed_messages:
            item = QLabel(f"OK  {message}")
            item.setObjectName("ChecklistItem")
            item.setProperty("state", "ok")
            self.finish_checklist_layout.addWidget(item)

        for message in failed_messages:
            item = QLabel(f"Needs attention  {message}")
            item.setObjectName("ChecklistItem")
            item.setProperty("state", "failed")
            self.finish_checklist_layout.addWidget(item)

        if not passed_messages and not failed_messages:
            item = QLabel("No setup checks have been recorded yet.")
            item.setObjectName("ChecklistItem")
            self.finish_checklist_layout.addWidget(item)

    def _fade_in_content(self):
        try:
            effect = QGraphicsOpacityEffect(self.content_card)
            self.content_card.setGraphicsEffect(effect)

            animation = QPropertyAnimation(effect, b"opacity", self)
            animation.setDuration(180)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.finished.connect(lambda: self.content_card.setGraphicsEffect(None))
            self._content_fade_animation = animation
            animation.start()
        except Exception:
            self.content_card.setGraphicsEffect(None)

    def show_current_step(self):
        current_step = self.steps[self.current_index]
        self.config_manager.mark_setup_step(current_step)

        self.step_counter_label.setText(
            f"Step {self.current_index + 1} of {len(self.steps)}"
        )
        self.step_title_label.setText(STEP_TITLES[current_step])
        self.step_description_label.setText(STEP_DESCRIPTIONS[current_step])
        self.step_key_label.setText(current_step.value)
        self._set_status_idle("This setup step is ready for a later stage.")
        self._clear_finish_checklist()
        self.finish_checklist_frame.setVisible(False)
        details_visible = current_step in (
            SetupStep.enroll_fingerprint,
            SetupStep.provision_secret,
            SetupStep.setup_recovery,
            SetupStep.finish,
        )
        self.view_details_button.setVisible(details_visible)
        self.recheck_button.setVisible(
            current_step in (SetupStep.check_veracrypt, SetupStep.detect_hardware)
        )
        self.choose_veracrypt_button.setVisible(
            current_step == SetupStep.check_veracrypt
        )
        self.start_enroll_button.setVisible(
            current_step == SetupStep.enroll_fingerprint
        )
        self.step_log_area.setVisible(False)
        workspace_step = current_step == SetupStep.create_workspace
        self.workspace_path_label.setVisible(workspace_step)
        self.workspace_size_label.setVisible(workspace_step)
        self.workspace_size_input.setVisible(workspace_step)
        self.workspace_controls_frame.setVisible(workspace_step)
        self.provision_secret_button.setVisible(
            current_step == SetupStep.provision_secret
        )
        self.provision_info_frame.setVisible(
            current_step == SetupStep.provision_secret
        )
        self.setup_recovery_button.setVisible(
            current_step == SetupStep.setup_recovery
        )

        if current_step == SetupStep.welcome:
            self._set_status_idle("Ready to begin setup. Click Next to start.")
        elif current_step == SetupStep.check_veracrypt:
            self.check_veracrypt_status()
            self.hardware_bound = None
            self.fingerprint_enrolled = None
        elif current_step == SetupStep.detect_hardware:
            self.veracrypt_installed = None
            self.fingerprint_enrolled = None
            self.check_hardware_status()
        elif current_step == SetupStep.enroll_fingerprint:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.show_fingerprint_enroll_step()
        elif current_step == SetupStep.create_workspace:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.fingerprint_enrolled = None
            self.show_create_workspace_step()
        elif current_step == SetupStep.provision_secret:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.fingerprint_enrolled = None
            self.show_provision_secret_step()
        elif current_step == SetupStep.setup_recovery:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.fingerprint_enrolled = None
            self.show_setup_recovery_step()
        elif current_step == SetupStep.finish:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.fingerprint_enrolled = None
            self.show_finish_step()
        else:
            self.veracrypt_installed = None
            self.hardware_bound = None
            self.fingerprint_enrolled = None

        self.update_button_states()
        self._refresh_action_frame_visibility()
        self._update_step_sidebar()
        self._fade_in_content()

    def update_button_states(self):
        current_step = self.steps[self.current_index]
        is_first_step = self.current_index == 0
        is_last_step = self.current_index == len(self.steps) - 1
        can_go_next = not is_last_step

        if (
            current_step == SetupStep.check_veracrypt
            and self.veracrypt_installed is not True
        ):
            can_go_next = False

        if (
            current_step == SetupStep.detect_hardware
            and self.hardware_bound is not True
        ):
            can_go_next = False

        if (
            current_step == SetupStep.enroll_fingerprint
            and self.fingerprint_enrolled is not True
        ):
            can_go_next = False

        if (
            current_step == SetupStep.create_workspace
            and self.workspace_created is not True
        ):
            can_go_next = False

        if (
            current_step == SetupStep.provision_secret
            and self.secret_provisioned is not True
        ):
            can_go_next = False

        if (
            current_step == SetupStep.setup_recovery
            and self.recovery_setup_done is not True
        ):
            can_go_next = False

        self.back_button.setEnabled(not is_first_step)
        self.next_button.setEnabled(can_go_next)
        finish_enabled = False
        if current_step == SetupStep.finish:
            finish_enabled = self._get_setup_validation_status()[0]

        self.finish_button.setEnabled(is_last_step and finish_enabled)
        self.recheck_button.setEnabled(True)
        self.choose_veracrypt_button.setEnabled(True)
        self.start_enroll_button.setEnabled(not self.enroll_in_progress)
        workspace_controls_enabled = not self.workspace_creation_in_progress
        self.choose_location_button.setEnabled(workspace_controls_enabled)
        self.workspace_size_input.setEnabled(workspace_controls_enabled)
        self.create_workspace_button.setEnabled(workspace_controls_enabled)
        self.provision_secret_button.setEnabled(
            not self.secret_provision_in_progress
        )
        self.setup_recovery_button.setEnabled(
            not self.recovery_setup_in_progress
            and self.recovery_setup_done is not True
        )

    def recheck_current_step(self):
        current_step = self.steps[self.current_index]
        if current_step == SetupStep.check_veracrypt:
            self.check_veracrypt_status()
        elif current_step == SetupStep.detect_hardware:
            self.check_hardware_status()

    def _resolve_veracrypt_executable_path(self, value) -> Path | None:
        if isinstance(value, str):
            value = value.strip()

        if not value:
            return None

        try:
            path = Path(value)
        except TypeError:
            return None

        if not path.is_absolute():
            path = self.project_root / path

        return path

    def _is_valid_veracrypt_executable(
        self,
        path: Path | str | None,
        require_name: bool = True,
    ) -> bool:
        if path is None:
            return False

        try:
            candidate = Path(path)
            if not candidate.exists() or not candidate.is_file():
                return False
            if require_name and candidate.name.lower() != "veracrypt.exe":
                return False
            return VeraCryptController(exe_path=str(candidate)).is_installed()
        except (OSError, TypeError, ValueError):
            return False

    def check_veracrypt_status(self):
        self._set_status_loading("Checking VeraCrypt installation...")
        config = self.config_manager.load_config()
        veracrypt_config = config.get("veracrypt", {})
        if not isinstance(veracrypt_config, dict):
            veracrypt_config = {}

        configured_path = self._resolve_veracrypt_executable_path(
            veracrypt_config.get("executable_path")
        )
        if self._is_valid_veracrypt_executable(configured_path):
            selected_path = str(configured_path)
            self.config_manager.update_section(
                "veracrypt",
                {
                    "installed": True,
                    "executable_path": selected_path,
                },
            )
            self.veracrypt_installed = True
            self._set_status_success(
                "VeraCrypt detected successfully from the configured location."
            )
            self.update_button_states()
            return

        controller = VeraCryptController()
        installed = controller.is_installed()
        values = {"installed": installed}

        if controller.exe_path:
            values["executable_path"] = str(controller.exe_path)

        self.config_manager.update_section("veracrypt", values)
        self.veracrypt_installed = installed

        if installed:
            self._set_status_success("VeraCrypt detected successfully.")
        else:
            self._set_status_error(
                "VeraCrypt was not detected. If VeraCrypt is not installed, install it from the official VeraCrypt website first. If it is already installed but not detected automatically, click Choose VeraCrypt Location and select VeraCrypt.exe."
            )

        self.update_button_states()

    def choose_veracrypt_location(self):
        config = self.config_manager.load_config()
        veracrypt_config = config.get("veracrypt", {})
        if not isinstance(veracrypt_config, dict):
            veracrypt_config = {}

        configured_path = self._resolve_veracrypt_executable_path(
            veracrypt_config.get("executable_path")
        )
        initial_path = (
            str(configured_path)
            if configured_path is not None
            else r"C:\Program Files\VeraCrypt\VeraCrypt.exe"
        )

        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose VeraCrypt Executable",
            initial_path,
            "VeraCrypt Executable (VeraCrypt.exe);;Executable Files (*.exe);;All Files (*)",
        )
        if not selected_path:
            return

        candidate = Path(selected_path)
        if self._is_valid_veracrypt_executable(candidate):
            self.config_manager.update_section(
                "veracrypt",
                {
                    "installed": True,
                    "executable_path": str(candidate),
                },
            )
            self.veracrypt_installed = True
            self._set_status_success(
                "VeraCrypt detected successfully from the selected location."
            )
        else:
            self.config_manager.update_section(
                "veracrypt",
                {
                    "installed": False,
                    "executable_path": "",
                },
            )
            self.veracrypt_installed = False
            self._set_status_error(
                "The selected file is not a valid VeraCrypt executable. Please choose VeraCrypt.exe."
            )

        self.update_button_states()

    def check_hardware_status(self):
        config = self.config_manager.load_config()
        hardware_config = config.get("hardware", {})
        if not isinstance(hardware_config, dict):
            hardware_config = {}

        key_path = self._config_path(
            hardware_config.get("ed25519_public_key_path"),
            self.project_root / "keys" / "esp_ed25519_public.bin",
        )
        result = detect_trusted_hardware_key(key_path=key_path)

        if result.matched:
            self.config_manager.update_section(
                "hardware",
                {
                    "device_bound": True,
                    "device_id": result.device_id,
                    "detected_port": result.port,
                },
            )
            self.hardware_bound = True
            self._set_status_success(
                f"Hardware key detected and identity verified on {result.port}."
            )
        else:
            self.config_manager.update_section(
                "hardware",
                {
                    "device_bound": False,
                    "device_id": "",
                    "detected_port": "",
                },
            )
            self.hardware_bound = False

            if result.error == "missing_trusted_key":
                self._set_status_error(
                    "Trusted public key file is missing. Cannot bind hardware key."
                )
            elif result.responded:
                self._set_status_error(
                    "A device responded, but its identity does not match the trusted hardware key."
                )
            else:
                self._set_status_idle(
                    "Hardware key was not detected. Connect the USB hardware key and click Recheck."
                )

        self.update_button_states()

    def show_fingerprint_enroll_step(self):
        config = self.config_manager.load_config()
        fingerprint_config = config.get("fingerprint", {})
        if not isinstance(fingerprint_config, dict):
            fingerprint_config = {}

        self.fingerprint_enrolled = (
            fingerprint_config.get("enrolled") is True
            and str(fingerprint_config.get("fingerprint_id", ""))
            == self.enroll_fingerprint_id
        )

        if self.fingerprint_enrolled:
            self._set_status_success(
                "Fingerprint enrollment completed successfully for ID 1."
            )
        else:
            self._set_status_idle(
                "Fingerprint enrollment is required. Click Start Enroll and follow the hardware key instructions."
            )
            self._clear_detail_log()

    def start_fingerprint_enroll(self):
        if self.enroll_in_progress:
            return

        config = self.config_manager.load_config()
        hardware_config = config.get("hardware", {})
        if not isinstance(hardware_config, dict):
            hardware_config = {}

        port = str(hardware_config.get("detected_port", "")).strip()
        if not port:
            self.config_manager.update_section(
                "fingerprint",
                {
                    "enrolled": False,
                },
            )
            self.fingerprint_enrolled = False
            self._set_status_error(
                "Hardware key is not detected. Please go back to Detect Hardware Key and recheck."
            )
            self.update_button_states()
            return

        self.config_manager.update_section(
            "fingerprint",
            {
                "enrolled": False,
            },
        )
        self.fingerprint_enrolled = False
        self.enroll_in_progress = True
        self._clear_detail_log()
        self._set_status_loading(
            "Fingerprint enrollment started. Follow the instructions from the hardware key."
        )
        self.update_button_states()

        worker = threading.Thread(
            target=self._fingerprint_enroll_worker,
            args=(port, self.enroll_fingerprint_id),
            daemon=True,
        )
        worker.start()

    def _fingerprint_enroll_worker(self, port: str, fingerprint_id: str):
        ser = None
        deadline = time.time() + 60.0

        try:
            ser = serial.Serial(port, 115200, timeout=1.0)
            time.sleep(1.5)

            try:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                pass

            ser.write(f"e{fingerprint_id}\n".encode("utf-8"))
            ser.flush()

            while time.time() < deadline:
                line = ser.readline().decode(errors="ignore").strip()
                if not line:
                    continue

                self.enroll_log_signal.emit(line)

                if line.startswith("ENROLL_OK:"):
                    enrolled_id = line.split(":", 1)[1].strip()
                    if enrolled_id == fingerprint_id:
                        self.enroll_finished_signal.emit(
                            True,
                            "Fingerprint enrollment completed successfully for ID 1.",
                        )
                    else:
                        self.enroll_finished_signal.emit(
                            False,
                            f"Fingerprint enrollment failed with code unexpected_id_{enrolled_id}.",
                        )
                    return

                if line.startswith("ENROLL_FAIL:"):
                    error_code = line.split(":", 1)[1].strip()
                    self.enroll_finished_signal.emit(
                        False,
                        f"Fingerprint enrollment failed with code {error_code}.",
                    )
                    return

            self.enroll_finished_signal.emit(
                False,
                "Fingerprint enrollment timed out. Please try again.",
            )
        except Exception:
            self.enroll_finished_signal.emit(
                False,
                "Fingerprint enrollment failed with code serial_error.",
            )
        finally:
            try:
                if ser and ser.is_open:
                    ser.close()
            except Exception:
                pass

    def append_enroll_log(self, line: str):
        self._append_detail_log(line)

    def handle_enroll_finished(self, success: bool, message: str):
        self.enroll_in_progress = False

        if success:
            self._set_status_success(message)
            self.config_manager.update_section(
                "fingerprint",
                {
                    "enrolled": True,
                    "fingerprint_id": self.enroll_fingerprint_id,
                },
            )
            self.fingerprint_enrolled = True
        else:
            self._set_status_error(message)
            self.config_manager.update_section(
                "fingerprint",
                {
                    "enrolled": False,
                },
            )
            self.fingerprint_enrolled = False

        self.update_button_states()

    def show_create_workspace_step(self):
        config = self.config_manager.load_config()
        workspace_config = config.get("workspace", {})
        if not isinstance(workspace_config, dict):
            workspace_config = {}

        configured_path = str(workspace_config.get("container_path", "")).strip()
        if configured_path:
            self.selected_workspace_path = str(
                self._config_path(
                    configured_path,
                    self.project_root / "data" / "workspace.hc",
                )
            )

        self.update_workspace_path_label()

        container_path = Path(self.selected_workspace_path)
        self.workspace_created = (
            workspace_config.get("container_created") is True
            and container_path.exists()
        )

        if self.workspace_created:
            self._set_status_success(
                "Workspace container already exists. You can continue."
            )
        else:
            self._set_status_idle(
                "Choose a VeraCrypt container location and click Create Workspace."
            )

    def update_workspace_path_label(self):
        self.workspace_path_label.setText(
            f"Container path: {self.selected_workspace_path}"
        )

    def choose_workspace_location(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Choose Workspace Container",
            self.selected_workspace_path,
            "VeraCrypt Containers (*.hc);;All Files (*)",
        )
        if not file_path:
            return

        self.selected_workspace_path = file_path
        self.workspace_created = False
        self.generated_workspace_password = None
        self.update_workspace_path_label()
        self._set_status_idle(
            "Choose a VeraCrypt container location and click Create Workspace."
        )
        self.update_button_states()

    def create_workspace(self):
        if self.workspace_creation_in_progress:
            return

        container_path = Path(self.selected_workspace_path)
        if container_path.exists():
            if container_path.is_dir():
                self._set_status_error(
                    "Selected workspace path is a directory. Choose a file path."
                )
                return

            response = QMessageBox.question(
                self,
                "Overwrite Workspace Container",
                (
                    "The selected container file already exists. "
                    "Overwrite it and create a new workspace?"
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if response != QMessageBox.StandardButton.Yes:
                return

            try:
                container_path.unlink()
            except OSError as e:
                self._set_status_error(
                    f"Failed to remove existing container: {e}"
                )
                return

        # Firmware temporary/dev provisioning accepts passwords up to 64 chars;
        # 32 random bytes encoded as URL-safe text keeps a safety margin.
        password = secrets.token_urlsafe(32)
        self.generated_workspace_password = password
        self.workspace_created = False
        self.workspace_creation_in_progress = True
        self._set_status_loading("Creating VeraCrypt workspace...")
        self.update_button_states()

        config = self.config_manager.load_config()
        veracrypt_config = config.get("veracrypt", {})
        if not isinstance(veracrypt_config, dict):
            veracrypt_config = {}

        exe_path = str(veracrypt_config.get("executable_path", "")).strip() or None
        size_mb = int(self.workspace_size_input.value())

        worker = threading.Thread(
            target=self._create_workspace_worker,
            args=(str(container_path), password, size_mb, exe_path),
            daemon=True,
        )
        worker.start()

    def _create_workspace_worker(
        self,
        container_path: str,
        password: str,
        size_mb: int,
        exe_path: str | None,
    ):
        controller = VeraCryptController(exe_path=exe_path)
        success, message = controller.create_container(
            container_path,
            password,
            size_mb=size_mb,
        )
        self.workspace_finished_signal.emit(success, message, container_path)

    def handle_workspace_finished(self, success: bool, message: str, container_path: str):
        self.workspace_creation_in_progress = False

        if success:
            self._set_status_success(message)
            self.config_manager.update_section(
                "workspace",
                {
                    "container_created": True,
                    "container_path": container_path,
                    "mount_letter": "X",
                },
            )
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_generated": True,
                    "password_provisioned_to_device": False,
                },
            )
            self.workspace_created = True
            self.selected_workspace_path = container_path
            self.update_workspace_path_label()
        else:
            self._set_status_error(message)
            self.generated_workspace_password = None
            self.config_manager.update_section(
                "workspace",
                {
                    "container_created": False,
                },
            )
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_generated": False,
                },
            )
            self.workspace_created = False

        self.update_button_states()

    def show_provision_secret_step(self):
        config = self.config_manager.load_config()
        workspace_config = config.get("workspace", {})
        if not isinstance(workspace_config, dict):
            workspace_config = {}

        provisioning_config = config.get("provisioning", {})
        if not isinstance(provisioning_config, dict):
            provisioning_config = {}

        workspace_created = workspace_config.get("container_created") is True
        if workspace_created and not self.generated_workspace_password:
            self._set_status_error(
                "Workspace password is not available in memory. Please recreate the workspace before provisioning."
            )
            self.secret_provisioned = False
            self._clear_detail_log()
            return

        self.secret_provisioned = (
            provisioning_config.get("password_provisioned_to_device") is True
        )

        if self.secret_provisioned:
            self._set_status_success(
                "Workspace secret has already been provisioned to the hardware key."
            )
            return

        if not workspace_created:
            self._set_status_error(
                "Workspace has not been created yet. Please create the workspace before provisioning."
            )
            self.secret_provisioned = False
            self._clear_detail_log()
            return

        self.secret_provisioned = False
        self._clear_detail_log()
        self._set_status_idle(
            "Scan your fingerprint on the hardware key to authorize secure provisioning."
        )

    def start_secret_provision(self):
        if self.secret_provision_in_progress:
            return

        if not self.generated_workspace_password:
            self._set_status_error(
                "Workspace password is not available in memory. Please recreate the workspace before provisioning."
            )
            self.secret_provisioned = False
            self.update_button_states()
            return

        config = self.config_manager.load_config()
        hardware_config = config.get("hardware", {})
        if not isinstance(hardware_config, dict):
            hardware_config = {}

        port = str(hardware_config.get("detected_port", "")).strip()
        if not port:
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_provisioned_to_device": False,
                },
            )
            self.secret_provisioned = False
            self._set_status_error(
                "Hardware key is not detected. Please go back to Detect Hardware Key and recheck."
            )
            self.update_button_states()
            return

        esp_x25519_public_key_bytes = self._load_esp_x25519_public_key_bytes(
            hardware_config
        )
        if esp_x25519_public_key_bytes is None:
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_provisioned_to_device": False,
                },
            )
            self.secret_provisioned = False
            self._set_status_error(
                "Secure provisioning failed: ESP X25519 public key file is missing or invalid."
            )
            self.update_button_states()
            return

        self.secret_provisioned = False
        self.secret_provision_in_progress = True
        self._clear_detail_log()
        self._set_status_loading("Waiting for fingerprint authorization...")
        self.update_button_states()

        worker = threading.Thread(
            target=self._secret_provision_worker,
            args=(port, self.generated_workspace_password, esp_x25519_public_key_bytes),
            daemon=True,
        )
        worker.start()

    def _load_esp_x25519_public_key_bytes(self, hardware_config: dict) -> bytes | None:
        key_path = self._config_path(
            hardware_config.get("x25519_public_key_path"),
            self.project_root / "keys" / "esp_x25519_public.bin",
        )

        try:
            key_bytes = key_path.read_bytes()
        except OSError:
            return None

        if len(key_bytes) != 32:
            return None

        return key_bytes

    def _read_serial_line_safe(self, ser) -> str:
        return ser.readline().decode(errors="ignore").strip()

    def _b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    def _log_provision_line_safe(self, line: str, password: str | None = None):
        if not line:
            return

        safe_line = line
        if password:
            safe_line = safe_line.replace(password, "<redacted>")

        if "PROVISION_REQ:" in safe_line or "PROVISION_REQ_B64:" in safe_line:
            safe_line = "PROVISION_REQ:<redacted>"

        self.provision_log_signal.emit(safe_line)

    def _wait_for_esp_ready_for_provisioning(self, ser, timeout=8.0) -> bool:
        deadline = time.time() + timeout
        next_ping_at = 0.0
        ready_prefixes = (
            "DEVICE_READY",
            "VC_PASSWORD_STATUS:",
            "TEMPLATE_COUNT:",
            "ED25519_PUBKEY:",
        )

        while time.time() < deadline:
            now = time.time()
            if now >= next_ping_at:
                try:
                    ser.write(b"PING\r\n")
                    ser.flush()
                except Exception:
                    pass
                next_ping_at = now + 1.0

            line = self._read_serial_line_safe(ser)
            if not line:
                continue

            self._log_provision_line_safe(line)

            if line == "PONG" or line.startswith(ready_prefixes):
                return True

        return False

    def _wait_for_provisioning_authorization(self, ser, timeout=30.0) -> bool:
        self.provision_log_signal.emit(
            "Please scan your fingerprint on the hardware key to authorize provisioning."
        )
        deadline = time.time() + timeout

        while time.time() < deadline:
            line = self._read_serial_line_safe(ser)
            if not line:
                continue

            self._log_provision_line_safe(line)

            if line.startswith("MATCH_READY:"):
                self.provision_status_signal.emit(
                    "loading",
                    "Fingerprint authorized. Preparing secure provisioning...",
                )
                return True

        return False

    def _secret_provision_worker(
        self,
        port: str,
        password: str,
        esp_x25519_public_key_bytes: bytes,
    ):
        ser = None

        try:
            ser = serial.Serial(port, 115200, timeout=0.5)
            time.sleep(0.5)

            ready = self._wait_for_esp_ready_for_provisioning(ser)
            if not ready:
                self.provision_log_signal.emit(
                    "ESP ready signal was not detected; trying provisioning command anyway."
                )

            try:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                pass

            authorized = self._wait_for_provisioning_authorization(ser)
            if not authorized:
                self.provision_finished_signal.emit(
                    False,
                    "Secure provisioning timed out waiting for fingerprint authorization.",
                )
                return

            try:
                esp_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
                    esp_x25519_public_key_bytes
                )
            except ValueError:
                self.provision_finished_signal.emit(
                    False,
                    "Secure provisioning failed: ESP X25519 public key file is missing or invalid.",
                )
                return

            challenge = secrets.token_bytes(32)
            pc_private = x25519.X25519PrivateKey.generate()
            pc_public_bytes = pc_private.public_key().public_bytes_raw()
            nonce = secrets.token_bytes(12)
            shared_secret = pc_private.exchange(esp_x25519_public_key)
            aes_key = hashlib.sha256(
                shared_secret + challenge + b"PROVISION_V1"
            ).digest()
            aad = challenge + pc_public_bytes
            plaintext = password.encode("utf-8")

            try:
                encrypted = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
            finally:
                plaintext = None

            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]
            command = (
                "PROVISION_REQ_B64:"
                f"{self._b64(challenge)}:"
                f"{self._b64(pc_public_bytes)}:"
                f"{self._b64(nonce)}:"
                f"{self._b64(ciphertext)}:"
                f"{self._b64(tag)}\r\n"
            )

            try:
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                pass

            self.provision_log_signal.emit(
                f"Secure provisioning command length: {len(command)} bytes"
            )
            ser.write(command.encode("utf-8"))
            ser.flush()
            command = ""
            ciphertext = None
            tag = None
            encrypted = None
            self.provision_log_signal.emit("Secure provisioning command sent.")
            self.provision_status_signal.emit(
                "loading",
                "Secure provisioning request sent. Waiting for hardware key confirmation...",
            )

            deadline = time.time() + 20.0
            while time.time() < deadline:
                line = self._read_serial_line_safe(ser)
                if not line:
                    continue

                self._log_provision_line_safe(line, password=password)

                if line == "PROVISION_OK":
                    self.provision_log_signal.emit(
                        "Hardware key accepted secure provisioning."
                    )
                    self.provision_status_signal.emit(
                        "loading",
                        "Hardware key accepted secure provisioning. Verifying stored secret...",
                    )
                    break

                if line == "PROVISION_DENY":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning denied: fingerprint authorization is required.",
                    )
                    return

                if line == "PROVISION_ERROR:FORMAT":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid command format.",
                    )
                    return

                if line == "PROVISION_ERROR:CHALLENGE":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid challenge.",
                    )
                    return

                if line == "PROVISION_ERROR:PCPUB":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid PC public key.",
                    )
                    return

                if line == "PROVISION_ERROR:NONCE":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid nonce.",
                    )
                    return

                if line == "PROVISION_ERROR:CIPHER":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid encrypted payload.",
                    )
                    return

                if line == "PROVISION_ERROR:TAG":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: invalid authentication tag.",
                    )
                    return

                if line == "PROVISION_ERROR:TAG_VERIFY":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: encrypted payload authentication failed.",
                    )
                    return

                if line == "PROVISION_STORE_FAIL":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: ESP could not store the secret.",
                    )
                    return

                if line == "VC_PASSWORD_STORE_FAIL":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: ESP could not store the secret.",
                    )
                    return

                if line == "VC_PASSWORD_INVALID_LENGTH":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: generated password length is not accepted by firmware.",
                    )
                    return

                if line == "NVS_OPEN_FAIL":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: ESP NVS open failed.",
                    )
                    return

                if line == "NVS_WRITE_FAIL":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: ESP NVS write failed.",
                    )
                    return

                if line == "UNKNOWN_CMD":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning failed: firmware does not support PROVISION_REQ.",
                    )
                    return
            else:
                self.provision_finished_signal.emit(
                    False,
                    "Secure provisioning timed out. Please try again.",
                )
                return

            ser.write(b"HAS_VC_PASSWORD\r\n")
            ser.flush()

            verify_deadline = time.time() + 10.0
            while time.time() < verify_deadline:
                line = self._read_serial_line_safe(ser)
                if not line:
                    continue

                self._log_provision_line_safe(line, password=password)

                if line == "VC_PASSWORD_SET":
                    self.provision_finished_signal.emit(
                        True,
                        "Workspace secret stored on the hardware key successfully.",
                    )
                    return

                if line == "VC_PASSWORD_MISSING":
                    self.provision_finished_signal.emit(
                        False,
                        "Secure provisioning verification failed.",
                    )
                    return

            self.provision_finished_signal.emit(
                False,
                "Secure provisioning timed out. Please try again.",
            )
        except Exception:
            self.provision_finished_signal.emit(
                False,
                "Secure provisioning failed with code serial_error.",
            )
        finally:
            try:
                if ser and ser.is_open:
                    ser.close()
            except Exception:
                pass

    def append_provision_log(self, line: str):
        self._append_detail_log(line)

    def handle_provision_status(self, state: str, message: str):
        if state == "success":
            self._set_status_success(message)
        elif state == "error":
            self._set_status_error(message)
        else:
            self._set_status_loading(message)

    def handle_secret_provision_finished(self, success: bool, message: str):
        self.secret_provision_in_progress = False

        if success:
            self._append_detail_log(message)
            self._set_status_success(message)
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_generated": True,
                    "password_provisioned_to_device": True,
                    "method": "x25519_aesgcm",
                },
            )
            self.secret_provisioned = True
        else:
            self._append_detail_log(message)
            self._set_status_error(
                "Secure provisioning failed. View the technical log for details."
            )
            self.config_manager.update_section(
                "provisioning",
                {
                    "password_provisioned_to_device": False,
                },
            )
            self.secret_provisioned = False

        self.update_button_states()

    def _is_recovery_configured(self) -> bool:
        try:
            config = self.config_manager.load_config()
            recovery_config = config.get("recovery", {})
            if not isinstance(recovery_config, dict):
                return False

            if recovery_config.get("enabled") is not True:
                return False

            recovery_blob_path = self._config_path(
                recovery_config.get("recovery_blob_path"),
                self.project_root / "data" / "recovery_blob.json",
            )
            return recovery_blob_path.is_file()
        except (OSError, TypeError, ValueError):
            return False

    def show_setup_recovery_step(self):
        if self._is_recovery_configured():
            self.recovery_setup_done = True
            self._set_status_success(
                "Recovery key is already configured. You can continue to the next step."
            )
            self.update_button_states()
            return

        if not self.generated_workspace_password:
            self._set_status_error(
                "Workspace password is not available in memory. Please recreate the workspace before setting up recovery."
            )
            self.recovery_setup_done = False
            self._clear_detail_log()
            return

        if self.recovery_setup_done:
            self._set_status_success(
                "Recovery setup completed. You can continue."
            )
            return

        self.recovery_setup_done = False
        self._clear_detail_log()
        self._set_status_idle(
            "Generate a one-time recovery key. It will be shown once, so write it down offline."
        )

    def start_recovery_setup(self):
        if self.recovery_setup_in_progress:
            return

        if self._is_recovery_configured():
            self.recovery_setup_done = True
            self._set_status_success(
                "Recovery key is already configured. You can continue to the next step."
            )
            self.update_button_states()
            return

        if not self.generated_workspace_password:
            self._set_status_error(
                "Workspace password is not available in memory. Please recreate the workspace before setting up recovery."
            )
            self.recovery_setup_done = False
            self.update_button_states()
            return

        self.recovery_setup_done = False
        self.recovery_setup_in_progress = True
        self._clear_detail_log()
        self._set_status_loading("Generating one-time recovery key...")
        self.update_button_states()

        worker = threading.Thread(
            target=self._recovery_setup_worker,
            args=(self.generated_workspace_password,),
            daemon=True,
        )
        worker.start()

    def _recovery_setup_worker(self, password: str):
        try:
            recovery_key = RecoveryManager(self.project_root).create_recovery_blob(
                password
            )
        except RecoveryError as e:
            self.recovery_finished_signal.emit(
                False,
                f"Recovery setup failed: {e}",
                "",
            )
            return
        except Exception:
            self.recovery_finished_signal.emit(
                False,
                "Recovery setup failed.",
                "",
            )
            return

        self.recovery_finished_signal.emit(
            True,
            "Recovery setup completed successfully.",
            recovery_key,
        )

    def handle_recovery_setup_finished(
        self,
        success: bool,
        message: str,
        recovery_key: str,
    ):
        self.recovery_setup_in_progress = False

        if success:
            self._set_status_success(message)
            self.config_manager.update_section(
                "recovery",
                {
                    "enabled": True,
                    "recovery_blob_path": "data/recovery_blob.json",
                    "consumed_flag_path": "data/recovery_consumed.flag",
                },
            )
            self.recovery_setup_done = True
            QMessageBox.information(
                self,
                "Recovery Key Generated",
                (
                    "Write this recovery key down offline. It will not be shown again. "
                    "It can only be used once.\n\n"
                    f"{recovery_key}"
                ),
            )
        else:
            if self._is_recovery_configured():
                self.recovery_setup_done = True
                self._set_status_success(
                    "Recovery key is already configured. You can continue to the next step."
                )
            else:
                self._set_status_error(message)
                self.config_manager.update_section(
                    "recovery",
                    {
                        "enabled": False,
                    },
                )
                self.recovery_setup_done = False

        recovery_key = ""
        self.update_button_states()

    def _config_path(self, value, default_path: Path) -> Path:
        if isinstance(value, str):
            value = value.strip()

        if not value:
            return default_path

        try:
            path = Path(value)
        except TypeError:
            return default_path

        if path.is_absolute():
            return path

        return self.project_root / path

    def _get_setup_validation_status(self) -> tuple[bool, list[str], list[str]]:
        config = self.config_manager.load_config()

        def section(name: str) -> dict:
            value = config.get(name, {})
            return value if isinstance(value, dict) else {}

        veracrypt_config = section("veracrypt")
        hardware_config = section("hardware")
        fingerprint_config = section("fingerprint")
        workspace_config = section("workspace")
        provisioning_config = section("provisioning")
        recovery_config = section("recovery")

        workspace_path = self._config_path(
            workspace_config.get("container_path"),
            self.project_root / "data" / "workspace.hc",
        )
        recovery_blob_path = self._config_path(
            recovery_config.get("recovery_blob_path"),
            self.project_root / "data" / "recovery_blob.json",
        )

        def path_exists(path: Path) -> bool:
            try:
                return path.exists()
            except OSError:
                return False

        checks = (
            (
                veracrypt_config.get("installed") is True,
                "VeraCrypt detected",
                "VeraCrypt is not detected",
            ),
            (
                hardware_config.get("device_bound") is True,
                "Hardware key verified",
                "Hardware key is not verified",
            ),
            (
                fingerprint_config.get("enrolled") is True,
                "Fingerprint enrolled",
                "Fingerprint is not enrolled",
            ),
            (
                workspace_config.get("container_created") is True,
                "Workspace container created",
                "Workspace container is not marked as created",
            ),
            (
                path_exists(workspace_path),
                "Workspace file exists",
                "Workspace file is missing",
            ),
            (
                provisioning_config.get("password_provisioned_to_device") is True,
                "Secret provisioned to hardware key",
                "Secret is not provisioned to the hardware key",
            ),
            (
                recovery_config.get("enabled") is True,
                "Recovery key configured",
                "Recovery key is not configured",
            ),
            (
                path_exists(recovery_blob_path),
                "Recovery blob exists",
                "Recovery blob file is missing",
            ),
        )

        passed_messages = [passed for ok, passed, _failed in checks if ok]
        failed_messages = [failed for ok, _passed, failed in checks if not ok]
        return not failed_messages, passed_messages, failed_messages

    def show_finish_step(self):
        all_ok, passed_messages, failed_messages = self._get_setup_validation_status()

        summary_lines = ["Setup summary", ""]
        if passed_messages:
            summary_lines.append("Completed checks:")
            summary_lines.extend(f"[OK] {message}" for message in passed_messages)

        if failed_messages:
            summary_lines.extend(("", "Items needing attention:"))
            summary_lines.extend(f"[FAILED] {message}" for message in failed_messages)

        self._set_detail_log("\n".join(summary_lines))
        self._clear_finish_checklist()

        if all_ok:
            self._set_status_success(
                "Setup validation passed. Click Finish to open the app."
            )
        else:
            self._set_status_error(
                "Setup validation is incomplete. Resolve failed items before finishing."
            )

    def go_back(self):
        if self.current_index > 0:
            self.current_index -= 1
            self.show_current_step()

    def go_next(self):
        if self.steps[self.current_index] == SetupStep.check_veracrypt:
            self.check_veracrypt_status()
            if self.veracrypt_installed is not True:
                return

        if self.steps[self.current_index] == SetupStep.detect_hardware:
            self.check_hardware_status()
            if self.hardware_bound is not True:
                return

        if (
            self.steps[self.current_index] == SetupStep.enroll_fingerprint
            and self.fingerprint_enrolled is not True
        ):
            return

        if (
            self.steps[self.current_index] == SetupStep.create_workspace
            and self.workspace_created is not True
        ):
            return

        if (
            self.steps[self.current_index] == SetupStep.provision_secret
            and self.secret_provisioned is not True
        ):
            return

        if (
            self.steps[self.current_index] == SetupStep.setup_recovery
            and self.recovery_setup_done is not True
        ):
            return

        if self.current_index < len(self.steps) - 1:
            self.current_index += 1
            self.show_current_step()

    def finish_setup(self):
        all_ok, _passed_messages, failed_messages = self._get_setup_validation_status()
        if not all_ok:
            self.show_finish_step()
            QMessageBox.warning(
                self,
                "Setup Incomplete",
                (
                    "Setup cannot be completed yet. Resolve these items first:\n\n"
                    + "\n".join(f"- {message}" for message in failed_messages)
                ),
            )
            return

        self.config_manager.mark_setup_completed()
        QMessageBox.information(self, "Setup Complete", "Setup is complete.")
        self.main_window = MainWindow(config_manager=self.config_manager)
        self.main_window.show()
        self.close()
