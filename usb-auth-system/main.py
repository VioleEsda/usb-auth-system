import sys
from PyQt6.QtWidgets import QApplication
from gui.main_window import MainWindow
from setup.setup_wizard import SetupWizardWindow
from utils.config_manager import ConfigManager


def main():
    app = QApplication(sys.argv)
    config_manager = ConfigManager()

    if config_manager.is_setup_completed():
        window = MainWindow(config_manager=config_manager)
    else:
        window = SetupWizardWindow(config_manager)

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
