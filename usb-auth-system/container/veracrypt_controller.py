import os
import shutil
import subprocess


class VeraCryptController:
    def __init__(self, exe_path=None):
        self.exe_path = exe_path or self._find_veracrypt()
        self.container_path = r"K:\secure\workspace.hc"
        self.mount_letter = "X"

    def _find_veracrypt(self):
        common_paths = [
            r"C:\Program Files\VeraCrypt\VeraCrypt.exe",
            r"C:\Program Files (x86)\VeraCrypt\VeraCrypt.exe",
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        return shutil.which("VeraCrypt")

    def is_installed(self) -> bool:
        return self.exe_path is not None and os.path.exists(self.exe_path)

    def mount_container(self, password: str):
        if not self.is_installed():
            return False, "VeraCrypt is not installed"

        if not os.path.exists(self.container_path):
            return False, f"Container not found: {self.container_path}"

        cmd = [
            self.exe_path,
            "/v", self.container_path,
            "/l", self.mount_letter,
            "/p", password,
            "/q", "/s", "/quit",
            "/m", "rm",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return False, "VeraCrypt mount timed out"
        except OSError as e:
            return False, f"Failed to start VeraCrypt: {e}"

        if result.returncode == 0:
            return True, f"Container mounted on {self.mount_letter}:"

        return False, result.stderr.strip() or result.stdout.strip() or "Mount failed"

    def unmount_container(self):
        if not self.is_installed():
            return False, "VeraCrypt is not installed"

        cmd = [
            self.exe_path,
            "/d", self.mount_letter,
            "/q", "/s", "/quit",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return False, "VeraCrypt unmount timed out"
        except OSError as e:
            return False, f"Failed to start VeraCrypt: {e}"

        if result.returncode == 0:
            return True, "Container unmounted"

        return False, result.stderr.strip() or result.stdout.strip() or "Unmount failed"
