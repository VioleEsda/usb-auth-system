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

    def _find_veracrypt_format(self):
        if self.exe_path:
            exe_dir = os.path.dirname(self.exe_path)
            candidate = os.path.join(exe_dir, "VeraCrypt Format.exe")
            if os.path.exists(candidate):
                return candidate

        return (
            shutil.which("VeraCrypt Format.exe")
            or shutil.which("VeraCrypt Format")
            or self.exe_path
        )

    def _format_command_for_debug(self, cmd: list[str]) -> str:
        redacted_cmd = []
        redact_next = False

        for part in cmd:
            if redact_next:
                redacted_cmd.append("<redacted>")
                redact_next = False
                continue

            redacted_cmd.append(part)
            if part.lower() in {"/password", "/p"}:
                redact_next = True

        return " ".join(f'"{part}"' if " " in part else part for part in redacted_cmd)

    def is_installed(self) -> bool:
        return self.exe_path is not None and os.path.exists(self.exe_path)

    def create_container(
        self,
        container_path: str,
        password: str,
        size_mb: int = 100,
        silent: bool = False,
    ) -> tuple[bool, str]:
        if not self.is_installed():
            return False, "VeraCrypt is not installed"

        try:
            size_mb = int(size_mb)
        except (TypeError, ValueError):
            return False, "Invalid container size"

        if size_mb <= 0:
            return False, "Invalid container size"

        container_path = os.path.abspath(container_path)
        parent_dir = os.path.dirname(container_path)

        try:
            os.makedirs(parent_dir, exist_ok=True)
        except OSError as e:
            return False, f"Failed to create container directory: {e}"

        if os.path.exists(container_path):
            return False, f"Container already exists: {container_path}"

        creator_exe = self._find_veracrypt_format()
        if not creator_exe or not os.path.exists(creator_exe):
            return False, "VeraCrypt format tool is not available"

        cmd = [
            creator_exe,
            "/create", container_path,
            "/size", f"{size_mb}M",
            "/password", password,
            "/hash", "sha512",
            "/encryption", "AES",
            "/filesystem", "FAT",
            "/quick",
            "/force",
        ]
        if silent:
            cmd.append("/silent")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return False, "VeraCrypt container creation timed out"
        except OSError as e:
            return False, f"Failed to start VeraCrypt: {e}"

        if result.returncode == 0:
            return True, "Container created successfully."

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        debug_command = self._format_command_for_debug(cmd)
        return False, (
            "Container creation failed.\n"
            f"Return code: {result.returncode}\n"
            f"Command: {debug_command}\n"
            f"stdout: {stdout or '<empty>'}\n"
            f"stderr: {stderr or '<empty>'}"
        )

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
