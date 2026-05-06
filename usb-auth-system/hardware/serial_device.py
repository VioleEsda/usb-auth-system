import queue
import threading
import time

import serial

from hardware.device_detector import find_hardware_key


class SerialDevice:
    def __init__(self, port=None, baudrate=115200, timeout=1.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout

        self.ser = None
        self.running = False
        self.connected = False
        self.thread = None
        self.callback = None

        self.line_queue = queue.Queue()
        self.write_lock = threading.Lock()

        self.last_seen = 0
        self.disconnect_notified = False

    def ping(self, timeout: float = 1.5) -> bool:
        if not self.is_connected():
            return False

        try:
            # bersihkan line lama supaya PONG yang dibaca benar-benar response terbaru
            self.clear_pending_lines()

            if not self.send_line("PING"):
                return False

            response = self.wait_for_prefix("PONG", timeout=timeout)
            return response == "PONG"

        except Exception as e:
            print(f"[SerialDevice] Ping failed: {e}")
            self.connected = False
            self.running = False
            self._notify_disconnected_once()
            return False

    def connect(self) -> bool:
        try:
            if self.port is None:
                self.port = find_hardware_key(
                    baudrate=self.baudrate,
                    timeout=self.timeout
                )

                if self.port is None:
                    print("[SerialDevice] Hardware key not found.")
                    self.connected = False
                    return False

            self.ser = serial.Serial(
                self.port,
                self.baudrate,
                timeout=self.timeout
            )

            # ESP32-S3 biasanya reset saat serial dibuka.
            time.sleep(1.5)

            try:
                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
            except Exception:
                pass

            self.running = True
            self.connected = True
            self.disconnect_notified = False
            self.last_seen = time.time()

            self.thread = threading.Thread(
                target=self.listen_loop,
                daemon=True
            )
            self.thread.start()

            print(f"[SerialDevice] Connected to {self.port}")
            return True

        except Exception as e:
            print(f"[SerialDevice] Connection failed: {e}")
            self.connected = False
            self.running = False
            return False

    def listen_loop(self):
        while self.running:
            try:
                if self.ser is None or not self.ser.is_open:
                    self.connected = False
                    self.running = False
                    self._notify_disconnected_once()
                    break

                raw = self.ser.readline()

                if not raw:
                    continue

                line = raw.decode(errors="ignore").strip()

                if not line:
                    continue

                self.last_seen = time.time()

                # Semua line masuk queue supaya bisa ditunggu oleh wait_for_prefix().
                self.line_queue.put(line)

                # Callback dipanggil di thread terpisah supaya listener tidak berhenti
                # saat GUI melakukan secure unlock dan menunggu UNLOCK_BLOB.
                if line != "PONG" and self.callback:
                    threading.Thread(
                        target=self.callback,
                        args=(line,),
                        daemon=True
                    ).start()

            except Exception as e:
                print(f"[SerialDevice] Disconnected/Error: {e}")
                self.connected = False
                self.running = False
                self._notify_disconnected_once()

                break

    def set_callback(self, callback):
        self.callback = callback

    def _notify_disconnected_once(self):
        if self.disconnect_notified:
            return

        self.disconnect_notified = True

        if self.callback:
            try:
                threading.Thread(
                    target=self.callback,
                    args=("DEVICE_DISCONNECTED",),
                    daemon=True
                ).start()
            except Exception:
                pass

    def send_line(self, command: str) -> bool:
        if not self.is_connected():
            return False

        try:
            with self.write_lock:
                self.ser.write((command + "\n").encode("utf-8"))
                self.ser.flush()
            return True

        except Exception as e:
            print(f"[SerialDevice] Send failed: {e}")
            self.connected = False
            self.running = False
            self._notify_disconnected_once()
            return False

    def wait_for_prefix(self, prefix: str, timeout: float = 5.0) -> str | None:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())

            try:
                line = self.line_queue.get(timeout=remaining)

                if line.startswith(prefix):
                    return line

            except queue.Empty:
                return None

        return None

    def clear_pending_lines(self) -> None:
        while True:
            try:
                self.line_queue.get_nowait()
            except queue.Empty:
                break

    def is_connected(self) -> bool:
        return (
            self.connected
            and self.ser is not None
            and self.ser.is_open
        )

    def is_alive(self, timeout: float = 5.0) -> bool:
        if not self.is_connected():
            return False

        return (time.time() - self.last_seen) < timeout

    def close(self):
        self.running = False
        self.connected = False

        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
        except Exception:
            pass
