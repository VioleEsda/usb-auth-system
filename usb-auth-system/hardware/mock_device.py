from hardware.device_interface import DeviceInterface


class MockDevice(DeviceInterface):
    def __init__(self):
        self.connected = False

    def connect(self) -> bool:
        self.connected = True
        return True

    def is_connected(self) -> bool:
        return self.connected

    def verify_fingerprint(self) -> bool:
        return True

    def sign_challenge(self, challenge: bytes) -> bytes:
        return b"mock_signature_" + challenge[:8]

    def close(self):
        self.connected = False