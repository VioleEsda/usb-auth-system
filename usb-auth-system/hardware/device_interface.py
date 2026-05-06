class DeviceInterface:
    def connect(self) -> bool:
        raise NotImplementedError

    def is_connected(self) -> bool:
        raise NotImplementedError

    def verify_fingerprint(self) -> bool:
        raise NotImplementedError

    def sign_challenge(self, challenge: bytes) -> bytes:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError