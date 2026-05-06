from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent / "keys"
KEYS_DIR.mkdir(exist_ok=True)

# generate key
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# save private key (untuk ESP nanti)
(KEYS_DIR / "esp_ed25519_private.bin").write_bytes(private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
))

# save public key (untuk Python)
(KEYS_DIR / "esp_ed25519_public.bin").write_bytes(public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
))

print("Keys generated!")
