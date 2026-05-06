from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent / "keys"
KEYS_DIR.mkdir(exist_ok=True)

priv = x25519.X25519PrivateKey.generate()
pub = priv.public_key()

(KEYS_DIR / "esp_x25519_private.bin").write_bytes(priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
))

(KEYS_DIR / "esp_x25519_public.bin").write_bytes(pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
))

print("X25519 keypair generated")
