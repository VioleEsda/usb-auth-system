from pathlib import Path


def print_c_array(filename, varname):
    path = Path(filename)
    data = path.read_bytes()

    print(f"// {path.as_posix()} ({len(data)} bytes)")
    print(f"uint8_t {varname}[{len(data)}] = {{")

    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        line = ", ".join(f"0x{b:02X}" for b in chunk)
        print(f"  {line},")

    print("};\n")


KEYS_DIR = Path(__file__).resolve().parent / "keys"

print_c_array(KEYS_DIR / "esp_ed25519_private.bin", "ed25519PrivateKey")
print_c_array(KEYS_DIR / "esp_x25519_private.bin", "x25519PrivateKey")
