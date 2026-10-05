#!/usr/bin/env python3
"""
secrets.py — Cross-Platform Secrets Engine for 'om'
Supports zero-dependency passphrase-protected encryption/decryption
and automatic SOPS / Age integration when binaries are present.
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import subprocess
from pathlib import Path

def has_sops() -> bool:
    """Check if sops binary is installed on the host."""
    try:
        res = subprocess.run(["sops", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

PBKDF2_ITERATIONS_V1 = 100000
PBKDF2_ITERATIONS_V2 = 600000

def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS_V1, length: int = 32) -> bytes:
    """Derive key material from passphrase using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=length)

def keystream_xor(key: bytes, data: bytes) -> bytes:
    """XOR data with a SHA256(key || counter) keystream (CTR-style; key must be unique per file via salt)."""
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(b ^ k for b, k in zip(data, stream))

def _v2_mac(mac_key: bytes, salt: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(mac_key, b"om-v2" + salt + ciphertext, hashlib.sha256).digest()

def encrypt_file(filepath: Path, output_path: Path, passphrase: str = None) -> bool:
    """Encrypt a file using SOPS if available, otherwise the native om-v2 vault (encrypt-then-MAC)."""
    if has_sops():
        try:
            res = subprocess.run(["sops", "-e", str(filepath)], capture_output=True, text=True, encoding="utf-8", check=True)
            output_path.write_text(res.stdout, encoding="utf-8", newline="\n")
            print(f"\033[32m✓ Encrypted with SOPS: {output_path.name}\033[0m")
            return True
        except Exception as e:
            print(f"SOPS encryption failed, falling back to native mode: {e}")

    if not passphrase:
        passphrase = os.environ.get("OM_SECRET_KEY")
    if not passphrase:
        print("\033[31mError: No passphrase provided and OM_SECRET_KEY not set.\033[0m")
        return False

    salt = os.urandom(16)
    material = derive_key(passphrase, salt, PBKDF2_ITERATIONS_V2, 64)
    enc_key, mac_key = material[:32], material[32:]
    ciphertext = keystream_xor(enc_key, filepath.read_bytes())
    envelope = {
        "version": "om-v2",
        "salt": base64.b64encode(salt).decode("ascii"),
        "payload": base64.b64encode(ciphertext).decode("ascii"),
        "mac": base64.b64encode(_v2_mac(mac_key, salt, ciphertext)).decode("ascii"),
    }
    output_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8", newline="\n")
    print(f"\033[32m✓ Encrypted with native vault: {output_path.name}\033[0m")
    return True

def decrypt_file(filepath: Path, passphrase: str = None) -> bytes:
    """Decrypt a file into memory. Raises ValueError on a wrong passphrase or tampered file (om-v2)."""
    if has_sops():
        try:
            res = subprocess.run(["sops", "-d", str(filepath)], capture_output=True, check=True)
            return res.stdout
        except Exception:
            pass

    if not passphrase:
        passphrase = os.environ.get("OM_SECRET_KEY")
    if not passphrase:
        raise ValueError("Passphrase required to decrypt.")

    envelope = json.loads(filepath.read_text(encoding="utf-8"))
    salt = base64.b64decode(envelope["salt"])
    ciphertext = base64.b64decode(envelope["payload"])
    version = envelope.get("version")

    if version == "om-v2":
        material = derive_key(passphrase, salt, PBKDF2_ITERATIONS_V2, 64)
        enc_key, mac_key = material[:32], material[32:]
        expected = base64.b64decode(envelope.get("mac", ""))
        if not hmac.compare_digest(_v2_mac(mac_key, salt, ciphertext), expected):
            raise ValueError("Integrity check failed: wrong passphrase or tampered file.")
        return keystream_xor(enc_key, ciphertext)

    if version == "om-v1":
        # Legacy format: unauthenticated and 4-byte counter; re-encrypt to upgrade.
        print("\033[33mWarning: om-v1 secret has no integrity check; re-encrypt it to upgrade to om-v2.\033[0m", file=sys.stderr)
        key = derive_key(passphrase, salt)
        stream = bytearray()
        counter = 0
        while len(stream) < len(ciphertext):
            stream += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
            counter += 1
        return bytes(b ^ k for b, k in zip(ciphertext, stream))

    raise ValueError(f"Unsupported secret format: {version!r}")
