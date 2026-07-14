"""
encryption.py  --  AES-256-CBC payload encryption for the LDACS SNP layer.

FIXES vs. the original:
  * The original loaded ONE fixed IV from a file and reused it for every packet.
    Reusing an IV under CBC with the same key leaks information (identical
    plaintext prefixes produce identical ciphertext prefixes) and directly
    contradicted the paper's claim of a "per-packet random IV". Here, encrypt()
    generates a FRESH cryptographically random 16-byte IV for every call and
    returns it alongside the ciphertext, so it can be carried in the packet header.
  * encrypt() no longer depends on a module-level key/IV loaded from disk; the key
    is passed in explicitly (it comes from the DH session key -- see dh.py).
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

_BLOCK = algorithms.AES.block_size // 8   # 16 bytes


def encrypt(payload: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt `payload` with AES-256-CBC.

    A fresh random IV is generated per call. Returns (iv, ciphertext).
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")

    iv = os.urandom(_BLOCK)                       # fresh IV every packet
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(payload) + padder.finalize()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC `ciphertext` using the supplied `iv` and `key`."""
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
    if len(iv) != _BLOCK:
        raise ValueError(f"Invalid IV length {len(iv)}, must be {_BLOCK} bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


if __name__ == "__main__":
    key = os.urandom(32)
    iv1, ct1 = encrypt(b"Ready for takeoff", key)
    iv2, ct2 = encrypt(b"Ready for takeoff", key)
    print("[enc] same plaintext, two packets -> different IVs:", iv1 != iv2)
    print("[enc] same plaintext, two packets -> different ct :", ct1 != ct2)
    assert iv1 != iv2 and ct1 != ct2, "IV reuse detected!"
    pt = decrypt(ct1, iv1, key)
    print("[enc] round-trip:", pt)
    assert pt == b"Ready for takeoff"
    print("[enc] OK -- per-packet random IV, round-trip correct")
