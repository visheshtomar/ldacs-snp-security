"""
authentication.py  --  RSA-2048 digital signatures (PSS padding, SHA-256).

The cryptography here was already correct in the original -- RSA-2048 + SHA-256 +
PSS is a sound, existentially-unforgeable signature scheme. The change is
structural:

  * The class now takes a SIGNING private key and a PEER public key separately,
    instead of one keypair used for both roles. This makes real entity
    authentication possible: the Aircraft Station signs with ITS private key, and
    the Ground Station verifies with the AIRCRAFT'S public key (and vice versa).
    A packet forged by an attacker who lacks the aircraft's private key will fail
    verification.

  * Signatures are produced over the CIPHERTEXT (encrypt-then-sign), not over a
    whole re-serialised header. That change lives in snp.py, which calls this
    module.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import cryptography.exceptions

# RSA-2048 signature size in bytes (modulus size). Used by snp.py to split the
# fixed-length signature off the front of a received packet.
SIGNATURE_SIZE = 256

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


class DigitalSignature:
    """
    Signs with `signing_key` (this station's private key) and verifies with
    `peer_public_key` (the other station's public key).
    """

    def __init__(self, signing_key, peer_public_key):
        if not isinstance(signing_key, rsa.RSAPrivateKey):
            raise ValueError("signing_key must be an RSA private key")
        if not isinstance(peer_public_key, rsa.RSAPublicKey):
            raise ValueError("peer_public_key must be an RSA public key")
        self.signing_key = signing_key
        self.peer_public_key = peer_public_key

    def sign(self, data: bytes) -> bytes:
        """Return the RSA-2048/PSS signature of `data` (256 bytes)."""
        return self.signing_key.sign(data, _PSS, hashes.SHA256())

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return True iff `signature` is a valid signature over `data` by the peer."""
        try:
            self.peer_public_key.verify(signature, data, _PSS, hashes.SHA256())
            return True
        except cryptography.exceptions.InvalidSignature:
            return False


if __name__ == "__main__":
    # Self-test: a signature from key A verifies under A's public key, and a
    # tampered message fails.
    a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ds = DigitalSignature(signing_key=a, peer_public_key=a.public_key())
    sig = ds.sign(b"altitude=10000")
    print("[auth] signature length:", len(sig), "bytes")
    print("[auth] valid signature verifies :", ds.verify(b"altitude=10000", sig))
    print("[auth] tampered message rejected:", not ds.verify(b"altitude=99999", sig))
    assert len(sig) == SIGNATURE_SIZE
    assert ds.verify(b"altitude=10000", sig)
    assert not ds.verify(b"altitude=99999", sig)
    print("[auth] OK -- RSA-2048/PSS sign & verify correct")
