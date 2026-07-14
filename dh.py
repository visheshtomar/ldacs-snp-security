"""
dh.py  --  REAL Diffie-Hellman key agreement for LDACS session-key establishment.

FIXES vs. the original:
  * The original used p = 23, g = 5 -- a 5-bit toy prime with NO security. It also
    never used the resulting public key for anything: the AES key was loaded from a
    file, so the "DH exchange" was purely decorative. Forward secrecy was claimed
    but not implemented.
  * This module uses the standardised 2048-bit MODP group from RFC 3526 (Group 14),
    performs an actual exchange of public values, computes the shared secret
    g^(ab) mod p on both sides, and derives a 256-bit AES key from it with
    HKDF-SHA256. Because each session uses fresh EPHEMERAL private exponents, this
    provides genuine forward secrecy: compromising one session's keys does not
    expose past or future sessions.

Typical use (two parties):
    a_priv, a_pub = generate_keypair()          # aircraft
    g_priv, g_pub = generate_keypair()          # ground
    # ... exchange a_pub and g_pub over the (authenticated) channel ...
    shared_a = compute_shared_secret(g_pub, a_priv)
    shared_g = compute_shared_secret(a_pub, g_priv)
    assert shared_a == shared_g                  # same secret on both sides
    aes_key = derive_aes_key(shared_a)           # 32 bytes
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 3526, Group 14: a 2048-bit safe prime with generator g = 2.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)   # the shared prime modulus
G = 2                 # the shared generator

# Number of bytes needed to encode an element of the group (2048 bits = 256 bytes).
_ELEMENT_BYTES = (P.bit_length() + 7) // 8


def generate_keypair() -> tuple[int, int]:
    """
    Generate an EPHEMERAL DH keypair.

    Returns (private_exponent, public_value) where
        public_value = G^private mod P.
    A fresh private exponent per session is what gives forward secrecy.
    """
    # 256-bit private exponent is more than enough for a 2048-bit group and keeps
    # the exponentiation fast. Must be in [2, P-2].
    private_key = int.from_bytes(os.urandom(32), "big") % (P - 2) + 2
    public_key = pow(G, private_key, P)
    return private_key, public_key


def compute_shared_secret(their_public: int, my_private: int) -> bytes:
    """
    Compute the shared secret their_public^my_private mod P and return it as a
    fixed-length big-endian byte string, ready to feed into a KDF.
    """
    if not (2 <= their_public <= P - 2):
        raise ValueError("Invalid peer public value")
    shared_int = pow(their_public, my_private, P)
    return shared_int.to_bytes(_ELEMENT_BYTES, "big")


def derive_aes_key(shared_secret: bytes, info: bytes = b"LDACS-SNP-AES-256") -> bytes:
    """
    Derive a 256-bit AES key from the raw DH shared secret using HKDF-SHA256.

    Using a KDF (rather than the raw shared secret) is important: the raw DH
    output is not uniformly random and must not be used directly as a key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,               # 256-bit AES key
        salt=None,
        info=info,
    ).derive(shared_secret)


def public_to_bytes(public_value: int) -> bytes:
    """Serialise a DH public value to fixed-length bytes for transmission."""
    return public_value.to_bytes(_ELEMENT_BYTES, "big")


def public_from_bytes(data: bytes) -> int:
    """Parse a DH public value received from the wire."""
    return int.from_bytes(data, "big")


if __name__ == "__main__":
    # Self-test: two parties must derive an identical key.
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    ka = derive_aes_key(compute_shared_secret(b_pub, a_priv))
    kb = derive_aes_key(compute_shared_secret(a_pub, b_priv))
    print("[dh] prime size :", P.bit_length(), "bits")
    print("[dh] key A      :", ka.hex())
    print("[dh] key B      :", kb.hex())
    print("[dh] keys match :", ka == kb)
    assert ka == kb, "DH key agreement FAILED"
    print("[dh] OK -- both parties derived the same 256-bit AES key")
