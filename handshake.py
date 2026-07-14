"""
handshake.py  --  Authenticated Diffie-Hellman handshake over UDP.

Establishes a fresh, forward-secret AES-256 session key between two stations while
authenticating each side with its long-term RSA identity key. This is what ties the
DH exchange to a verified identity and defeats an active man-in-the-middle: an
attacker cannot substitute its own DH public value because it cannot forge the RSA
signature over it.

Message on the wire (both directions):
    dh_public (256 B) || rsa_signature (256 B)
"""

import dh
from authentication import SIGNATURE_SIZE

_DH_BYTES = 256   # a 2048-bit group element


def initiator_handshake(sock, peer_addr, signer) -> bytes:
    """
    Run the handshake as the INITIATOR (e.g. the aircraft).
    `signer` verifies with the peer's public key and signs with our own.
    Returns the derived 32-byte session key.
    """
    my_priv, my_pub = dh.generate_keypair()
    my_pub_bytes = dh.public_to_bytes(my_pub)
    sock.sendto(my_pub_bytes + signer.sign(my_pub_bytes), peer_addr)

    data, _ = sock.recvfrom(4096)
    peer_pub_bytes, peer_sig = data[:_DH_BYTES], data[_DH_BYTES:_DH_BYTES + SIGNATURE_SIZE]
    if not signer.verify(peer_pub_bytes, peer_sig):
        raise ValueError("Handshake failed: peer DH value has an invalid signature")

    shared = dh.compute_shared_secret(dh.public_from_bytes(peer_pub_bytes), my_priv)
    return dh.derive_aes_key(shared)


def responder_handshake(sock, signer) -> tuple[bytes, tuple]:
    """
    Run the handshake as the RESPONDER (e.g. the ground station).
    Returns (session_key, peer_addr).
    """
    data, peer_addr = sock.recvfrom(4096)
    peer_pub_bytes, peer_sig = data[:_DH_BYTES], data[_DH_BYTES:_DH_BYTES + SIGNATURE_SIZE]
    if not signer.verify(peer_pub_bytes, peer_sig):
        raise ValueError("Handshake failed: peer DH value has an invalid signature")

    my_priv, my_pub = dh.generate_keypair()
    my_pub_bytes = dh.public_to_bytes(my_pub)
    sock.sendto(my_pub_bytes + signer.sign(my_pub_bytes), peer_addr)

    shared = dh.compute_shared_secret(dh.public_from_bytes(peer_pub_bytes), my_priv)
    return dh.derive_aes_key(shared), peer_addr
