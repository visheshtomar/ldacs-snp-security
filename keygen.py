"""
keygen.py  --  Key generation for the LDACS SNP security prototype.

FIXES vs. the original:
  * Generates SEPARATE RSA-2048 keypairs for the Aircraft Station (AS) and the
    Ground Station (GS).  In the original, both parties loaded the SAME keypair,
    so "authentication" could not actually distinguish sender from receiver.
    Real entity authentication requires each station to hold its OWN private key
    and the PEER's public key.
  * The long-term AES key and the fixed IV files are REMOVED.  The session key is
    now derived per session from the Diffie-Hellman exchange (see dh.py), and a
    fresh random IV is generated for every packet (see encryption.py).  Storing a
    single fixed key+IV on disk was the root of the "same IV every packet" flaw.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(name: str) -> None:
    """Generate one RSA-2048 keypair and write <name>_private.pem / <name>_public.pem."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[keygen] RSA-2048 keypair for '{name}' written "
          f"({name}_private.pem, {name}_public.pem)")


def main() -> None:
    # Aircraft Station and Ground Station each get their own identity keypair.
    generate_rsa_keypair("aircraft")
    generate_rsa_keypair("ground")
    print("[keygen] Done. Session AES keys are derived per-session via Diffie-Hellman.")


if __name__ == "__main__":
    main()
