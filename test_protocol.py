"""
test_protocol.py  --  End-to-end verification of the fixed LDACS SNP security layer.

Run this to PROVE the implementation is correct. It exercises:
  * a real Diffie-Hellman handshake (both sides derive the same key),
  * a normal encrypt -> sign -> transmit -> verify -> decrypt round-trip,
  * MITM confidentiality (ciphertext reveals nothing without the key),
  * message-injection integrity (a tampered packet is rejected),
  * impersonation (a packet signed by the wrong key is rejected),
  * fragmentation + reassembly of a large payload.

Every check prints PASS/FAIL and the script asserts on failure.
"""

import subprocess
import sys

subprocess.check_call([sys.executable, "keygen.py"])

from authentication import DigitalSignature, load_private_key, load_public_key
from encryption import decrypt
import dh
import snp

RESULTS = []

def check(name, condition):
    RESULTS.append(condition)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}")


# Load the two stations' identity keys.
as_priv = load_private_key("aircraft_private.pem")
as_pub = load_public_key("aircraft_public.pem")
gs_priv = load_private_key("ground_private.pem")
gs_pub = load_public_key("ground_public.pem")

# Aircraft signs with its own key and verifies the ground's; ground does the mirror.
aircraft_signer = DigitalSignature(signing_key=as_priv, peer_public_key=gs_pub)
ground_verifier = DigitalSignature(signing_key=gs_priv, peer_public_key=as_pub)

print("\n== 1. Diffie-Hellman session-key agreement ==")
as_dh_priv, as_dh_pub = dh.generate_keypair()
gs_dh_priv, gs_dh_pub = dh.generate_keypair()
# In the real protocol these public values are exchanged over the signed channel.
key_aircraft = dh.derive_aes_key(dh.compute_shared_secret(gs_dh_pub, as_dh_priv))
key_ground = dh.derive_aes_key(dh.compute_shared_secret(as_dh_pub, gs_dh_priv))
check("both sides derive identical 256-bit session key", key_aircraft == key_ground)
check("session key is 32 bytes (AES-256)", len(key_aircraft) == 32)
session_key = key_aircraft

print("\n== 2. Normal secure round-trip ==")
msg = b"Ready for takeoff"
packets = snp.encapsulate(msg, session_key, aircraft_signer,
                          src_id=1, dst_id=2, sequence_number=1)
check("short message produces exactly one packet", len(packets) == 1)
payload, header = snp.decapsulate(packets[0], session_key, ground_verifier)
check("decrypted payload matches original", payload == msg)
check("header parsed (src=1, dst=2)", header["src_id"] == 1 and header["dst_id"] == 2)

print("\n== 3. MITM confidentiality ==")
# An on-path attacker sees only the raw packet bytes.
wire = packets[0]
check("plaintext does NOT appear in transmitted bytes", msg not in wire)
# Without the session key the attacker cannot decrypt.
attacker_key = b"\x00" * 32
leaked = None
try:
    # Try to decrypt the ciphertext region with a wrong key.
    ct = wire[snp.SIGNATURE_SIZE + snp.HEADER_SIZE + snp.IV_SIZE:]
    iv = wire[snp.SIGNATURE_SIZE + snp.HEADER_SIZE: snp.SIGNATURE_SIZE + snp.HEADER_SIZE + snp.IV_SIZE]
    leaked = decrypt(ct, iv, attacker_key)
except Exception:
    leaked = None
check("attacker with wrong key cannot recover plaintext", leaked != msg)

print("\n== 4. Message injection (integrity) ==")
# Attacker flips a byte in the ciphertext and forwards it.
tampered = bytearray(packets[0])
tampered[-1] ^= 0x01
rejected = False
try:
    snp.decapsulate(bytes(tampered), session_key, ground_verifier)
except snp.SignatureError:
    rejected = True
check("tampered packet rejected at signature verification", rejected)

print("\n== 5. Impersonation ==")
# Attacker (holding neither station's private key) forges a keypair and signs.
from cryptography.hazmat.primitives.asymmetric import rsa
attacker_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
attacker_signer = DigitalSignature(signing_key=attacker_priv,
                                   peer_public_key=gs_pub)  # peer irrelevant here
forged = snp.encapsulate(b"Descend to 100ft", session_key, attacker_signer,
                         src_id=1, dst_id=2, sequence_number=2)[0]
rejected = False
try:
    snp.decapsulate(forged, session_key, ground_verifier)  # verifies against AS public key
except snp.SignatureError:
    rejected = True
check("packet signed by unknown key rejected", rejected)

print("\n== 6. Fragmentation + reassembly ==")
big = bytes(range(256)) * 20          # 5120 bytes, exceeds max_fragment_size=1024
frag_packets = snp.encapsulate(big, session_key, aircraft_signer,
                               src_id=1, dst_id=2, sequence_number=3,
                               max_fragment_size=1024)
check("large payload split into multiple fragments", len(frag_packets) == 5)
recovered = [snp.decapsulate(p, session_key, ground_verifier) for p in frag_packets]
reassembled = snp.reassemble(recovered)
check("reassembled payload equals original", reassembled == big)

print("\n== SUMMARY ==")
passed, total = sum(RESULTS), len(RESULTS)
print(f"  {passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
