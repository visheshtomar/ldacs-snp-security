"""
benchmark.py  --  Measure the REAL cryptographic overhead of the fixed SNP layer.

The numbers in the original paper were produced by the broken implementation
(fixed IV, hard-coded offsets, signature computed over the wrong bytes). These are
therefore NOT valid for the corrected code. Run this to obtain fresh, honest
measurements you can cite in a future paper. Figures depend on the host CPU.

It reports, per operation and averaged over many iterations:
  * AES-256 encrypt / decrypt time vs. payload size,
  * RSA-2048 sign / verify time vs. payload size,
  * full encapsulate / decapsulate time.
"""

import subprocess
import sys
import timeit

subprocess.check_call([sys.executable, "keygen.py"])

from authentication import DigitalSignature, load_private_key, load_public_key
from encryption import encrypt, decrypt
import dh
import snp
import os

as_priv = load_private_key("aircraft_private.pem")
gs_pub = load_public_key("ground_public.pem")
gs_priv = load_private_key("ground_private.pem")
as_pub = load_public_key("aircraft_public.pem")
signer = DigitalSignature(signing_key=as_priv, peer_public_key=gs_pub)
verifier = DigitalSignature(signing_key=gs_priv, peer_public_key=as_pub)

key = dh.derive_aes_key(dh.compute_shared_secret(*(lambda a, b: (b[1], a[0]))(
    dh.generate_keypair(), dh.generate_keypair())))
key = os.urandom(32)  # simplest: a random 256-bit session key for timing

N = 2000
sizes = [64, 512, 1024, 1500]

def ms(fn, number):
    return timeit.timeit(fn, number=number) / number * 1000.0

print(f"\nAveraged over {N} iterations. Host: {os.cpu_count()} CPU(s).\n")

print("AES-256 (CBC, fresh IV per call)")
print(f"{'payload':>8} {'encrypt(ms)':>12} {'decrypt(ms)':>12}")
for s in sizes:
    data = os.urandom(s)
    iv, ct = encrypt(data, key)
    enc = ms(lambda: encrypt(data, key), N)
    dec = ms(lambda: decrypt(ct, iv, key), N)
    print(f"{s:>8} {enc:>12.4f} {dec:>12.4f}")

print("\nRSA-2048 / PSS / SHA-256")
print(f"{'payload':>8} {'sign(ms)':>12} {'verify(ms)':>12}")
for s in sizes:
    data = os.urandom(s)
    sig = signer.sign(data)
    sgn = ms(lambda: signer.sign(data), N // 2)
    ver = ms(lambda: verifier.verify(data, sig), N // 2)
    print(f"{s:>8} {sgn:>12.4f} {ver:>12.4f}")

print("\nFull SNP encapsulate / decapsulate (single packet)")
print(f"{'payload':>8} {'encap(ms)':>12} {'decap(ms)':>12}")
for s in sizes:
    data = os.urandom(s)
    pkt = snp.encapsulate(data, key, signer, src_id=1, dst_id=2, sequence_number=1)[0]
    enc = ms(lambda: snp.encapsulate(data, key, signer, src_id=1, dst_id=2, sequence_number=1), N // 2)
    dec = ms(lambda: snp.decapsulate(pkt, key, verifier), N // 2)
    print(f"{s:>8} {enc:>12.4f} {dec:>12.4f}")

print("\nNote: RSA signing dominates per-packet cost, as expected.")
