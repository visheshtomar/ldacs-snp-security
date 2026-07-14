"""
throughput.py  --  Measure SNP-layer THROUGHPUT: with vs. without cryptography.

Throughput = how many bits/second we can push through the SNP layer.
    throughput (Kbps) = (total_bytes * 8) / elapsed_seconds / 1000

We compare a FAIR baseline (build the same packet, but skip encrypt+sign) against
the fully secured pipeline (encrypt + sign + verify + decrypt). The difference is
the cost of the cryptography itself.
"""

import os, sys, time, struct, subprocess

subprocess.check_call([sys.executable, "keygen.py"], stdout=subprocess.DEVNULL)

from authentication import DigitalSignature, load_private_key, load_public_key
import snp

signer = DigitalSignature(load_private_key("aircraft_private.pem"),
                          load_public_key("ground_public.pem"))
verifier = DigitalSignature(load_private_key("ground_private.pem"),
                            load_public_key("aircraft_public.pem"))
session_key = os.urandom(32)

NUM_PACKETS = 5000
PAYLOAD_SIZE = 100
payload = os.urandom(PAYLOAD_SIZE)


def encapsulate_plain(payload, *, src_id, dst_id, sequence_number):
    """Same SNP framing as the real encapsulate(), but WITHOUT encrypt/sign."""
    header = struct.pack(snp._HEADER_FORMAT, 1, src_id, dst_id, sequence_number,
                         0, int(time.time()) & 0xFFFFFFFF, 0, 0, 0, 1, len(payload))
    return header + payload            # no IV, no ciphertext, no signature


def run(secure: bool):
    total = 0
    start = time.perf_counter()
    for i in range(NUM_PACKETS):
        if secure:
            pkt = snp.encapsulate(payload, session_key, signer,
                                  src_id=1, dst_id=2, sequence_number=i)[0]
            snp.decapsulate(pkt, session_key, verifier)     # full round-trip
        else:
            pkt = encapsulate_plain(payload, src_id=1, dst_id=2, sequence_number=i)
            _ = pkt[snp.HEADER_SIZE:]                        # 'parse' the payload
        total += len(payload)
    return total, time.perf_counter() - start


def kbps(b, t):
    return (b * 8) / t / 1000

print(f"\nPushing {NUM_PACKETS} packets x {PAYLOAD_SIZE} bytes.\n")
bb, bt = run(secure=False)
sb, st = run(secure=True)
base, sec = kbps(bb, bt), kbps(sb, st)

print(f"{'Mode':<30}{'Throughput':>16}")
print("-" * 46)
print(f"{'Baseline (framing only)':<30}{base:>11,.0f} Kbps")
print(f"{'Secured (AES-256 + RSA-2048)':<30}{sec:>11,.0f} Kbps")
print("-" * 46)
print(f"Throughput drop from cryptography: {(1 - sec/base)*100:.1f}%")
print(f"\nPackets/sec secured: {NUM_PACKETS/st:,.0f}   (i.e. {st/NUM_PACKETS*1000:.3f} ms/packet)")
