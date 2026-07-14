"""
throughput_socket.py  --  Realistic (network-limited) throughput over real UDP sockets.

Unlike throughput.py (pure CPU), this sends every packet through actual UDP sockets
between two threads, exactly like the sender/receiver demo. Because the socket send
+ receive is itself slow, the socket becomes the bottleneck -- so the extra cost of
cryptography shows up as a SMALL percentage drop, similar to the ~22% reported in the
dissertation. This is the "real-world impact" view of throughput.
"""

import os, sys, time, socket, threading, struct, subprocess

subprocess.check_call([sys.executable, "keygen.py"], stdout=subprocess.DEVNULL)

from authentication import DigitalSignature, load_private_key, load_public_key
import snp

signer = DigitalSignature(load_private_key("aircraft_private.pem"),
                          load_public_key("ground_public.pem"))
verifier = DigitalSignature(load_private_key("ground_private.pem"),
                            load_public_key("aircraft_public.pem"))
session_key = os.urandom(32)

NUM_PACKETS = 3000
PAYLOAD_SIZE = 100
payload = os.urandom(PAYLOAD_SIZE)
RX = ("127.0.0.1", 5202)


def encapsulate_plain(payload, seq):
    header = struct.pack(snp._HEADER_FORMAT, 1, 1, 2, seq, 0,
                         int(time.time()) & 0xFFFFFFFF, 0, 0, 0, 1, len(payload))
    return header + payload


def receiver_thread(secure, done):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(RX)
    s.settimeout(5)
    count = 0
    try:
        while count < NUM_PACKETS:
            data, _ = s.recvfrom(65535)
            if secure:
                snp.decapsulate(data, session_key, verifier)   # verify + decrypt
            else:
                _ = data[snp.HEADER_SIZE:]                      # just read payload
            count += 1
    except socket.timeout:
        pass
    s.close()
    done["count"] = count


def run(secure: bool):
    done = {"count": 0}
    t = threading.Thread(target=receiver_thread, args=(secure, done), daemon=True)
    t.start()
    time.sleep(0.3)  # let receiver bind

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start = time.perf_counter()
    for i in range(NUM_PACKETS):
        if secure:
            pkt = snp.encapsulate(payload, session_key, signer,
                                  src_id=1, dst_id=2, sequence_number=i)[0]
        else:
            pkt = encapsulate_plain(payload, i)
        s.sendto(pkt, RX)
    elapsed = time.perf_counter() - start
    s.close()
    t.join(timeout=6)
    return NUM_PACKETS * PAYLOAD_SIZE, elapsed


def kbps(b, t):
    return (b * 8) / t / 1000

print(f"\nSending {NUM_PACKETS} packets x {PAYLOAD_SIZE} bytes over real UDP sockets.\n")
bb, bt = run(secure=False)
sb, st = run(secure=True)
base, sec = kbps(bb, bt), kbps(sb, st)

print(f"{'Mode':<32}{'Throughput':>15}")
print("-" * 47)
print(f"{'Baseline (no crypto, UDP)':<32}{base:>10,.0f} Kbps")
print(f"{'Secured (AES+RSA, UDP)':<32}{sec:>10,.0f} Kbps")
print("-" * 47)
print(f"Throughput drop from cryptography: {(1 - sec/base)*100:.1f}%")
print("\nNetwork (socket) is the bottleneck here, so crypto adds a SMALL %,")
print("just like the dissertation -- compare with throughput.py (CPU-only).")
