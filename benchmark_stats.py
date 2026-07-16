"""
benchmark_stats.py  --  STATISTICALLY RIGOROUS benchmarking (classical LDACS).

The original benchmark.py ran each measurement ONCE per payload size. A single run
can be skewed by a background process, CPU frequency scaling, or garbage collection
happening to fire at that moment. This script instead runs each measurement many
times and reports the MEAN and STANDARD DEVIATION, which is what a reader needs to
judge whether a difference between two numbers is real or just noise.

Library choices (see README section "Why these libraries" for the full explanation):
  - `statistics` (Python standard library) for mean/stdev -- no numpy needed for this.
  - `time.perf_counter` for timing -- the standard high-resolution monotonic clock.
"""

import os
import statistics
import time

from authentication import DigitalSignature, load_private_key, load_public_key
from encryption import encrypt, decrypt
import dh

N_RUNS = 200            # independent repetitions per measurement
PAYLOAD_SIZES = [64, 512, 1024, 1500]


def timed_runs(fn, n=N_RUNS):
    """Run fn() n times, return (mean_ms, stdev_ms, min_ms, max_ms)."""
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return (statistics.mean(samples), statistics.stdev(samples),
            min(samples), max(samples))


def main():
    import subprocess, sys
    subprocess.check_call([sys.executable, "keygen.py"], stdout=subprocess.DEVNULL)

    signer = DigitalSignature(load_private_key("aircraft_private.pem"),
                              load_public_key("ground_public.pem"))
    verifier = DigitalSignature(load_private_key("ground_private.pem"),
                                load_public_key("aircraft_public.pem"))

    # DH handshake timing (one full ephemeral exchange, both sides).
    def dh_full_exchange():
        a_priv, a_pub = dh.generate_keypair()
        b_priv, b_pub = dh.generate_keypair()
        ka = dh.derive_aes_key(dh.compute_shared_secret(b_pub, a_priv))

    key = os.urandom(32)

    print(f"Each figure is mean +/- stdev over {N_RUNS} independent runs.\n")

    print("Diffie-Hellman (full ephemeral exchange, one side's cost)")
    m, s, lo, hi = timed_runs(dh_full_exchange, n=50)  # DH keygen is slower; fewer runs
    print(f"  {m:7.3f} +/- {s:.3f} ms   (min {lo:.3f}, max {hi:.3f})\n")

    print(f"{'':>8}{'AES-256 encrypt (ms)':>26}{'AES-256 decrypt (ms)':>26}")
    for size in PAYLOAD_SIZES:
        data = os.urandom(size)
        m_e, s_e, *_ = timed_runs(lambda: encrypt(data, key))
        iv, ct = encrypt(data, key)
        m_d, s_d, *_ = timed_runs(lambda: decrypt(ct, iv, key))
        print(f"{size:>8}{m_e:>18.4f} +/- {s_e:<6.4f}{m_d:>18.4f} +/- {s_d:<6.4f}")

    print(f"\n{'':>8}{'RSA-2048 sign (ms)':>26}{'RSA-2048 verify (ms)':>26}")
    for size in PAYLOAD_SIZES:
        data = os.urandom(size)
        m_sg, s_sg, *_ = timed_runs(lambda: signer.sign(data))
        sig = signer.sign(data)
        m_vf, s_vf, *_ = timed_runs(lambda: verifier.verify(data, sig))
        print(f"{size:>8}{m_sg:>18.4f} +/- {s_sg:<6.4f}{m_vf:>18.4f} +/- {s_vf:<6.4f}")

    print("\nNote: report mean +/- stdev, not single-run figures, in any write-up.")


if __name__ == "__main__":
    main()
