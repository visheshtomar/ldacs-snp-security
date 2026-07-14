# LDACS SNP Security Prototype — Corrected & Verified

A working, tested implementation of classical cryptographic protection (AES-256 +
RSA-2048 + Diffie–Hellman) for the LDACS Sub-Network Protocol (SNP) layer.

This is a corrected rewrite of the original MSc dissertation prototype. Every file
has been fixed so that **what the code does matches what the paper claims**, and the
whole thing is verified end-to-end by an automated test suite.

---

## Quick start

```bash
python keygen.py          # generate aircraft + ground RSA identity keys
python test_protocol.py   # run all correctness + attack tests (should print 11/11)
python benchmark.py       # measure real crypto overhead on your machine
```

To run the live two-terminal demo:

```bash
# terminal 1
python receiver.py
# terminal 2
python sender.py
```

Requires: Python 3.10+ and the `cryptography` package (`pip install cryptography`).

---

## What was wrong, and what was fixed

| # | Original problem | Fix |
|---|------------------|-----|
| 1 | SNP header declared a **16-byte** signature field, but RSA-2048 signatures are **256 bytes**; Scapy silently truncated it and the real signature was concatenated outside the header. | Dropped Scapy; explicit fixed-layout wire format with a correctly sized 256-byte signature (`snp.py`). |
| 2 | Signature was computed over a re-serialised **header**, not the ciphertext. | Clean **encrypt-then-sign**: the signature covers exactly the bytes on the wire (`header‖IV‖ciphertext`). |
| 3 | Decryption used **hard-coded byte offsets** (`signed_data[21:53]`) and only worked for one test message. | Header carries an explicit `ciphertext_length`; parsing is fully length-driven. |
| 4 | Fragmentation was **dead code** (nested inside an early `return`) and never executed. | Fragmentation implemented and tested; large payloads split, each fragment independently encrypted+signed, and `reassemble()` recombines them. |
| 5 | A **single fixed IV** was loaded from disk and reused for every packet (a real CBC weakness). | Fresh cryptographically-random IV per packet (`encryption.py`), carried in the header. |
| 6 | "Diffie–Hellman" used `p=23, g=5` (a 5-bit toy prime) and its output was **never used** — the AES key came from a file, so there was no real key agreement and no forward secrecy. | Real DH over the **RFC 3526 2048-bit group**, actual exchange of public values, shared secret run through **HKDF-SHA256**; ephemeral keys give genuine forward secrecy (`dh.py`, `handshake.py`). |
| 7 | Both parties loaded the **same** RSA keypair, so authentication could not distinguish sender from receiver. | Separate identity keypairs for aircraft and ground; each signs with its own key and verifies with the peer's (`keygen.py`, `authentication.py`). |

---

## Files

| File | Role |
|------|------|
| `keygen.py` | Generates aircraft + ground RSA-2048 identity keypairs. |
| `dh.py` | Real Diffie–Hellman (RFC 3526 group 14) + HKDF key derivation. |
| `encryption.py` | AES-256-CBC with a fresh random IV per packet. |
| `authentication.py` | RSA-2048 / PSS / SHA-256 signatures, separate sign/verify keys. |
| `snp.py` | SNP encapsulate / decapsulate / reassemble (the core protocol). |
| `handshake.py` | Authenticated DH handshake used by the socket demo. |
| `sender.py` / `receiver.py` | Live two-terminal UDP demo (aircraft / ground). |
| `test_protocol.py` | Automated correctness + attack test suite (11 checks). |
| `benchmark.py` | Measures real AES / RSA / full-packet overhead. |

---

## What the tests prove

`test_protocol.py` confirms:

- **DH handshake** — both sides derive the identical 256-bit session key.
- **Round-trip** — a message is encrypted, signed, verified, and decrypted correctly.
- **MITM confidentiality** — the plaintext never appears in the transmitted bytes, and an attacker with the wrong key cannot decrypt.
- **Message injection** — flipping one ciphertext byte is caught at signature verification.
- **Impersonation** — a packet signed by an attacker's key (not the aircraft's) is rejected.
- **Fragmentation** — a 5 KB payload is split into 5 fragments and losslessly reassembled.

---

## Honest notes for a future paper

- **The dissertation's performance numbers are no longer valid**, because they came
  from the broken implementation (fixed IV, wrong signed bytes, hard-coded offsets).
  Re-run `benchmark.py` and report those figures instead. Absolute timings differ
  from the dissertation because this build uses OpenSSL via `cryptography`; the
  qualitative finding — *RSA signing dominates the per-packet cost* — still holds.
- The emulation is still **software on general-purpose hardware over UDP**; absolute
  throughput/latency are not predictive of a deployed LDACS radio link. Report
  **relative** overhead.
- **Natural next step (and your PhD topic):** swap RSA/DH for the NIST PQC standards
  **ML-KEM (FIPS 203)** and **ML-DSA (FIPS 204)** using `liboqs`/`oqs-python`, and
  re-run the same tests and benchmark. Because an ML-DSA-65 signature is ~3.3 KB vs.
  256 bytes for RSA-2048, the packet-size and throughput impact on LDACS's
  constrained channel is exactly the open, quotable question worth publishing.
