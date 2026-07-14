r"""
snp.py  --  LDACS Sub-Network Protocol (SNP) secure encapsulation.

This is a full rewrite of the original SNP layer. The original had five distinct
problems; each is fixed here:

  1. Signature field was declared as 16 bytes in the Scapy header, but an RSA-2048
     signature is 256 bytes. Scapy silently truncated it, and the real signature
     was concatenated OUTSIDE the header. => We drop Scapy and use an explicit,
     fixed-layout wire format with a correctly sized 256-byte signature.

  2. The signature was computed over a re-serialised header, not the ciphertext.
     => We now sign the exact bytes that travel on the wire (header + IV +
     ciphertext): a clean encrypt-then-sign construction.

  3. Decryption used hard-coded byte offsets (`signed_data[21:53]`), so it only
     worked for one specific test message. => The header carries an explicit
     ciphertext-length field, and parsing is fully length-driven.

  4. Fragmentation was dead code (nested inside an early `return`), so the paper's
     "fragmentation support" never executed. => Fragmentation is implemented and
     tested: payloads larger than `max_fragment_size` are split, each fragment is
     independently encrypted+signed, and `reassemble()` puts them back together.

  5. A fixed IV was reused for every packet. => Fixed in encryption.py; each
     fragment here gets its own fresh IV, carried in the header region.

WIRE FORMAT (per packet):

    +-------------------+------------------+---------+------------------------+
    | signature (256 B) | header (26 B)    | IV(16 B)| ciphertext (variable)  |
    +-------------------+------------------+---------+------------------------+
    \___ RSA-2048/PSS __/\____________ signed region (header|IV|ciphertext) __/

The signature is verified BEFORE decryption, so forged or modified ciphertext is
rejected without ever entering the decryption path.
"""

import struct
import time

from encryption import encrypt, decrypt
from authentication import SIGNATURE_SIZE

# Fixed-layout header. All integers big-endian.
#   B  type              (1) : 1 = data
#   H  src_id            (2)
#   H  dst_id            (2)
#   H  sequence_number   (2)
#   B  priority          (1)
#   I  timestamp         (4)
#   B  flags             (1)
#   B  fragmented        (1) : 1 if this packet is part of a fragmented message
#   I  fragment_index    (4) : which fragment this is (0-based)
#   I  fragment_total    (4) : total number of fragments in the message
#   I  ciphertext_length (4) : length of the ciphertext that follows the IV
_HEADER_FORMAT = "!BHHHBIBBIII"
HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)   # 26 bytes
IV_SIZE = 16


class SignatureError(Exception):
    """Raised when a received packet fails RSA signature verification."""


def encapsulate(payload: bytes, session_key: bytes, signer, *,
                src_id: int, dst_id: int, sequence_number: int,
                priority: int = 0, flags: int = 0,
                max_fragment_size: int = 1024) -> list[bytes]:
    """
    Encrypt, sign, and encapsulate `payload` into one or more SNP packets.

    Returns a LIST of packet byte-strings. For a payload that fits in a single
    fragment the list has one element; larger payloads are fragmented. `signer`
    is a DigitalSignature configured with THIS station's signing key.
    """
    # Split into fragments (at least one, even for an empty payload).
    if len(payload) <= max_fragment_size:
        fragments = [payload]
    else:
        fragments = [payload[i:i + max_fragment_size]
                     for i in range(0, len(payload), max_fragment_size)]
    total = len(fragments)

    packets: list[bytes] = []
    for index, fragment in enumerate(fragments):
        # Each fragment gets its OWN fresh random IV (see encryption.encrypt).
        iv, ciphertext = encrypt(fragment, session_key)

        header = struct.pack(
            _HEADER_FORMAT,
            1,                                    # type = data
            src_id, dst_id, sequence_number,
            priority,
            int(time.time()) & 0xFFFFFFFF,        # timestamp
            flags,
            1 if total > 1 else 0,                # fragmented flag
            index,                                # fragment_index
            total,                                # fragment_total
            len(ciphertext),                      # ciphertext_length
        )

        signed_region = header + iv + ciphertext  # exactly what we sign & send
        signature = signer.sign(signed_region)    # encrypt-then-sign
        packets.append(signature + signed_region)

    return packets


def decapsulate(packet: bytes, session_key: bytes, verifier) -> tuple[bytes, dict]:
    """
    Verify, decrypt, and parse a single SNP packet.

    Returns (fragment_payload, header_dict). Raises SignatureError if the
    signature is invalid (an attacker's forgery or a modified packet), and
    ValueError if the packet is malformed. `verifier` is a DigitalSignature
    configured with the PEER's public key.
    """
    if len(packet) < SIGNATURE_SIZE + HEADER_SIZE + IV_SIZE:
        raise ValueError("packet too short to be a valid SNP packet")

    signature = packet[:SIGNATURE_SIZE]
    signed_region = packet[SIGNATURE_SIZE:]

    # (1) Verify the signature over the whole signed region BEFORE decrypting.
    if not verifier.verify(signed_region, signature):
        raise SignatureError("Invalid digital signature -- packet rejected")

    # (2) Parse the header (fully length-driven, no hard-coded offsets).
    header_bytes = signed_region[:HEADER_SIZE]
    (ptype, src_id, dst_id, seq, priority, timestamp, flags,
     fragmented, frag_index, frag_total, ct_len) = struct.unpack(_HEADER_FORMAT, header_bytes)

    iv_start = HEADER_SIZE
    ct_start = HEADER_SIZE + IV_SIZE
    iv = signed_region[iv_start:ct_start]
    ciphertext = signed_region[ct_start:ct_start + ct_len]
    if len(ciphertext) != ct_len:
        raise ValueError("truncated ciphertext -- length field does not match data")

    # (3) Decrypt.
    payload = decrypt(ciphertext, iv, session_key)

    header = {
        "type": ptype, "src_id": src_id, "dst_id": dst_id,
        "sequence_number": seq, "priority": priority, "timestamp": timestamp,
        "flags": flags, "fragmented": fragmented,
        "fragment_index": frag_index, "fragment_total": frag_total,
    }
    return payload, header


def reassemble(fragments: list[tuple[bytes, dict]]) -> bytes:
    """
    Reassemble a fragmented message from a list of (payload, header) pairs as
    returned by decapsulate(). Fragments are ordered by their fragment_index.
    """
    if not fragments:
        return b""
    total = fragments[0][1]["fragment_total"]
    if len(fragments) != total:
        raise ValueError(f"expected {total} fragments, got {len(fragments)}")
    ordered = sorted(fragments, key=lambda item: item[1]["fragment_index"])
    return b"".join(payload for payload, _ in ordered)
