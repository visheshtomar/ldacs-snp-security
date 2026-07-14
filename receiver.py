"""
receiver.py  --  Ground Station (GS): the responding LDACS endpoint.

Usage (run this FIRST, then sender.py in another terminal):
    python receiver.py

Completes an authenticated Diffie-Hellman handshake, then receives AES-256
encrypted / RSA-2048 signed SNP packets, verifies and decrypts them, and replies.
Packets whose signature does not verify (tampered or forged) are rejected.
Set USE_GUI = True to enable tkinter popups (requires a display).
"""

import socket

from authentication import DigitalSignature, load_private_key, load_public_key
import snp
from handshake import responder_handshake

USE_GUI = False   # headless-safe default

RECEIVER_ADDR = ("127.0.0.1", 5002)

MENU = """
Please select a reply:
1. Have a safe journey
2. Request accepted
3. Weather is clear
4. Wait for further update
Enter your choice: """

REPLIES = {
    "1": "Have a safe journey",
    "2": "Request accepted",
    "3": "Weather is clear",
    "4": "Wait for further update",
}


def popup(msg):
    if not USE_GUI:
        return
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showinfo("Message received", msg); root.destroy()


def main():
    # Ground signs with its own key; verifies the aircraft's key.
    signer = DigitalSignature(signing_key=load_private_key("ground_private.pem"),
                              peer_public_key=load_public_key("aircraft_public.pem"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(RECEIVER_ADDR)
    print(f"[receiver] listening on {RECEIVER_ADDR[0]}:{RECEIVER_ADDR[1]}")

    print("[receiver] performing authenticated DH handshake ...")
    session_key, peer_addr = responder_handshake(sock, signer)
    print(f"[receiver] session key established: {session_key.hex()[:16]}...")

    seq = 0
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            message, header = snp.decapsulate(data, session_key, signer)
        except snp.SignatureError:
            print("[receiver] REJECTED: packet with invalid digital signature")
            continue

        text = message.decode()
        print("\n" + "-" * 50)
        print(f"[receiver] received (verified+decrypted): {text!r}")
        print("-" * 50)
        popup(text)

        reply = REPLIES.get(input(MENU).strip(), "Request accepted")
        seq += 1
        packet = snp.encapsulate(reply.encode(), session_key, signer,
                                 src_id=2, dst_id=1, sequence_number=seq)[0]
        sock.sendto(packet, addr)
        print(f"[receiver] replied: {reply!r}")


if __name__ == "__main__":
    main()
