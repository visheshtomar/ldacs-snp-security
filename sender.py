"""
sender.py  --  Aircraft Station (AS): the initiating LDACS endpoint.

Usage (run receiver.py first, in another terminal):
    python sender.py

This performs an authenticated Diffie-Hellman handshake with the ground station,
then sends menu-selected ATC messages, each AES-256 encrypted and RSA-2048 signed
via the SNP layer. Set USE_GUI = True to enable tkinter popups (requires a display).
"""

import socket

from authentication import DigitalSignature, load_private_key, load_public_key
import snp
from handshake import initiator_handshake

USE_GUI = False   # headless-safe default

SENDER_ADDR = ("127.0.0.1", 5003)
RECEIVER_ADDR = ("127.0.0.1", 5002)

MENU = """
Please select an option:
1. Ready for takeoff
2. Ready for landing
3. Turning towards left
4. Request to change direction
5. Request for current weather
6. Terminate the connection
Enter your choice: """

CHOICES = {
    "1": "Ready for takeoff",
    "2": "Ready for landing",
    "3": "Turning towards left",
    "4": "Request to change direction",
    "5": "Request for current weather",
    "6": "Request for termination",
}


def popup(msg):
    if not USE_GUI:
        return
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showinfo("Message", msg); root.destroy()


def main():
    # Aircraft signs with its own key; verifies the ground station's key.
    signer = DigitalSignature(signing_key=load_private_key("aircraft_private.pem"),
                              peer_public_key=load_public_key("ground_public.pem"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(SENDER_ADDR)

    print("[sender] performing authenticated DH handshake ...")
    session_key = initiator_handshake(sock, RECEIVER_ADDR, signer)
    print(f"[sender] session key established: {session_key.hex()[:16]}...")

    seq = 0
    while True:
        choice = input(MENU).strip()
        message = CHOICES.get(choice)
        if message is None:
            print("Invalid choice.")
            continue

        seq += 1
        # Short control messages fit in a single packet.
        packet = snp.encapsulate(message.encode(), session_key, signer,
                                 src_id=1, dst_id=2, sequence_number=seq)[0]
        sock.sendto(packet, RECEIVER_ADDR)
        print(f"[sender] sent (encrypted+signed): {message!r}")

        # Await the ground station's reply.
        data, _ = sock.recvfrom(4096)
        try:
            reply, _ = snp.decapsulate(data, session_key, signer)
            print(f"[sender] reply: {reply.decode()}")
            popup(reply.decode())
        except snp.SignatureError:
            print("[sender] WARNING: received a packet with an invalid signature")

        if choice == "6":
            print("[sender] termination requested. Exiting.")
            break

    sock.close()


if __name__ == "__main__":
    main()
