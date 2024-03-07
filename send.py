from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTPHeader, GTP_U_Header
import sys

def encrypt(key, plaintext):
    key_idx = 0
    ciphertext = bytearray(len(plaintext))
    for i in range(len(plaintext)):
        if key_idx >= len(key):
            key_idx = 0
        ciphertext[i] = key[key_idx] ^ plaintext[i]
        key_idx += 1
    return bytes(ciphertext)

def create_gtp_packet(command):
    key = b'123'  # Updated key based on the listener script
    message_type = b'\x01'  # Assuming Echo Request for demonstration; adjust as needed
    encrypted_command = encrypt(key, command.encode())
    payload = message_type + encrypted_command
    
    # Create the packet with GTPHeader; adjust the creation of the GTPHeader to work around the issue
    packet = (IP(dst="127.0.0.1") /  # Use the appropriate destination IP
              UDP(sport=2123, dport=2152) /  # GTP-C typically uses port 2123 for control messages
              GTPHeader() /  # Create a GTPHeader without directly setting message_type
              Raw(load=payload))
    
    # If necessary, manually adjust the packet fields to set the message_type
    packet[GTPHeader].message_type = 1  # Set Echo Request; adjust if this direct assignment works or if another method is needed

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
