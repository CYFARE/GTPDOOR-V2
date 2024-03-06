import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTPHeader

captured_payloads = []

def process_packet(packet):
    if IP in packet and UDP in packet and GTPHeader in packet:
        gtp = packet[GTPHeader]
        if gtp.message_type == 1:  # GTP Echo Request
            payload = bytes(gtp.payload)
            message_type = payload[0]
            if message_type in (0x01, 0x02) or (0x03 <= message_type <= 0x04) or (0x08 <= message_type <= 0xFF):
                key = b'your_key_here'  # This needs to be set based on your decryption key
                decrypted_payload = decrypt(key, payload[1:])  # Decrypt payload excluding the message type byte
                print(f"Decrypted payload: {decrypted_payload}")

def decrypt(key, ciphertext):
    key_idx = 0
    strlen = len(ciphertext)
    plaintext = bytearray(strlen)
    for i in range(strlen):
        if key_idx >= len(key):
            key_idx = 0
        plaintext[i] = key[key_idx] ^ ciphertext[i]
        key_idx += 1
    return plaintext

def start_sniffing():
    print("Starting packet sniffing...")
    scapy.sniff(prn=process_packet, store=False, lfilter=lambda x: x.haslayer(GTPHeader))

if __name__ == "__main__":
    start_sniffing()
