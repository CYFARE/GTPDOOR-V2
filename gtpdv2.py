import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTPHeader
import binascii

captured_payloads = []

def capture_payload(packet):
    if IP in packet and UDP in packet and GTPHeader in packet:
        gtp = packet[GTPHeader]
        if gtp.message_type == 1:  # GTP Echo Request
            payload = bytes(gtp.payload)
            message_type = payload[0]
            if message_type in (0x01, 0x02) or (0x03 <= message_type <= 0x04) or (0x08 <= message_type <= 0xFF):
                captured_payloads.append(payload[1:])  # Store payload excluding the message type byte

def decrypt_and_convert_payloads(key):
    for payload in captured_payloads:
        decrypted = decrypt(key, payload)
        try:
            ascii_payload = binascii.unhexlify(decrypted).decode('ascii')
            print(f"Decrypted ASCII payload: {ascii_payload}")
        except (TypeError, ValueError) as e:
            print(f"Error converting decrypted payload to ASCII: {e}")

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

def start_capture():
    print("Starting packet capture...")
    scapy.sniff(prn=capture_payload, store=False, lfilter=lambda x: x.haslayer(GTPHeader), count=100)  # Adjust count as needed

if __name__ == "__main__":
    start_capture()
    key = b'your_key_here'  # Set your decryption key
    decrypt_and_convert_payloads(key)
