import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTPHeader

def process_packet(packet):
    if IP in packet and UDP in packet:
        udp_layer = packet[UDP]
        if udp_layer.dport == 2152:
            if GTPHeader in packet:
                gtp_layer = packet[GTPHeader]
                try:
                    gtp_payload = bytes(gtp_layer.payload)
                    if len(gtp_payload) > 0:
                        key = b'123'  # Ensure this matches the encryption key
                        decrypted_payload = decrypt(key, gtp_payload)
                        # Convert the decrypted bytearray to an ASCII string
                        decrypted_string = decrypted_payload.decode('ascii')
                        print(f"Decrypted payload: {decrypted_string}")
                except Exception as e:
                    print(f"Error processing GTP packet: {e}")


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
    print("Starting packet sniffing on GTP port...")
    # Ensure sniffing on the correct interface that receives GTP packets, e.g., 'lo' for local testing or another as needed.
    scapy.sniff(iface="lo", prn=process_packet, store=False, filter="udp port 2152")
    # to listen on all interfaces - does't work
    #scapy.sniff(prn=process_packet, store=False, filter="udp port 2152")

if __name__ == "__main__":
    start_sniffing()
