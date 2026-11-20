import sys
from Crypto.Cipher import AES
from scapy.all import ICMP, Raw, rdpcap

KEY = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
IV = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")


def unpad_pkcs7(data: bytes) -> bytes:
    # Remove trailing PKCS#7 padding if valid
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 test_first_block.py capture_all.pcap")
        sys.exit(1)

    packets = rdpcap(sys.argv[1])
    # Filter ICMP echo requests from the sender host
    reqs = [
        pkt for pkt in packets
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw) and pkt[ICMP].type == 8
    ]
    print(f"ICMP echo requests: {len(reqs)}")

    # Take first 16-byte ciphertext block after the 16-byte ping header
    raw_payload = bytes(reqs[0][Raw].load)
    ct_block = raw_payload[16:32]
    plain = unpad_pkcs7(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct_block))
    print("First block bytes:", plain)
    print("First block text :", plain.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()