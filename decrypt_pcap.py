import sys
from Crypto.Cipher import AES
from scapy.all import ICMP, Raw, rdpcap

# Same AES-128 key and IV hardcoded in nightshade.py (__k and __v)
KEY = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
IV = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")


def unpad_pkcs7(data: bytes) -> bytes:
    # nightshade.py pads 15-byte chunks to 16 bytes using PKCS#7 (e.g. \x01 at the end)
    if not data:
        return data
    pad_len = data[-1]
    # Verify padding bytes match the expected count before stripping them
    if 1 <= pad_len <= 16 and data.endswith(bytes([pad_len]) * pad_len):
        return data[:-pad_len]
    return data


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 decrypt_pcap.py capture_all.pcap recovered.txt")
        sys.exit(1)

    out_path = sys.argv[2] if len(sys.argv) > 2 else "exfiltrated.bin"
    packets = rdpcap(sys.argv[1])

    # Keep only ICMP Echo Requests (type 8) carrying payload data:
    # nightshade.py runs `ping -c 1 -p <hex>`, so each exfiltrated chunk is in an outgoing echo request
    reqs = [
        pkt for pkt in packets
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw) and pkt[ICMP].type == 8
    ]

    recovered = bytearray()
    for pkt in reqs:
        raw_payload = bytes(pkt[Raw].load)
        # Skip the 16-byte ping timestamp/header and take the first 16-byte AES block
        # (ping -p repeats the hex pattern across the rest of the payload)
        ct_block = raw_payload[16:32]
        # Each chunk in nightshade.py creates a fresh AES-CBC cipher with the same IV
        plain = unpad_pkcs7(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct_block))
        recovered.extend(plain)

    with open(out_path, "wb") as f:
        f.write(recovered)

    print(f"Decrypted {len(reqs)} blocks -> saved {len(recovered)} bytes to {out_path}")
    print("--- Preview ---")
    print(recovered.decode("utf-8", errors="replace")[:1500])


if __name__ == "__main__":
    main()