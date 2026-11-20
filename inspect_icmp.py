import sys
from scapy.all import ICMP, Raw, rdpcap


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 inspect_icmp.py capture_all.pcap")
        sys.exit(1)

    packets = rdpcap(sys.argv[1])
    icmp_raw = [pkt for pkt in packets if pkt.haslayer(ICMP) and pkt.haslayer(Raw)]
    print(f"Total ICMP packets with Raw payload: {len(icmp_raw)}")

    # Print first few payloads to see how ping -p formatted them
    for idx, pkt in enumerate(icmp_raw[:5]):
        src = pkt[0][1].src if hasattr(pkt[0][1], "src") else "?"
        dst = pkt[0][1].dst if hasattr(pkt[0][1], "dst") else "?"
        payload = bytes(pkt[Raw].load)
        print(f"[{idx}] {src} -> {dst} | len={len(payload)} | hex={payload.hex()}")


if __name__ == "__main__":
    main()