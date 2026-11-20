from Crypto.Cipher import AES

# Same AES-128-CBC parameters and encrypted target as nightshade.py
KEY = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
IV = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")
ENC_DST = "37e0f8f92c71f1c3f047f43c13725ef1"


def unpad_pkcs7(data: bytes) -> bytes:
    # Strip PKCS#7 padding bytes
    return data[: -data[-1]]


def main() -> None:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plain = unpad_pkcs7(cipher.decrypt(bytes.fromhex(ENC_DST)))
    print("Target:", plain.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()