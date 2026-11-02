from scapy.all import rdpcap, DNSQR
from Crypto.Cipher import AES
import base64
import subprocess
import tempfile
import os


PCAP_FILE = "the-missing-recipe.pcap"

DOMAIN = "targwuwrnhos.com"

AES_KEY = b"Brunn3rK3yAESCBC"

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


# ============================================================
# CUSTOM BASE32 DECODER
# ============================================================

def custom_b32decode(s):
    """
    Decode the challenge's Base32 stream exactly as the
    original custom decoder does.

    We deliberately DO NOT use base64.b32decode(), because
    the second stream in this PCAP has a non-RFC4648 length.
    """

    s = s.upper().rstrip("=")

    bits = ""

    for char in s:

        if char not in BASE32_ALPHABET:
            raise ValueError(
                f"Invalid Base32 character: {char!r}"
            )

        value = BASE32_ALPHABET.index(char)

        bits += format(value, "05b")

    output = bytearray()

    complete_bits = len(bits) - (len(bits) % 8)

    for i in range(0, complete_bits, 8):

        output.append(
            int(bits[i:i + 8], 2)
        )

    return bytes(output)


# ============================================================
# EXTRACT DNS QUERIES
# ============================================================

def extract_dns_labels(filename):

    packets = rdpcap(filename)

    labels = []

    for packet_index, pkt in enumerate(packets):

        if not pkt.haslayer(DNSQR):
            continue

        qname = pkt[DNSQR].qname.decode(
            errors="ignore"
        ).rstrip(".")

        suffix = "." + DOMAIN

        if not qname.endswith(suffix):
            continue

        subdomain = qname[:-len(suffix)]

        if not subdomain:
            continue

        # These are C2/status messages, not Base32 payload.
        if subdomain.lower() in {
            "update",
            "brunnerlocked",
        }:
            continue

        # Only keep strings composed of Base32 characters.
        if not all(
            c.upper() in BASE32_ALPHABET
            for c in subdomain
        ):
            continue

        labels.append(
            {
                "packet": packet_index,
                "label": subdomain,
            }
        )

    return labels


# ============================================================
# RECONSTRUCT BASE32 STREAM
# ============================================================

def reconstruct_stream(labels):

    return "".join(
        item["label"]
        for item in labels
    )


# ============================================================
# ZSTANDARD
# ============================================================

def zstd_magic(data):

    return data.startswith(
        ZSTD_MAGIC
    )


def zstd_decompress_strict(data):

    """
    First try Python's zstandard module.

    This isn't guaranteed to be available in every venv,
    so the main solver uses the system zstd command below.
    """

    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()

    return dctx.decompress(data)


def zstd_decompress_cli(data):

    """
    Feed a Zstandard frame to the system 'zstd' utility.

    The second frame in this PCAP is truncated by one byte.
    zstd may therefore return an error while STILL producing
    the available decompressed bytes.

    We preserve that output because it is useful evidence.
    """

    with tempfile.NamedTemporaryFile(
        delete=False
    ) as f:

        filename = f.name

        f.write(data)

    try:

        result = subprocess.run(
            [
                "zstd",
                "-q",
                "-d",
                "--stdout",
                filename,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return (
            result.returncode,
            result.stdout,
            result.stderr.decode(
                errors="replace"
            ),
        )

    finally:

        os.unlink(filename)


# ============================================================
# AES-CBC
# ============================================================

def decrypt_complete_aes_blocks(data):

    """
    Interpret:

        [16-byte IV][AES-CBC ciphertext]

    and decrypt all COMPLETE ciphertext blocks that are
    actually present in the capture.

    This deliberately does NOT invent the missing final byte.
    """

    if len(data) < 16:

        raise ValueError(
            "Not enough bytes for an IV"
        )

    iv = data[:16]

    ciphertext = data[16:]

    complete_length = (
        len(ciphertext) // AES.block_size
    ) * AES.block_size

    complete_ciphertext = (
        ciphertext[:complete_length]
    )

    cipher = AES.new(
        AES_KEY,
        AES.MODE_CBC,
        iv,
    )

    plaintext = cipher.decrypt(
        complete_ciphertext
    )

    return (
        iv,
        complete_ciphertext,
        plaintext,
        ciphertext[complete_length:],
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. Extract DNS payload labels
    # --------------------------------------------------------

    labels = extract_dns_labels(
        PCAP_FILE
    )

    print(
        f"[+] DNS payload labels found: {len(labels)}"
    )

    for item in labels:

        print(
            f"{item['packet']:5d} {item['label']}"
        )


    # --------------------------------------------------------
    # 2. The PCAP contains TWO payload phases.
    #
    #    First:
    #        packets 1861..10778
    #
    #    Second:
    #        packets 21517..43805
    #
    # We identify the split using packet ordering.
    # --------------------------------------------------------

    first_labels = [
        x for x in labels
        if x["packet"] < 21517
    ]

    second_labels = [
        x for x in labels
        if x["packet"] > 21516
    ]


    print(
        "\n[+] First-stage labels:",
        len(first_labels)
    )

    print(
        "[+] Second-stage labels:",
        len(second_labels)
    )


    # --------------------------------------------------------
    # 3. Reconstruct Base32 streams
    # --------------------------------------------------------

    stream1 = reconstruct_stream(
        first_labels
    )

    stream2 = reconstruct_stream(
        second_labels
    )


    print(
        "\n[+] Stage 1 Base32 length:",
        len(stream1)
    )

    print(
        "[+] Stage 2 Base32 length:",
        len(stream2)
    )


    # --------------------------------------------------------
    # 4. Custom Base32 decode
    # --------------------------------------------------------

    blob1 = custom_b32decode(
        stream1
    )

    blob2 = custom_b32decode(
        stream2
    )


    print(
        "\n[+] Stage 1 decoded bytes:",
        len(blob1)
    )

    print(
        "[+] Stage 2 decoded bytes:",
        len(blob2)
    )


    print(
        "[+] Stage 1 magic:",
        blob1[:4].hex()
    )

    print(
        "[+] Stage 2 magic:",
        blob2[:4].hex()
    )


    # --------------------------------------------------------
    # 5. Locate Zstandard frames
    # --------------------------------------------------------

    combined = blob1 + blob2

    first_offset = combined.find(
        ZSTD_MAGIC
    )

    second_offset = combined.find(
        ZSTD_MAGIC,
        first_offset + 4
    )


    print(
        "\n[+] First Zstd offset:",
        first_offset
    )

    print(
        "[+] Second Zstd offset:",
        second_offset
    )


    if first_offset == -1:

        raise RuntimeError(
            "First Zstd frame not found"
        )


    if second_offset == -1:

        raise RuntimeError(
            "Second Zstd frame not found"
        )


    # --------------------------------------------------------
    # 6. Split frames
    # --------------------------------------------------------

    frame1 = combined[
        first_offset:second_offset
    ]

    frame2 = combined[
        second_offset:
    ]


    print(
        "[+] Frame 1 length:",
        len(frame1)
    )

    print(
        "[+] Frame 2 length:",
        len(frame2)
    )


    # --------------------------------------------------------
    # 7. Decompress frame 1
    # --------------------------------------------------------

    print(
        "\n========== ZSTD OBJECT 0 =========="
    )


    rc1, plaintext1, error1 = (
        zstd_decompress_cli(frame1)
    )


    print(
        "[+] zstd exit code:",
        rc1
    )

    print(
        "[+] Decompressed:",
        len(plaintext1),
        "bytes"
    )

    print()

    print(
        plaintext1.decode(
            "utf-8",
            errors="replace"
        )
    )


    # --------------------------------------------------------
    # 8. Decompress frame 2
    # --------------------------------------------------------

    print(
        "\n========== ZSTD OBJECT 1 =========="
    )


    rc2, plaintext2, error2 = (
        zstd_decompress_cli(frame2)
    )


    print(
        "[+] zstd exit code:",
        rc2
    )

    print(
        "[+] Decompressed:",
        len(plaintext2),
        "bytes"
    )


    if error2:

        print(
            "[+] zstd message:",
            error2
        )


    print(
        "[+] First 32 bytes:"
    )

    print(
        plaintext2[:32].hex()
    )


    # --------------------------------------------------------
    # 9. AES
    # --------------------------------------------------------

    print(
        "\n========== AES-CBC =========="
    )


    iv, ciphertext, decrypted, remainder = (
        decrypt_complete_aes_blocks(
            plaintext2
        )
    )


    print(
        "[+] IV:",
        iv.hex()
    )

    print(
        "[+] Captured ciphertext:",
        len(plaintext2) - 16,
        "bytes"
    )

    print(
        "[+] Complete AES ciphertext:",
        len(ciphertext),
        "bytes"
    )

    print(
        "[+] Incomplete ciphertext bytes:",
        len(remainder)
    )


    print(
        "\n===== AES PLAINTEXT AVAILABLE FROM CAPTURE ====="
    )

    print(
        decrypted.decode(
            "utf-8",
            errors="replace"
        )
    )


    # --------------------------------------------------------
    # 10. Do NOT silently manufacture a missing byte
    # --------------------------------------------------------

    if remainder:

        print(
            "\n[!] IMPORTANT:"
        )

        print(
            f"[!] The capture contains {len(remainder)} "
            "ciphertext byte(s) that do not make a full AES block."
        )

        print(
            "[!] The PCAP's Zstd frame declares more "
            "decompressed data than was actually captured."
        )

        print(
            "[!] No missing ciphertext byte has been invented."
        )


if __name__ == "__main__":

    main()
