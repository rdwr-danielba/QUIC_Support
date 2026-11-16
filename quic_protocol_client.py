
import argparse
import socket
import secrets
import hmac
import hashlib

from scapy.all import rdpcap, IP, IPv6, TCP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# QUIC v1 Initial salt (RFC 9001)
INITIAL_SALT = bytes.fromhex(
    "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
)


def encode_varint(value):
    if value < 0x40:
        return bytes([value])
    elif value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    elif value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    elif value < 0x4000000000000000:
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("QUIC variable integer too large")


def hkdf_expand_label(secret, label, length):
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + b"\x00"
    )

    output = b""
    previous = b""
    counter = 1

    while len(output) < length:
        previous = hmac.new(
            secret,
            previous + info + bytes([counter]),
            hashlib.sha256
        ).digest()

        output += previous
        counter += 1

    return output[:length]


def extract_client_hello(pcap_file):
    packets = rdpcap(pcap_file)
    streams = {}

    # Collect TCP payloads by TCP connection
    for packet in packets:
        if TCP not in packet:
            continue

        tcp = packet[TCP]
        payload = bytes(tcp.payload)

        if not payload:
            continue

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        else:
            continue

        key = (src, tcp.sport, dst, tcp.dport)

        streams.setdefault(key, []).append((tcp.seq, payload))

    # Reassemble each TCP stream and search for TLS ClientHello
    for key, segments in streams.items():
        segments.sort(key=lambda item: item[0])

        base_seq = segments[0][0]
        stream = bytearray()

        for seq, payload in segments:
            offset = seq - base_seq

            if offset > len(stream):
                continue

            overlap = len(stream) - offset

            if overlap < len(payload):
                stream.extend(payload[max(0, overlap):])

        # Extract TLS handshake records
        handshake_data = bytearray()
        pos = 0

        while pos + 5 <= len(stream):
            content_type = stream[pos]

            if content_type not in (20, 21, 22, 23):
                pos += 1
                continue

            record_length = int.from_bytes(
                stream[pos + 3:pos + 5], "big"
            )

            end = pos + 5 + record_length

            if end > len(stream):
                break

            if content_type == 22:
                handshake_data.extend(stream[pos + 5:end])

            pos = end

        # TLS handshake format:
        # 1 byte type + 3 bytes length + handshake body
        pos = 0

        while pos + 4 <= len(handshake_data):
            msg_type = handshake_data[pos]

            msg_length = int.from_bytes(
                handshake_data[pos + 1:pos + 4], "big"
            )

            end = pos + 4 + msg_length

            if end > len(handshake_data):
                break

            if msg_type == 1:
                client_hello = bytes(handshake_data[pos:end])

                print(f"Found ClientHello in stream: {key}")
                print(f"Original ClientHello length: {len(client_hello)} bytes")

                return client_hello

            pos = end

    raise ValueError("No complete TLS ClientHello found in the PCAP")


def build_crypto_frames(client_hello, chunks):
    """Split ClientHello into multiple CRYPTO frames with consecutive offsets."""

    if chunks < 1:
        raise ValueError("--crypto-chunks must be at least 1")

    if chunks > len(client_hello):
        raise ValueError(
            f"--crypto-chunks cannot exceed ClientHello length "
            f"({len(client_hello)} bytes)"
        )

    frames = bytearray()

    # Distribute bytes evenly, including any remainder
    base_size, remainder = divmod(len(client_hello), chunks)

    offset = 0

    for i in range(chunks):
        chunk_size = base_size + (1 if i < remainder else 0)
        chunk = client_hello[offset:offset + chunk_size]

        # CRYPTO frame:
        # Type 0x06 | Offset | Length | Data
        frames.append(0x06)
        frames.extend(encode_varint(offset))
        frames.extend(encode_varint(len(chunk)))
        frames.extend(chunk)

        print(
            f"CRYPTO frame {i + 1}/{chunks}: "
            f"Offset={offset}, Length={len(chunk)}"
        )

        offset += len(chunk)

    return bytes(frames)


def build_quic_initial(client_hello, crypto_chunks=1):
    # Generate connection IDs
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)

    # Derive QUIC v1 client Initial keys
    initial_secret = hmac.new(
        INITIAL_SALT,
        dcid,
        hashlib.sha256
    ).digest()

    client_secret = hkdf_expand_label(
        initial_secret, b"client in", 32
    )

    key = hkdf_expand_label(client_secret, b"quic key", 16)
    iv = hkdf_expand_label(client_secret, b"quic iv", 12)
    hp = hkdf_expand_label(client_secret, b"quic hp", 16)

    # Build one or more CRYPTO frames
    crypto_frames = build_crypto_frames(
        client_hello, crypto_chunks
    )

    packet_number = 0
    packet_number_bytes = b"\x00"

    def create_packet(plaintext):
        # Long header, fixed bit, Initial packet, 1-byte PN
        first_byte = 0xC0

        header_prefix = (
            bytes([first_byte])
            + (1).to_bytes(4, "big")  # QUIC v1
            + bytes([len(dcid)])
            + dcid
            + bytes([len(scid)])
            + scid
            + encode_varint(0)  # Token length
        )

        # Length includes packet number and AEAD tag
        packet_length = 1 + len(plaintext) + 16
        header_prefix += encode_varint(packet_length)

        # Packet number is part of the authenticated header
        aad = header_prefix + packet_number_bytes

        nonce = bytearray(iv)
        nonce_number = packet_number.to_bytes(12, "big")

        for i in range(12):
            nonce[i] ^= nonce_number[i]

        ciphertext = AESGCM(key).encrypt(
            bytes(nonce),
            plaintext,
            aad
        )

        packet = bytearray(
            header_prefix + packet_number_bytes + ciphertext
        )

        # QUIC header protection
        pn_offset = len(header_prefix)
        sample = bytes(packet[pn_offset + 4:pn_offset + 20])

        encryptor = Cipher(
            algorithms.AES(hp),
            modes.ECB()
        ).encryptor()

        mask = encryptor.update(sample) + encryptor.finalize()

        packet[0] ^= mask[0] & 0x0F
        packet[pn_offset] ^= mask[1]

        return bytes(packet)

    # QUIC Initial datagrams must be at least 1200 bytes
    padding = 0

    while True:
        plaintext = crypto_frames + (b"\x00" * padding)
        packet = create_packet(plaintext)

        if len(packet) >= 1200:
            break

        padding += 1200 - len(packet)

    print(f"QUIC Initial packet size: {len(packet)} bytes")
    print(f"QUIC DCID: {dcid.hex()}")
    print(f"QUIC SCID: {scid.hex()}")
    print(f"Total CRYPTO frames: {crypto_chunks}")

    return packet


def main():
    parser = argparse.ArgumentParser(
        description="Send an existing TLS ClientHello inside QUIC Initial"
    )

    parser.add_argument("--ip", required=True, help="Destination IP")
    parser.add_argument(
        "--port", type=int, default=443,
        help="Destination UDP port"
    )
    parser.add_argument(
        "--client-hello", required=True,
        help="Source TLS PCAP"
    )
    parser.add_argument(
        "--crypto-chunks",
        type=int,
        default=1,
        help="Number of CRYPTO frames in the same QUIC Initial packet (default: 1)"
    )

    args = parser.parse_args()

    print(f"Extracting ClientHello from {args.client_hello}")

    client_hello = extract_client_hello(args.client_hello)

    print("Building QUIC Initial packet...")

    quic_packet = build_quic_initial(
        client_hello,
        crypto_chunks=args.crypto_chunks
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect((args.ip, args.port))
        sock.send(quic_packet)

        print(f"Sent {len(quic_packet)} bytes to {args.ip}:{args.port}")
        print("QUIC Initial transmission completed.")

    finally:
        sock.close()


if __name__ == "__main__":
    main()
