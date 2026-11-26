# QUIC Protocol Client

A Python script that extracts a TLS `ClientHello` message from a PCAP file and re-sends it encapsulated inside a QUIC Initial packet (RFC 9001) to a target server over UDP.

## Overview

The script:
1. Reads a `.pcap` file containing a captured TCP/TLS handshake.
2. Reassembles the TCP stream(s) and extracts the raw TLS `ClientHello` handshake message.
3. Splits the `ClientHello` into one or more QUIC `CRYPTO` frames.
4. Derives QUIC v1 Initial keys (using the RFC 9001 Initial salt), encrypts the payload with AES-GCM, and applies QUIC header protection.
5. Pads the packet to the minimum QUIC Initial size (1200 bytes).
6. Sends the resulting UDP datagram to the specified destination, either a fixed number of times or in a continuous loop at a given rate.

## Requirements

- Python 3.8+

### Python Libraries

Install the required third-party packages with pip:

```bash
pip install scapy cryptography
```

| Library | Purpose |
|---|---|
| `scapy` | Reading/parsing the PCAP file and reconstructing TCP streams |
| `cryptography` | AES-GCM encryption and AES-ECB header protection (QUIC key derivation) |

All other imports (`argparse`, `socket`, `secrets`, `hmac`, `hashlib`, `time`) are part of the Python standard library.

> **Note:** The script uses `time.perf_counter()` and `time.sleep()` in the `--isLoop` mode but does not import `time` at the top of the file. Make sure to add `import time` near the other imports before using `--isLoop True`, otherwise you will get a `NameError`.

## Usage

```bash
python3 quic_protocol_client.py --ip <destination_ip> --client-hello <path_to_pcap> [options]
```

### Required Flags

| Flag | Description |
|---|---|
| `--ip` | Destination IP address to send the QUIC Initial packet to. |
| `--client-hello` | Path to a `.pcap` file containing a TCP/TLS stream with a `ClientHello` message. |

### Optional Flags

| Flag | Default | Description |
|---|---|---|
| `--port` | `443` | Destination UDP port. |
| `--crypto-chunks` | `1` | Number of `CRYPTO` frames to split the `ClientHello` into within the same QUIC Initial packet. Must be between `1` and the length of the `ClientHello` in bytes. |
| `--isLoop` | `False` | If `True` (`true`/`1`/`yes`), continuously sends packets at `--rate` packets/second until interrupted (Ctrl+C). If `False`, sends the packet a fixed number of times defined by `--rate`. |
| `--rate` | `1` | When `--isLoop` is `True`: packets per second to send. When `--isLoop` is `False`: number of times to send the packet. |

## Examples

**Send a single QUIC Initial packet to 93.184.216.34 on port 443:**
```bash
python3 quic_protocol_client.py --ip 93.184.216.34 --client-hello capture.pcap
```

**Send the packet 10 times (burst mode):**
```bash
python3 quic_protocol_client.py --ip 93.184.216.34 --client-hello capture.pcap --rate 10
```

**Continuously send 50 packets per second:**
```bash
python3 quic_protocol_client.py --ip 93.184.216.34 --client-hello capture.pcap --isLoop True --rate 50
```

**Split the ClientHello into 3 CRYPTO frames and target a custom port:**
```bash
python3 quic_protocol_client.py --ip 10.0.0.5 --port 8443 --client-hello capture.pcap --crypto-chunks 3
```

## How It Works (Technical Details)

- **Connection IDs:** Random 8-byte Destination (DCID) and Source (SCID) Connection IDs are generated for each run via `secrets.token_bytes(8)`.
- **Key Derivation:** Uses HKDF-Expand-Label (TLS 1.3 style, SHA-256) with the QUIC v1 Initial salt to derive `client_secret`, then `quic key`, `quic iv`, and `quic hp` (header protection key).
- **CRYPTO Frames:** The `ClientHello` bytes are divided evenly across `--crypto-chunks` frames, each prefixed with QUIC frame type `0x06`, a varint offset, and a varint length.
- **Packet Encryption:** AES-128-GCM encrypts the frame payload using a nonce derived from the IV XORed with the packet number.
- **Header Protection:** AES-ECB is used to mask the first byte's low nibble and the packet number byte(s), per QUIC's header protection scheme.
- **Padding:** Extra zero bytes are added to the plaintext until the final packet reaches the required minimum of 1200 bytes.

## Troubleshooting

- **`ValueError: No complete TLS ClientHello found in the PCAP`** — The provided PCAP does not contain a full, reassembled TLS `ClientHello` record. Ensure the capture includes the complete TCP handshake and the TLS record wasn't fragmented/dropped.
- **`ValueError: --crypto-chunks cannot exceed ClientHello length`** — Reduce `--crypto-chunks` to a value less than or equal to the `ClientHello` size in bytes.
- **`NameError: name 'time' is not defined`** — Add `import time` at the top of `quic_protocol_client.py` before using `--isLoop True`.

