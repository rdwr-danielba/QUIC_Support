# QUIC Client–Server Setup

## 1. Overview

This setup sends an existing TLS ClientHello from a PCAP file inside a QUIC v1 Initial packet.

**Lab configuration:**

| Parameter | Value |
|---|---|
| Server IP | `40.1.1.10` |
| Server UDP port | `4433` |
| Protocol | QUIC v1 |
| Client input | `CH_TLS13.pcap` |
| CRYPTO frames | 1 by default |

The goal is to allow DefensePro to inspect the TLS ClientHello inside QUIC traffic. A complete QUIC handshake is not required.

---

# 2. Server Setup – 40.1.1.10

## 2.1 Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip openssl
python3 -m pip install aioquic
```

If pip reports an externally managed environment:

```bash
python3 -m venv ~/quic-venv
source ~/quic-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install aioquic
```

## 2.2 Generate a self-signed certificate

Create a directory:

```bash
mkdir -p ~/quic-server
cd ~/quic-server
```

Generate the certificate and private key:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=40.1.1.10" \
  -addext "subjectAltName=IP:40.1.1.10"
```

Restrict private-key permissions:

```bash
chmod 600 server.key
```

Generated files:

- `server.crt` – self-signed certificate.
- `server.key` – private key.

**Note:** The packet-generation client does not need these certificate files. They are used by the QUIC server.

## 2.3 Allow UDP port 4433

If UFW is enabled:

```bash
sudo ufw allow 4433/udp
sudo ufw status
```

Make sure any external firewall also allows UDP/4433.

## 2.4 Start the QUIC server

Using the aioquic example server:

```bash
python3 server.py --host 0.0.0.0 --port 4433 \
  --certificate ~/quic-server/server.crt \
  --private-key ~/quic-server/server.key
```

Run this from the directory containing the aioquic example `server.py`.

If using a local `quic_server.py` wrapper, check its supported arguments:

```bash
python3 quic_server.py --help
```

The exact CLI options depend on the server script/version.

## 2.5 Verify the server

Check that UDP/4433 is listening:

```bash
ss -lunp | grep 4433
```

Capture incoming traffic:

```bash
sudo tcpdump -ni any 'udp port 4433'
```

---

# 3. Client Setup

## 3.1 Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip tcpdump tshark
```

Install Python dependencies:

```bash
python3 -m pip install scapy cryptography
```

If necessary, use a virtual environment:

```bash
python3 -m venv ~/quic-venv
source ~/quic-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install scapy cryptography
```

## 3.2 Prepare the files

Place the following files in the same directory:

```text
quic_protocol_client.py
CH_TLS13.pcap
```

The input PCAP must contain a TLS ClientHello that the script can extract.

For QUIC compatibility, use a TLS 1.3 ClientHello offering TLS 1.3 cipher suites, such as:

- `0x1301` – TLS_AES_128_GCM_SHA256
- `0x1302` – TLS_AES_256_GCM_SHA384
- `0x1303` – TLS_CHACHA20_POLY1305_SHA256

## 3.3 Check available flags

```bash
python3 quic_protocol_client.py --help
```

### Available arguments

| Flag | Default | Description |
|---|---|---|
| `--ip` | Required | Destination server IP |
| `--port` | `443` | Destination UDP port |
| `--client-hello` | Required | Input PCAP containing the ClientHello |
| `--crypto-chunks` | `1` | Number of CRYPTO frames inside the same QUIC Initial packet |

**Important:** The default destination port is 443. For this lab, explicitly use port 4433.

---

# 4. Send QUIC Traffic

## 4.1 Send one ClientHello using one CRYPTO frame

```bash
python3 quic_protocol_client.py \
  --ip 40.1.1.10 \
  --port 4433 \
  --client-hello CH_TLS13.pcap
```

By default, the ClientHello is placed inside one CRYPTO frame.

## 4.2 Send one ClientHello split into multiple CRYPTO frames

Example: split the ClientHello into three CRYPTO frames:

```bash
python3 quic_protocol_client.py \
  --ip 40.1.1.10 \
  --port 4433 \
  --client-hello CH_TLS13.pcap \
  --crypto-chunks 3
```

All three CRYPTO frames are carried inside the same QUIC Initial packet.

The script splits the ClientHello bytes evenly between the requested number of frames. Each frame uses its own offset and length, and the offsets are consecutive.

### Additional examples

Two CRYPTO frames:

```bash
python3 quic_protocol_client.py --ip 40.1.1.10 --port 4433 \
  --client-hello CH_TLS13.pcap --crypto-chunks 2
```

Five CRYPTO frames:

```bash
python3 quic_protocol_client.py --ip 40.1.1.10 --port 4433 \
  --client-hello CH_TLS13.pcap --crypto-chunks 5
```

---

# 5. Capture and Verify Traffic

## 5.1 Capture on the client

Identify the correct interface:

```bash
ip addr
```

Start the capture (replace `eth1` if necessary):

```bash
sudo tcpdump -ni eth1 \
  'host 40.1.1.10 and udp port 4433' \
  -w QUIC.pcap
```

Run the client command in another terminal, then stop tcpdump using `Ctrl+C`.

## 5.2 Capture on the server

```bash
sudo tcpdump -ni any 'udp port 4433' -w server_QUIC.pcap
```

Send traffic from the client and stop the capture with `Ctrl+C`.

## 5.3 Verify QUIC Initial packets

```bash
tshark -r QUIC.pcap -Y quic -V
```

Filter for TLS ClientHello:

```bash
tshark -r QUIC.pcap -Y 'tls.handshake.type == 1' -V
```

Verify the following:

- QUIC version is QUIC v1.
- Packet type is Initial.
- ClientHello is present inside the CRYPTO frame.
- CRYPTO frame offset starts at 0.
- ClientHello extensions and cipher suites are decoded correctly.

For a multi-frame test, verify that multiple CRYPTO frames exist and that their offsets are consecutive.

---

# 6. Important Technical Notes

## 6.1 TLS ClientHello inside QUIC

QUIC carries TLS handshake messages inside CRYPTO frames.

Unlike TLS over TCP, QUIC does not carry the TLS record header inside the CRYPTO frame.

The client script therefore extracts the TLS handshake message from the original PCAP and places it directly into QUIC CRYPTO frames.

## 6.2 QUIC Initial salt

The script uses the fixed QUIC v1 Initial salt defined by RFC 9001:

```python
INITIAL_SALT = bytes.fromhex(
    "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
)
```

This salt is used together with the Destination Connection ID to derive the Initial packet protection keys.

Initial packet keys are publicly derivable; Initial encryption is not intended to provide confidentiality.

## 6.3 Server handshake rejection

The current `CH_TLS13.pcap` does not contain:

- ALPN extension advertising `h3`.
- QUIC transport parameters extension.

Therefore, the aioquic server may reject the handshake with errors such as:

```text
No common ALPN protocols
```

This is expected for the current test setup.

**A successful QUIC handshake is not required for the DefensePro DPI test.**

The important verification is that the QUIC Initial packet contains the intended ClientHello and that DefensePro receives and parses it.

---

# 7. Troubleshooting

### Server does not receive packets

Check:

```bash
ss -lunp | grep 4433
```

Check the route from the client:

```bash
ip route get 40.1.1.10
```

Capture on both sides:

```bash
sudo tcpdump -ni any 'udp port 4433'
```

Check host and network firewalls.

### No common ALPN protocols

The ClientHello does not advertise `h3`. This can prevent the aioquic server from completing the handshake but does not prevent ClientHello inspection.

### No supported cipher suite

The input PCAP may contain only TLS 1.2 cipher suites. Use a TLS 1.3 ClientHello for QUIC testing.

### Certificate errors

Verify that the server command references the correct certificate and private key:

```text
server.crt
server.key
```

The packet-generation client does not validate the server certificate.

---

# 8. Quick Reference – Full Test

### Server (40.1.1.10)

Start the server:

```bash
python3 server.py --host 0.0.0.0 --port 4433 \
  --certificate ~/quic-server/server.crt \
  --private-key ~/quic-server/server.key
```

### Client

Send one ClientHello:

```bash
python3 quic_protocol_client.py --ip 40.1.1.10 --port 4433 \
  --client-hello CH_TLS13.pcap
```

Send one ClientHello split into three CRYPTO frames:

```bash
python3 quic_protocol_client.py --ip 40.1.1.10 --port 4433 \
  --client-hello CH_TLS13.pcap --crypto-chunks 3
```

Capture and inspect:

```bash
sudo tcpdump -ni eth1 'host 40.1.1.10 and udp port 4433' -w QUIC.pcap
tshark -r QUIC.pcap -Y 'tls.handshake.type == 1' -V
```

---

**End of README**

