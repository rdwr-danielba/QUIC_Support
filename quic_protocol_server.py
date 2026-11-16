
import asyncio
import argparse

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3_ALPN


async def main(ip, port):
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN
    )

    configuration.load_cert_chain(
        certfile="quic.crt",
        keyfile="quic.key"
    )

    await serve(
        ip,
        port,
        configuration=configuration
    )

    print(f"QUIC server listening on {ip}:{port}/UDP")

    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC Server")

    parser.add_argument("--ip", required=True, help="IP address to listen on")
    parser.add_argument("--port", type=int, default=443, help="Listening UDP port (default: 443)")

    args = parser.parse_args()

    asyncio.run(main(args.ip, args.port))
