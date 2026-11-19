#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
  echo "usage: $0 LOCAL_MIXED_PORT REMOTE_SSH_IPV4 REMOTE_DNS_IPV4" >&2
  exit 2
fi

# Verify the running UU outbound through its local mixed inbound.
python3 - "$@" <<'PY'
import asyncio
import socket
import struct
import sys

local = ("127.0.0.1", int(sys.argv[1]))
ssh_host, dns_host = sys.argv[2:]


async def address(reader, kind):
    """Read a SOCKS address, e.g. an IPv4 reply returns dotted decimal."""
    if kind == 1:
        return socket.inet_ntoa(await reader.readexactly(4))
    if kind == 4:
        return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    if kind != 3:
        raise ValueError(f"invalid SOCKS address type {kind}")
    size, = await reader.readexactly(1)
    return (await reader.readexactly(size)).decode()


async def socks(command, host, port):
    """Open one SOCKS5 operation, e.g. CONNECT to the remote SSH port."""
    reader, writer = await asyncio.open_connection(*local)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 did not accept no-auth test client")
        writer.write(bytes((5, command, 0, 1)) + socket.inet_aton(host) + struct.pack("!H", port))
        await writer.drain()
        version, code, _, kind = await reader.readexactly(4)
        if (version, code) != (5, 0):
            raise RuntimeError(f"SOCKS5 command failed: {code}")
        bind_ip = await address(reader, kind)
        bind_port, = struct.unpack("!H", await reader.readexactly(2))
        return reader, writer, bind_ip, bind_port
    except BaseException:
        writer.close()
        raise


async def ssh_banner():
    """Confirm TCP forwarding with the SSH greeting, without opening an SSH login."""
    reader, writer, _, _ = await socks(1, ssh_host, 22)
    try:
        if not (await reader.readline()).startswith(b"SSH-2.0-"):
            raise RuntimeError("remote SSH banner missing")
    finally:
        writer.close()


async def udp_dns():
    """Confirm UoT packet delivery by matching a DNS response to its query."""
    _, writer, bind_ip, bind_port = await socks(3, "0.0.0.0", 0)
    peer = (local[0] if bind_ip == "0.0.0.0" else bind_ip, bind_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        header = b"\x00\x00\x00\x01" + socket.inet_aton(dns_host) + struct.pack("!H", 53)
        request = struct.pack("!HHHHHH", 23456, 0x0100, 1, 0, 0, 0)
        request += b"\x07example\x03com\x00\x00\x01\x00\x01"
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, peer)
        await loop.sock_sendall(sock, header + request)
        reply = await loop.sock_recv(sock, 4096)
        if len(reply) < 22 or reply[10:12] != struct.pack("!H", 23456) or not reply[12] & 0x80:
            raise RuntimeError("UDP DNS reply does not match the query")
    finally:
        sock.close()
        writer.close()


async def main():
    """Exercise concurrent TCP flows and a UDP flow on one configured outbound."""
    await asyncio.wait_for(asyncio.gather(*(ssh_banner() for _ in range(4))), 45)
    await asyncio.wait_for(udp_dns(), 12)
    print("UU port mapping passed: 4 TCP SSH banners and 1 UDP DNS reply")


asyncio.run(main())
PY
