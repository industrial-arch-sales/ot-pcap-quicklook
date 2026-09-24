#!/usr/bin/env python3
"""Build the deterministic PCAP used by the README quick-start example."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


OUTPUT = Path(__file__).parents[1] / "examples" / "synthetic-modbus.pcap"


def modbus(transaction_id: int, function: int, body: bytes) -> bytes:
    """Build one Modbus TCP ADU for Unit ID 1."""
    return struct.pack("!HHHBB", transaction_id, 0, len(body) + 2, 1, function) + body


def ipv4(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def ethernet_ipv4_tcp(source: str, destination: str, source_port: int,
                      destination_port: int, sequence: int, payload: bytes) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame; checksums are not needed for parsing."""
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 20 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0, 64, 6, 0,
        ipv4(source), ipv4(destination),
    )
    tcp_header = struct.pack(
        "!HHLLBBHHH", source_port, destination_port, sequence, 0,
        0x50, 0x18, 8192, 0, 0,
    )
    return ethernet + ip_header + tcp_header + payload


def write_pcap(frames: list[bytes]) -> None:
    OUTPUT.parent.mkdir(exist_ok=True)
    with OUTPUT.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for offset, frame in enumerate(frames):
            capture.write(struct.pack("<IIII", 1_700_000_000 + offset, 0, len(frame), len(frame)))
            capture.write(frame)


def main() -> None:
    scada, plc, untrusted = "10.20.30.10", "10.20.30.50", "10.20.30.99"
    frames = [
        ethernet_ipv4_tcp(scada, plc, 43122, 502, 1, modbus(1, 3, b"\x00\x00\x00\x02")),
        ethernet_ipv4_tcp(plc, scada, 502, 43122, 1, modbus(1, 3, b"\x04\x00\x19\x00\x1a")),
        ethernet_ipv4_tcp(scada, plc, 43122, 502, 2, modbus(2, 3, b"\x00\x02\x00\x02")),
        ethernet_ipv4_tcp(plc, scada, 502, 43122, 2, modbus(2, 3, b"\x04\x00\x1b\x00\x1c")),
        ethernet_ipv4_tcp(untrusted, plc, 49152, 502, 1, modbus(7, 6, b"\x00\x64\x00\x01")),
        ethernet_ipv4_tcp(plc, untrusted, 502, 49152, 1, modbus(7, 6, b"\x00\x64\x00\x01")),
    ]
    write_pcap(frames)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
