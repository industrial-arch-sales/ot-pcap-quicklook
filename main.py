#!/usr/bin/env python3
"""Small, dependency-free static triage for classic PCAP and text logs.

This utility is intentionally a quick-look aid. It does not decrypt traffic,
reassemble TCP streams, or replace a complete OT assessment workflow.
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


MODBUS_FUNCTIONS = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil",
    6: "Write Single Register", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
}
MODBUS_WRITES = {5, 6, 15, 16, 22, 23}


@dataclass(frozen=True)
class TcpPayload:
    source: str
    destination: str
    source_port: int
    destination_port: int
    payload: bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Quick static triage for classic PCAP files and text logs."
    )
    parser.add_argument("input", type=Path, help="Input .pcap or text log file")
    parser.add_argument("--max-packets", type=int, default=200_000,
                        help="Maximum PCAP packets to inspect (default: 200000)")
    return parser.parse_args()


def iter_pcap_packets(path: Path, maximum: int) -> Iterator[bytes]:
    """Yield frames from a classic libpcap capture; reject unsupported formats."""
    with path.open("rb") as capture:
        magic = capture.read(4)
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
            b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
            b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
            b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
        }
        if magic not in formats:
            raise ValueError("Only classic PCAP is supported (not PCAPNG).")
        endian, _ = formats[magic]
        header = capture.read(20)
        if len(header) != 20:
            raise ValueError("Truncated PCAP global header.")
        _, _, _, _, _, linktype = struct.unpack(f"{endian}HHiIII", header)
        if linktype != 1:
            raise ValueError(f"Unsupported link type {linktype}; Ethernet is required.")
        for _ in range(maximum):
            packet_header = capture.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("Truncated PCAP packet header.")
            _, _, included_length, _ = struct.unpack(f"{endian}IIII", packet_header)
            frame = capture.read(included_length)
            if len(frame) != included_length:
                raise ValueError("Truncated PCAP packet data.")
            yield frame


def tcp_payload_from_ethernet(frame: bytes) -> TcpPayload | None:
    """Extract an IPv4 TCP payload from an untagged or 802.1Q Ethernet frame."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_length = (version_ihl & 0x0F) * 4
    if ip_length < 20 or len(frame) < offset + ip_length:
        return None
    if frame[offset + 9] != 6:  # TCP
        return None
    total_length = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
    ip_end = min(len(frame), offset + total_length)
    tcp_start = offset + ip_length
    if ip_end < tcp_start + 20:
        return None
    source_port, destination_port = struct.unpack("!HH", frame[tcp_start:tcp_start + 4])
    tcp_length = (frame[tcp_start + 12] >> 4) * 4
    if tcp_length < 20 or tcp_start + tcp_length > ip_end:
        return None
    return TcpPayload(
        str(ipaddress.IPv4Address(frame[offset + 12:offset + 16])),
        str(ipaddress.IPv4Address(frame[offset + 16:offset + 20])),
        source_port,
        destination_port,
        frame[tcp_start + tcp_length:ip_end],
    )


def inspect_modbus(payload: bytes) -> tuple[int, int] | None:
    """Return (function_code, unit_id) for a complete Modbus TCP ADU."""
    if len(payload) < 8:
        return None
    protocol_id, length = struct.unpack("!HH", payload[2:6])
    if protocol_id != 0 or length < 2 or len(payload) < 6 + length:
        return None
    return payload[7], payload[6]


def mqtt_packet_type(payload: bytes) -> str | None:
    if not payload:
        return None
    names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
             8: "SUBSCRIBE", 9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP",
             14: "DISCONNECT"}
    return names.get(payload[0] >> 4, "OTHER")


def inspect_pcap(path: Path, maximum: int) -> None:
    packet_count = tcp_count = 0
    conversations: Counter[str] = Counter()
    modbus_functions: Counter[str] = Counter()
    modbus_writes: Counter[str] = Counter()
    mqtt_types: Counter[str] = Counter()
    for frame in iter_pcap_packets(path, maximum):
        packet_count += 1
        tcp = tcp_payload_from_ethernet(frame)
        if tcp is None:
            continue
        tcp_count += 1
        conversations[f"{tcp.source}:{tcp.source_port} -> {tcp.destination}:{tcp.destination_port}"] += 1
        modbus = inspect_modbus(tcp.payload)
        if modbus:
            function, unit = modbus
            label = MODBUS_FUNCTIONS.get(function & 0x7F, f"Function 0x{function:02X}")
            if function & 0x80:
                label += " (exception response)"
            key = f"unit {unit}: {label}"
            modbus_functions[key] += 1
            if (function & 0x7F) in MODBUS_WRITES and not function & 0x80:
                modbus_writes[key] += 1
        if tcp.source_port == 1883 or tcp.destination_port == 1883:
            kind = mqtt_packet_type(tcp.payload)
            if kind:
                mqtt_types[kind] += 1

    print(f"Input: {path}")
    print(f"PCAP packets inspected: {packet_count:,} | IPv4/TCP frames: {tcp_count:,}")
    print_counter("Top TCP conversations", conversations)
    print_counter("Modbus function codes", modbus_functions)
    print_counter("Potential Modbus write commands", modbus_writes)
    print_counter("MQTT packet types (port 1883)", mqtt_types)
    print("\nNote: results are static packet observations; TCP stream reassembly is not performed.")


def inspect_log(path: Path) -> None:
    lines = 0
    hits: Counter[str] = Counter()
    markers = {"modbus": "Modbus", "mqtt": "MQTT", "iec 62443": "IEC 62443",
               "write": "write", "exception": "exception", "pcap": "PCAP"}
    with path.open("r", encoding="utf-8", errors="replace") as log:
        for line in log:
            lines += 1
            folded = line.casefold()
            for marker, label in markers.items():
                if marker in folded:
                    hits[label] += 1
    print(f"Input: {path}\nLog lines inspected: {lines:,}")
    print_counter("Keyword occurrences", hits)
    print("\nNote: text logs are searched by keyword only; this is not a SIEM parser.")


def print_counter(title: str, counter: Counter[str], limit: int = 10) -> None:
    print(f"\n{title}")
    if not counter:
        print("  None observed")
        return
    for label, count in counter.most_common(limit):
        print(f"  {count:>6}  {label}")


def main() -> int:
    args = parse_args()
    if args.max_packets < 1:
        print("--max-packets must be at least 1.", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"File not found: {args.input}", file=sys.stderr)
        return 2
    try:
        if args.input.suffix.casefold() in {".pcap", ".cap"}:
            inspect_pcap(args.input, args.max_packets)
        else:
            inspect_log(args.input)
    except (OSError, ValueError, struct.error) as error:
        print(f"Unable to inspect input: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
