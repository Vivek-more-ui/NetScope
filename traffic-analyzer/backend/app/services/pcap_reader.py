"""Pure-Python PCAP and PCAPNG capture file reader.

Reads capture files into a sequence of ``RawFrame`` objects without requiring
TShark, tcpdump, or external C extensions.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List

PCAP_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"  # Little-endian, microseconds
PCAP_MAGIC_BE_US = b"\xa1\xb2\xc3\xd4"  # Big-endian, microseconds
PCAP_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"  # Little-endian, nanoseconds
PCAP_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"  # Big-endian, nanoseconds
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"      # Section Header Block


@dataclass
class RawFrame:
    frame_number: int          # 1-based
    timestamp_epoch: float     # seconds
    captured_length: int       # bytes actually stored in the file
    original_length: int       # bytes on the wire
    link_type: int             # 1 = Ethernet
    data: bytes                # the stored bytes


class PcapReaderError(RuntimeError):
    """Raised when a capture file format is malformed or unsupported."""


def read_capture(path: str | Path) -> list[RawFrame]:
    """Read all packets from a PCAP or PCAPNG file into a list of RawFrame objects."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {file_path}")

    with file_path.open("rb") as handle:
        magic = handle.read(4)
        if not magic:
            return []

        if magic in (PCAP_MAGIC_LE_US, PCAP_MAGIC_BE_US, PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS):
            return _read_pcap(handle, magic)
        elif magic == PCAPNG_MAGIC:
            return _read_pcapng(handle)
        else:
            raise PcapReaderError(f"Unsupported capture magic: {magic.hex()}")


def _read_pcap(handle: BinaryIO, magic: bytes) -> list[RawFrame]:
    endian = "<" if magic in (PCAP_MAGIC_LE_US, PCAP_MAGIC_LE_NS) else ">"
    is_nano = magic in (PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS)
    time_divisor = 1_000_000_000.0 if is_nano else 1_000_000.0

    rest_hdr = handle.read(20)
    if len(rest_hdr) < 20:
        return []

    version_major, version_minor, thiszone, sigfigs, snaplen, link_type = struct.unpack(
        endian + "HHIIII", rest_hdr
    )

    frames: list[RawFrame] = []
    frame_number = 1

    while True:
        pkt_hdr = handle.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_subsec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_hdr)
        if incl_len > 64 * 1024 * 1024:
            break

        data = handle.read(incl_len)
        if len(data) < incl_len:
            break

        epoch = ts_sec + (ts_subsec / time_divisor)
        frames.append(
            RawFrame(
                frame_number=frame_number,
                timestamp_epoch=epoch,
                captured_length=incl_len,
                original_length=orig_len,
                link_type=link_type,
                data=data,
            )
        )
        frame_number += 1

    return frames


def _read_pcapng(handle: BinaryIO) -> list[RawFrame]:
    # Section Header Block read first 4 bytes were 0x0a0d0d0a
    block_hdr = handle.read(4)
    if len(block_hdr) < 4:
        return []
    total_len = struct.unpack("<I", block_hdr)[0]
    # Read byte order magic to determine endianness
    bom = handle.read(4)
    if bom == b"\x4d\x3c\x2b\x1a":
        endian = ">"
    else:
        endian = "<"

    # Seek back to beginning of section header
    handle.seek(0)

    frames: list[RawFrame] = []
    frame_number = 1
    # Interface link types and resolution (in power of 10, default 6 = 1e-6 us)
    interfaces: list[dict] = []

    while True:
        hdr = handle.read(8)
        if len(hdr) < 8:
            break
        block_type, block_len = struct.unpack(endian + "II", hdr)
        if block_len < 12 or block_len > 64 * 1024 * 1024:
            break

        body_len = block_len - 12
        body = handle.read(body_len)
        trailer = handle.read(4)
        if len(body) < body_len or len(trailer) < 4:
            break

        if block_type == 0x0A0D0D0A:  # Section Header Block
            if len(body) >= 4:
                bom = body[:4]
                endian = ">" if bom == b"\x4d\x3c\x2b\x1a" else "<"
            interfaces.clear()

        elif block_type == 0x00000001:  # Interface Description Block
            if len(body) >= 4:
                link_type = struct.unpack(endian + "H", body[:2])[0]
                tsresol = 6  # default 10^-6 (microsecond)
                # Parse options if any (body[8:])
                opt_offset = 8
                while opt_offset + 4 <= len(body):
                    opt_code, opt_len = struct.unpack(endian + "HH", body[opt_offset : opt_offset + 4])
                    opt_offset += 4
                    if opt_code == 0:  # opt_endofopt
                        break
                    if opt_code == 9 and opt_len >= 1 and opt_offset < len(body):  # if_tsresol
                        res_val = body[opt_offset]
                        if res_val & 0x80:
                            # 2^-(res_val & 0x7f)
                            tsresol = 2 ** (res_val & 0x7F)
                        else:
                            tsresol = 10**res_val
                    opt_offset += (opt_len + 3) & ~3
                interfaces.append({"link_type": link_type, "tsresol": tsresol})

        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
                ts_raw = (ts_high << 32) | ts_low
                res = interfaces[if_id]["tsresol"] if if_id < len(interfaces) else 1_000_000
                divisor = res if isinstance(res, (int, float)) and res > 100 else (10**res if isinstance(res, int) else 1_000_000.0)
                epoch = ts_raw / float(divisor)
                pkt_data = body[20 : 20 + cap_len]
                ltype = interfaces[if_id]["link_type"] if if_id < len(interfaces) else 1
                frames.append(
                    RawFrame(
                        frame_number=frame_number,
                        timestamp_epoch=epoch,
                        captured_length=orig_len,  # wire length
                        original_length=orig_len,
                        link_type=ltype,
                        data=pkt_data,
                    )
                )
                frame_number += 1

        elif block_type == 0x00000003:  # Simple Packet Block
            if len(body) >= 4:
                orig_len = struct.unpack(endian + "I", body[:4])[0]
                pkt_data = body[4 : 4 + (block_len - 16)]
                ltype = interfaces[0]["link_type"] if interfaces else 1
                frames.append(
                    RawFrame(
                        frame_number=frame_number,
                        timestamp_epoch=0.0,
                        captured_length=orig_len,
                        original_length=orig_len,
                        link_type=ltype,
                        data=pkt_data,
                    )
                )
                frame_number += 1

    return frames
