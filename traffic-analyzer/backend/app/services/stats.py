"""Traffic statistics engine and filtering service.

Calculates capture summaries, protocol and host distributions, and provides
server-side filtering and sorting for packet explorer.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from ..models.packet import (
    CaptureSummary,
    ConversationEntry,
    HostEntry,
    HttpStatusCount,
    NormalizedPacket,
    ProtocolCount,
)


def _format_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def protocol_counts(packets: list[NormalizedPacket]) -> list[ProtocolCount]:
    """Transport-layer protocol distribution.

    Every packet contributes to exactly one transport protocol, so the packet counts
    sum to the total number of packets. This is the *layer below* the application
    protocol; use :func:`application_protocol_counts` for the application view.
    """
    total = len(packets)
    if total == 0:
        return []

    packet_counter: Counter[str] = Counter()
    byte_counter: Counter[str] = Counter()

    for p in packets:
        proto = p.transport_protocol or "OTHER"
        packet_counter[proto] += 1
        byte_counter[proto] += p.captured_frame_length

    result: list[ProtocolCount] = []
    # Sort by packet count descending
    for proto, count in packet_counter.most_common():
        pct = round((count * 100.0) / total, 2)
        result.append(
            ProtocolCount(
                protocol=proto,
                packets=count,
                bytes=byte_counter[proto],
                percentage=pct,
            )
        )
    return result


def application_protocol_counts(packets: list[NormalizedPacket]) -> list[ProtocolCount]:
    """Application-layer protocol distribution.

    Mutually exclusive: every packet is counted under the application protocol that
    was actually observed for it (falling back to its transport protocol, then to
    ``OTHER``), so the counts sum to the total number of packets. Encrypted traffic is
    reported as ``TLS``/``QUIC`` and never as ``HTTP``.
    """
    total = len(packets)
    if total == 0:
        return []

    packet_counter: Counter[str] = Counter()
    byte_counter: Counter[str] = Counter()

    for p in packets:
        proto = p.application_protocol or p.transport_protocol or "OTHER"
        packet_counter[proto] += 1
        byte_counter[proto] += p.captured_frame_length

    result: list[ProtocolCount] = []
    # Sort by packet count descending
    for proto, count in packet_counter.most_common():
        pct = round((count * 100.0) / total, 2)
        result.append(
            ProtocolCount(
                protocol=proto,
                packets=count,
                bytes=byte_counter[proto],
                percentage=pct,
            )
        )
    return result


def host_counts(packets: list[NormalizedPacket]) -> list[HostEntry]:
    """Calculate host statistics for communicating IP endpoints."""
    sent_bytes: Counter[str] = Counter()
    recv_bytes: Counter[str] = Counter()
    sent_packets: Counter[str] = Counter()
    host_protos: defaultdict[str, set[str]] = defaultdict(set)

    for p in packets:
        length = p.captured_frame_length
        proto = p.application_protocol or p.transport_protocol
        if p.source_ip:
            sent_packets[p.source_ip] += 1
            sent_bytes[p.source_ip] += length
            if proto:
                host_protos[p.source_ip].add(proto)
        if p.destination_ip:
            recv_bytes[p.destination_ip] += length
            if proto:
                host_protos[p.destination_ip].add(proto)

    all_ips = set(sent_bytes.keys()) | set(recv_bytes.keys())
    entries: list[HostEntry] = []
    for ip in all_ips:
        s_bytes = sent_bytes[ip]
        r_bytes = recv_bytes[ip]
        p_count = sent_packets[ip]
        entries.append(
            HostEntry(
                ip=ip,
                packets=p_count,
                bytes_sent=s_bytes,
                bytes_received=r_bytes,
                total_bytes=s_bytes + r_bytes,
                protocols=sorted(list(host_protos[ip])),
            )
        )

    entries.sort(key=lambda h: (-h.total_bytes, h.ip))
    return entries


def conversation_counts(packets: list[NormalizedPacket]) -> list[ConversationEntry]:
    conv_packets: Counter[tuple] = Counter()
    conv_bytes: Counter[tuple] = Counter()

    for p in packets:
        if not (p.source_ip and p.destination_ip):
            continue
        key = (p.source_ip, p.source_port, p.destination_ip, p.destination_port, p.transport_protocol)
        conv_packets[key] += 1
        conv_bytes[key] += p.captured_frame_length

    results: list[ConversationEntry] = []
    for key, count in conv_packets.most_common():
        src_ip, src_p, dst_ip, dst_p, trans = key
        results.append(
            ConversationEntry(
                source_ip=src_ip,
                source_port=src_p,
                destination_ip=dst_ip,
                destination_port=dst_p,
                transport_protocol=trans,
                packets=count,
                bytes=conv_bytes[key],
            )
        )
    return results


def build_summary(
    analysis_id: str,
    source_file: str,
    source_kind: str,
    packets: list[NormalizedPacket],
    warnings: list[str],
    created_at: Optional[str] = None,
) -> CaptureSummary:
    total_packets = len(packets)
    total_bytes = sum(p.captured_frame_length for p in packets)

    first_ts = packets[0].timestamp if packets else None
    last_ts = packets[-1].timestamp if packets else None

    duration = 0.0
    if len(packets) >= 2:
        duration = max(0.0, packets[-1].timestamp_epoch - packets[0].timestamp_epoch)

    unique_ips = set()
    for p in packets:
        if p.source_ip:
            unique_ips.add(p.source_ip)
        if p.destination_ip:
            unique_ips.add(p.destination_ip)

    enc_count = sum(1 for p in packets if p.is_encrypted)
    req_count = sum(1 for p in packets if p.http_method is not None)
    res_count = sum(1 for p in packets if p.http_status_code is not None)

    protos = protocol_counts(packets)
    app_protos = application_protocol_counts(packets)
    hosts = host_counts(packets)
    convs = conversation_counts(packets)

    # HTTP status code counts
    status_counter: Counter[int] = Counter()
    for p in packets:
        if p.http_status_code is not None:
            status_counter[p.http_status_code] += 1
    http_statuses: list[HttpStatusCount] = []
    if res_count > 0:
        for code, count in status_counter.most_common():
            http_statuses.append(
                HttpStatusCount(
                    status_code=code,
                    packets=count,
                    percentage=round(count * 100.0 / res_count, 2),
                )
            )

    return CaptureSummary(
        analysis_id=analysis_id,
        source_file=source_file,
        source_kind=source_kind,
        created_at=created_at or _format_utc_now(),
        packet_count=total_packets,
        total_bytes=total_bytes,
        duration_seconds=duration,
        first_timestamp=first_ts,
        last_timestamp=last_ts,
        unique_hosts=len(unique_ips),
        encrypted_packet_count=enc_count,
        http_request_count=req_count,
        http_response_count=res_count,
        protocol_counts=protos,
        application_protocol_counts=app_protos,
        http_status_counts=http_statuses,
        top_hosts=hosts[:10],
        conversations=convs[:10],
        warnings=list(warnings),
    )


def filter_packets(
    packets: list[NormalizedPacket],
    q: Optional[str] = None,
    protocol: Optional[str] = None,
    transport: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    min_bytes: Optional[int] = None,
    max_bytes: Optional[int] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    encrypted: Optional[bool] = None,
    order_by: str = "frame_number",
    order_dir: str = "asc",
) -> list[NormalizedPacket]:
    filtered = packets

    if q:
        needle = q.lower()
        filtered = [
            p
            for p in filtered
            if (p.source_ip and needle in p.source_ip.lower())
            or (p.destination_ip and needle in p.destination_ip.lower())
            or (p.source_port is not None and needle in str(p.source_port))
            or (p.destination_port is not None and needle in str(p.destination_port))
            or (p.transport_protocol and needle in p.transport_protocol.lower())
            or (p.application_protocol and needle in p.application_protocol.lower())
            or (p.server_name and needle in p.server_name.lower())
            or (p.http_method and needle in p.http_method.lower())
            or (p.info and needle in p.info.lower())
        ]

    if protocol:
        p_lower = protocol.lower()
        filtered = [p for p in filtered if p.application_protocol and p.application_protocol.lower() == p_lower]

    if transport:
        t_lower = transport.lower()
        filtered = [p for p in filtered if p.transport_protocol and p.transport_protocol.lower() == t_lower]

    if src_ip:
        filtered = [p for p in filtered if p.source_ip == src_ip]

    if dst_ip:
        filtered = [p for p in filtered if p.destination_ip == dst_ip]

    if src_port is not None:
        filtered = [p for p in filtered if p.source_port == src_port]

    if dst_port is not None:
        filtered = [p for p in filtered if p.destination_port == dst_port]

    if method:
        m_lower = method.lower()
        filtered = [p for p in filtered if p.http_method and p.http_method.lower() == m_lower]

    if status_code is not None:
        filtered = [p for p in filtered if p.http_status_code == status_code]

    if min_bytes is not None:
        filtered = [p for p in filtered if p.captured_frame_length >= min_bytes]

    if max_bytes is not None:
        filtered = [p for p in filtered if p.captured_frame_length <= max_bytes]

    if start:
        filtered = [p for p in filtered if p.timestamp >= start]

    if end:
        filtered = [p for p in filtered if p.timestamp <= end]

    if encrypted is not None:
        filtered = [p for p in filtered if p.is_encrypted == encrypted]

    # Ordering
    reverse = (order_dir.lower() == "desc")
    valid_sort_keys = {
        "frame_number": lambda p: p.frame_number,
        "timestamp": lambda p: p.timestamp_epoch,
        "captured_frame_length": lambda p: p.captured_frame_length,
        "source_ip": lambda p: p.source_ip or "",
        "destination_ip": lambda p: p.destination_ip or "",
    }
    sort_key = valid_sort_keys.get(order_by, lambda p: p.frame_number)
    filtered = sorted(filtered, key=sort_key, reverse=reverse)

    return filtered
