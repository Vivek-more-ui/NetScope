"""Live capture router.

Provides capture status, interface discovery, start capture, and stop capture endpoints.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException

from ..config import CAPTURES_DIR, DUMPCAP_PATH, TSHARK_PATH, ensure_directories
from ..models.packet import (
    CaptureInterface,
    CaptureInterfacesResponse,
    CaptureStartRequest,
    CaptureStartResponse,
    CaptureStatus,
    CaptureStopRequest,
    CaptureStopResponse,
)
from ..services import pipeline, tshark
from ..services.pipeline import CaptureNotReadable
from ..services.store import Analysis, store, utc_now_iso

router = APIRouter()


class CaptureSession:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running: bool = False
        self.capture_id: Optional[str] = None
        self.interface: Optional[str] = None
        self.started_at: Optional[str] = None
        self.stopped_at: Optional[str] = None
        self.capture_file: Optional[Path] = None
        self.filter: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None
        self.log_file = None
        self.last_error: Optional[str] = None
        self.analysis_id: Optional[str] = None
        self.packets_captured: int = 0


_SESSION = CaptureSession()


@router.get("/status", response_model=CaptureStatus)
async def get_status() -> CaptureStatus:
    available = tshark.is_available()
    with _SESSION.lock:
        if _SESSION.running and _SESSION.process:
            ret = _SESSION.process.poll()
            if ret is not None:
                _SESSION.running = False
                _SESSION.stopped_at = utc_now_iso()
                if ret != 0:
                    _SESSION.last_error = f"Capture process terminated with exit code {ret}"

        # Count packets if capture file exists
        p_count = _SESSION.packets_captured
        if _SESSION.capture_file and _SESSION.capture_file.exists():
            counted = tshark.count_packets(_SESSION.capture_file)
            if counted is not None:
                p_count = counted
                _SESSION.packets_captured = counted

        return CaptureStatus(
            running=_SESSION.running,
            capture_id=_SESSION.capture_id,
            interface=_SESSION.interface,
            started_at=_SESSION.started_at,
            stopped_at=_SESSION.stopped_at,
            packets_captured=p_count,
            packets_filtered=0,
            capture_file=str(_SESSION.capture_file) if _SESSION.capture_file else None,
            filter=_SESSION.filter,
            last_error=_SESSION.last_error,
            tshark_available=available,
        )


def _discover_interfaces() -> tuple[str, bool, list[CaptureInterface]]:
    """Return (source, tshark_available, interfaces).

    Prefers TShark's own listing; when TShark cannot list interfaces (missing binary or
    permission problem) the system device list is used as a fallback.
    """
    available = tshark.is_available()
    source: str = "none"
    if available:
        source = "tshark"
    elif DUMPCAP_PATH:
        source = "dumpcap"

    raw_ifaces = tshark.list_interfaces()
    ifaces: list[CaptureInterface] = []
    for item in raw_ifaces:
        ifaces.append(
            CaptureInterface(
                index=item.get("index"),
                name=item.get("name", ""),
                description=item.get("friendly") or item.get("description"),
                is_loopback=item.get("is_loopback", False) or item.get("name") in ("lo", "lo0"),
                addresses=item.get("addresses", []),
            )
        )

    # If tshark failed to list interfaces due to permissions, fallback to system sysfs
    if not ifaces and Path("/sys/class/net").is_dir():
        try:
            for idx, dev in enumerate(sorted(os.listdir("/sys/class/net")), start=1):
                is_lo = (dev == "lo")
                ifaces.append(
                    CaptureInterface(
                        index=idx,
                        name=dev,
                        description=f"System network device ({dev})",
                        is_loopback=is_lo,
                        addresses=[],
                    )
                )
        except Exception:
            pass

    return source, available, ifaces


@router.get("/interfaces", response_model=CaptureInterfacesResponse)
async def get_interfaces() -> CaptureInterfacesResponse:
    source, available, ifaces = _discover_interfaces()
    return CaptureInterfacesResponse(
        source=source,  # type: ignore[arg-type]
        tshark_available=available,
        interfaces=ifaces,
    )


@router.post("/start", response_model=CaptureStartResponse, status_code=202)
async def start_capture(payload: CaptureStartRequest) -> CaptureStartResponse:
    ensure_directories()
    # Check binary availability
    tool_path = TSHARK_PATH or DUMPCAP_PATH
    if not tool_path:
        raise HTTPException(
            status_code=503,
            detail={"message": "TShark or dumpcap is not installed on this system. Live capture is unavailable."},
        )

    # Validate filter against shell metacharacters
    shell_metas = (";", "&", "|", "$", "`", "\n", "\r")
    if payload.filter and any(char in payload.filter for char in shell_metas):
        raise HTTPException(
            status_code=400,
            detail={"message": "Capture filter contains forbidden shell metacharacters.", "filter": payload.filter},
        )

    # Validate the interface against the interfaces this host actually offers.
    _, _, known_interfaces = _discover_interfaces()
    known_names = {item.name for item in known_interfaces}
    if known_names and payload.interface not in known_names:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Unknown capture interface '{payload.interface}'.",
                "interface": payload.interface,
                "available_interfaces": sorted(known_names),
            },
        )

    with _SESSION.lock:
        if _SESSION.running and _SESSION.process and _SESSION.process.poll() is None:
            raise HTTPException(
                status_code=409,
                detail={"message": f"A capture is already running with ID '{_SESSION.capture_id}'."},
            )

        c_id = uuid.uuid4().hex
        started_at = utc_now_iso()
        cap_file = CAPTURES_DIR / f"capture-{c_id}.pcapng"
        log_file_path = CAPTURES_DIR / f"capture-{c_id}.log"
        log_handle = open(log_file_path, "w", encoding="utf-8")

        cmd = [tool_path, "-i", payload.interface, "-w", str(cap_file)]
        if payload.duration_seconds:
            cmd.extend(["-a", f"duration:{payload.duration_seconds}"])
        if payload.filter:
            cmd.extend(["-f", payload.filter])

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
            )
        except OSError as exc:
            log_handle.close()
            raise HTTPException(
                status_code=503,
                detail={"message": f"Failed to launch capture tool: {exc}"},
            ) from exc

        # Give it a short moment to ensure it didn't immediately fail on permission
        time.sleep(0.1)
        ret = process.poll()
        if ret is not None and ret != 0:
            log_handle.close()
            err_msg = "Capture process exited immediately."
            if log_file_path.exists():
                err_text = log_file_path.read_text(encoding="utf-8", errors="ignore").strip()
                if err_text:
                    err_msg = f"Capture failed: {err_text}"
            raise HTTPException(
                status_code=503,
                detail={"message": err_msg},
            )

        _SESSION.running = True
        _SESSION.capture_id = c_id
        _SESSION.interface = payload.interface
        _SESSION.started_at = started_at
        _SESSION.stopped_at = None
        _SESSION.capture_file = cap_file
        _SESSION.filter = payload.filter
        _SESSION.process = process
        _SESSION.log_file = log_handle
        _SESSION.last_error = None
        _SESSION.analysis_id = None
        _SESSION.packets_captured = 0

        return CaptureStartResponse(
            status="running",
            capture_id=c_id,
            interface=payload.interface,
            started_at=started_at,
            filter=payload.filter,
            message=f"Capture started on '{payload.interface}'.",
        )


@router.post("/stop", response_model=CaptureStopResponse, status_code=200)
async def stop_capture(payload: Optional[CaptureStopRequest] = None) -> CaptureStopResponse:
    with _SESSION.lock:
        if not _SESSION.running and not _SESSION.capture_id:
            raise HTTPException(
                status_code=409,
                detail={"message": "No capture is currently active."},
            )

        c_id = _SESSION.capture_id or "unknown"
        proc = _SESSION.process
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if _SESSION.log_file and not _SESSION.log_file.closed:
            _SESSION.log_file.close()

        _SESSION.running = False
        _SESSION.stopped_at = utc_now_iso()

        cap_file = _SESSION.capture_file
        analysis_id = None
        p_count = 0

        if cap_file and cap_file.exists() and cap_file.stat().st_size > 0:
            try:
                load_res = pipeline.load_any(cap_file)
                p_count = len(load_res.packets)
                _SESSION.packets_captured = p_count

                analysis_id = uuid.uuid4().hex
                created_at = utc_now_iso()
                analysis = Analysis(
                    analysis_id=analysis_id,
                    source_file=cap_file.name,
                    source_kind="live",
                    created_at=created_at,
                    packets=load_res.packets,
                    warnings=load_res.warnings,
                    source_path=str(cap_file),
                )
                store.put(analysis)
                _SESSION.analysis_id = analysis_id
            except Exception as exc:
                _SESSION.last_error = f"Analysis of capture file failed: {exc}"

        return CaptureStopResponse(
            status="stopped",
            capture_id=c_id,
            packets_captured=p_count,
            capture_file=str(cap_file) if cap_file else None,
            analysis_id=analysis_id,
            message="Capture stopped and analysed." if analysis_id else "Capture stopped.",
        )
