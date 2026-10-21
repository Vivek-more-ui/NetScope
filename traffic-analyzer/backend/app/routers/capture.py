"""Live capture router.

OWNER: CaptureBridge.

Implement the routes described in `traffic-analyzer/docs/API.md` section 2 using the
helpers in `app/services/tshark.py`:

* GET  /status      -> CaptureStatus
* GET  /interfaces  -> CaptureInterfacesResponse
* POST /start       -> CaptureStartRequest -> CaptureStartResponse (202)
* POST /stop        -> CaptureStopRequest  -> CaptureStopResponse (200)

Rules:
* Exactly one capture may run at a time; a second start returns 409 conflict.
* The TShark child process must be terminated on stop and on application shutdown.
* If TShark is missing, start/stop return 503 unavailable with a clear message.
* A stopped capture is analysed automatically and the resulting analysis_id is returned.
"""

from fastapi import APIRouter

router = APIRouter()
