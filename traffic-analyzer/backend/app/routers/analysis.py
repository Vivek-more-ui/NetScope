"""Analysis router.

OWNER: PacketCore.

Implement the routes described in `traffic-analyzer/docs/API.md` section 3:

* POST /upload                  -> AnalysisUploadResult (201)
* GET  /{analysis_id}/summary   -> CaptureSummary
* GET  /{analysis_id}/packets   -> PacketPage
* GET  /{analysis_id}/protocols -> ProtocolPage
* GET  /{analysis_id}/hosts     -> HostPage
* GET  /{analysis_id}/export/packets.csv   -> text/csv
* GET  /{analysis_id}/export/summary.json  -> application/json

Rules:
* Unknown analysis ids return 404 not_found using the shared error envelope.
* Packet lists are paginated (limit/offset) and support the filter parameters from the
  contract. Filtering happens server side; never return the whole array for a page.
* Uploads accept .pcap/.pcapng/.cap/.csv. Unsupported types return 415, unparsable or
  empty files return 400.
* The CSV export writes the columns in the order documented in docs/SCHEMA.md and writes
  null values as empty cells.
"""

from fastapi import APIRouter

router = APIRouter()
