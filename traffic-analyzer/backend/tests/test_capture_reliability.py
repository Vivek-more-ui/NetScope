"""Regression tests for the availability and robustness of the capture endpoints.

The failure this file guards against: the API answered HTTP 500 for
``/api/capture/status``, ``/api/capture/interfaces`` and the analysis routes, which
made the whole application look broken even though the page itself loaded.

The root cause was environmental (the backend process was not running, so the dev
proxy turned a refused connection into a 500), and the hardening below makes sure a
failing helper can never turn a capture endpoint into a 500 again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import config
from app.routers import capture as capture_router
from app.services import tshark

ABSOLUTE_PATH = re.compile(r"(/home/|/tmp/|/root/|/var/|/usr/|C:\\\\)")


class TestCaptureStatusNeverFails:
    def test_status_is_served_even_when_the_packet_counter_breaks(self, client, monkeypatch):
        def explode(_path):
            raise RuntimeError("tshark exploded")

        monkeypatch.setattr(capture_router.tshark, "count_packets", explode)
        response = client.get("/api/capture/status")
        assert response.status_code == 200, response.text
        assert response.json()["running"] is False

    def test_status_is_served_when_the_tool_probe_breaks(self, client, monkeypatch):
        def explode():
            raise RuntimeError("probe failed")

        monkeypatch.setattr(capture_router.tshark, "is_available", explode)
        response = client.get("/api/capture/status")
        assert response.status_code == 200, response.text
        assert response.json()["tshark_available"] is False

    def test_status_does_not_leak_absolute_paths(self, client, monkeypatch):
        monkeypatch.setattr(
            capture_router._SESSION, "capture_file", config.CAPTURES_DIR / "capture-xyz.pcapng"
        )
        response = client.get("/api/capture/status")
        assert response.status_code == 200
        assert response.json()["capture_file"] == "capture-xyz.pcapng"
        assert ABSOLUTE_PATH.search(response.text) is None


class TestInterfaceListingNeverFails:
    def test_interfaces_are_served_when_the_listing_breaks(self, client, monkeypatch):
        def explode():
            raise RuntimeError("no permissions")

        monkeypatch.setattr(capture_router.tshark, "list_interfaces", explode)
        response = client.get("/api/capture/interfaces")
        assert response.status_code == 200, response.text
        body = response.json()
        # The route falls back to the system device list instead of failing, and it
        # explains what happened.
        assert isinstance(body["interfaces"], list)
        assert body["message"], "an explanation must be returned when the listing failed"

    def test_interfaces_are_served_without_tshark(self, client, monkeypatch):
        monkeypatch.setattr(capture_router.tshark, "is_available", lambda: False)
        monkeypatch.setattr(capture_router.tshark, "list_interfaces", list)
        response = client.get("/api/capture/interfaces")
        assert response.status_code == 200, response.text
        assert response.json()["tshark_available"] is False

    def test_interfaces_expose_a_beginner_friendly_message(self, client, monkeypatch):
        monkeypatch.setattr(capture_router.tshark, "list_interfaces", lambda: [])
        monkeypatch.setattr(capture_router, "DUMPCAP_PATH", None)
        response = client.get("/api/capture/interfaces")
        body = response.json()
        if body["interfaces"]:
            assert body["message"] is None
        else:
            assert body["message"] and "capture" in body["message"].lower()


class TestStartAndStop:
    def test_start_without_a_capture_tool_is_503_with_advice(self, client, monkeypatch):
        monkeypatch.setattr(capture_router, "TSHARK_PATH", None)
        monkeypatch.setattr(capture_router, "DUMPCAP_PATH", None)
        response = client.post("/api/capture/start", json={"interface": "lo"})
        assert response.status_code == 503, response.text
        body = response.json()
        assert body["error"]["code"] == "unavailable"
        assert "TShark" in body["error"]["message"]

    def test_start_rejects_a_shell_metacharacter_filter(self, client):
        response = client.post(
            "/api/capture/start", json={"interface": "lo", "filter": "tcp port 80; rm -rf /"}
        )
        assert response.status_code == 400, response.text
        assert "shell metacharacters" in response.json()["error"]["message"]

    def test_start_rejects_an_unknown_interface(self, client):
        response = client.post("/api/capture/start", json={"interface": "definitely-not-real"})
        assert response.status_code == 400, response.text
        assert "Unknown capture interface" in response.json()["error"]["message"]

    def test_stop_without_a_running_capture_is_409(self, client):
        response = client.post("/api/capture/stop", json={})
        assert response.status_code == 409, response.text

    def test_stop_reports_a_failed_analysis_without_failing_the_request(self, client, monkeypatch):
        config.ensure_directories()
        capture_file = config.CAPTURES_DIR / "capture-abc.pcapng"
        capture_file.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)

        session = capture_router._SESSION
        monkeypatch.setattr(session, "capture_id", "abc123")
        monkeypatch.setattr(session, "running", False)
        monkeypatch.setattr(session, "capture_file", capture_file)
        monkeypatch.setattr(session, "log_file", None)

        def explode(_path):
            raise RuntimeError("reader failed")

        monkeypatch.setattr(capture_router.pipeline, "load_any", explode)
        response = client.post("/api/capture/stop", json={})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "stopped"
        assert body["analysis_id"] is None
        assert body["error"], "the failure must be reported honestly"
        assert ABSOLUTE_PATH.search(response.text) is None
        capture_file.unlink(missing_ok=True)


class TestSampleCaptures:
    """The "Try sample" path: a beginner must be able to see the full workflow."""

    def test_samples_are_listed_with_a_description(self, client):
        response = client.get("/api/analysis/samples")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["count"] == len(body["samples"])
        assert body["count"] >= 1
        for sample in body["samples"]:
            assert sample["name"]
            assert sample["description"]
            assert sample["size_bytes"] >= 0

    def test_a_sample_can_be_analysed_with_one_call(self, client):
        samples = client.get("/api/analysis/samples").json()["samples"]
        name = samples[0]["name"]
        response = client.post(f"/api/analysis/samples/{name}")
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["source_file"] == name
        assert body["packet_count"] >= 0

        summary = client.get(f"/api/analysis/{body['analysis_id']}/summary")
        assert summary.status_code == 200
        assert summary.json()["packet_count"] == body["packet_count"]

    def test_an_unknown_sample_is_404(self, client):
        response = client.post("/api/analysis/samples/does-not-exist.pcap")
        assert response.status_code == 404, response.text

    def test_a_sample_name_cannot_escape_the_sample_folder(self, client):
        response = client.post("/api/analysis/samples/..%2F..%2Fetc%2Fpasswd")
        assert response.status_code in (400, 404), response.text
        assert ABSOLUTE_PATH.search(response.text) is None


class TestNoInternalDetailLeaks:
    def test_errors_never_contain_a_traceback(self, client):
        for path, method, payload in (
            ("/api/capture/start", "post", {"interface": "definitely-not-real"}),
            ("/api/capture/stop", "post", {}),
            ("/api/analysis/does-not-exist/summary", "get", None),
        ):
            response = (
                client.post(path, json=payload) if method == "post" else client.get(path)
            )
            assert "Traceback" not in response.text
            assert "Exception" not in response.text

    def test_upload_errors_do_not_expose_absolute_paths(self, client, tmp_path: Path):
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"not a capture at all")
        response = client.post("/api/analysis/upload", files={"file": ("bad.pcap", bad.read_bytes())})
        assert response.status_code == 400, response.text
        assert ABSOLUTE_PATH.search(response.text) is None
