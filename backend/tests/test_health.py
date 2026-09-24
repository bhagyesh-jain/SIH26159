from backend.app.core.tshark_discovery import discover_tshark_path, get_tshark_version


def test_tshark_discovery():
    """Verify that TShark discovery finds the installed Windows TShark executable."""
    path = discover_tshark_path()
    assert path is not None
    assert path.is_file()
    assert "tshark" in path.name.lower()


def test_tshark_version_check():
    """Verify that TShark version check returns valid version output."""
    available, version_str, bin_path = get_tshark_version()
    assert available is True
    assert "TShark" in version_str or "Wireshark" in version_str
    assert bin_path is not None


def test_health_api_endpoint(client):
    """Verify GET /api/v1/health returns HTTP 200 and TShark status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["tshark"]["available"] is True
    assert "TShark" in data["tshark"]["version"]
