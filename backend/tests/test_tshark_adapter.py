from backend.app.services.tshark_adapter import extract_packets_json


def test_tshark_packet_extraction(synthetic_pcap_file):
    """
    Tests TShark adapter packet extraction on genuine synthetic PCAP fixture.
    Verifies that TShark returns parsed packet frames.
    """
    packets = extract_packets_json(synthetic_pcap_file)
    assert isinstance(packets, list)
    assert len(packets) == 5  # Our synthetic fixture contains 5 packets

    # Inspect first packet fields
    first_pkt = packets[0]["_source"]["layers"]
    assert "frame.number" in first_pkt
    assert "tcp.stream" in first_pkt
    assert first_pkt["tcp.dstport"][0] == "25"  # SMTP port
