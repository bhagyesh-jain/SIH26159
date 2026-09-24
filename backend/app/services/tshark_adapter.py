import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any
from backend.app.core.tshark_discovery import discover_tshark_path


class TSharkAdapterError(Exception):
    """Raised when TShark subprocess fails or returns non-zero status."""
    pass


def extract_packets_json(pcap_path: Path) -> List[Dict[str, Any]]:
    """
    Invokes TShark via subprocess with an array of arguments (no shell=True).
    Extracts frame, IP, TCP, stream, and protocol fields as structured JSON.
    """
    tshark_bin = discover_tshark_path()
    if not tshark_bin:
        raise TSharkAdapterError("TShark executable was not found on the system.")

    if not pcap_path.is_file():
        raise TSharkAdapterError(f"Capture file not found at path: {pcap_path}")

    # Explicit argument list — safe against shell injection vulnerabilities
    args = [
        str(tshark_bin),
        "-r", str(pcap_path),
        "-T", "json",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info"
    ]

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,  # 30-second execution cap
        )
        if not result.stdout.strip():
            return []
        
        parsed_packets = json.loads(result.stdout)
        return parsed_packets
    except subprocess.TimeoutExpired:
        raise TSharkAdapterError("TShark analysis timed out after 30 seconds.")
    except subprocess.CalledProcessError as e:
        stderr_msg = e.stderr.strip() if e.stderr else str(e)
        raise TSharkAdapterError(f"TShark execution failed: {stderr_msg}")
    except json.JSONDecodeError as e:
        raise TSharkAdapterError(f"Failed to parse TShark JSON output: {str(e)}")
