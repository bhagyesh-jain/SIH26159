import re
from typing import List, Dict, Optional, Any
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import (
    UpgradeStatus, SecurityEventData, StreamLine, reassemble_stream_lines
)
from backend.app.services.protocols.tls import analyze_tls_stream

class IMAPStateMachine:
    """
    Passive, protocol-aware state machine for analyzing IMAP STARTTLS security posture
    from reassembled TCP stream observations.
    """

    def __init__(self):
        self.events: List[SecurityEventData] = []
        self.server_greeting_seen = False
        self.client_greeting_seen = False
        self.starttls_offered = False
        self.starttls_requested = False
        self.starttls_accepted = False
        self.starttls_rejected = False
        self.pending_starttls_tag: Optional[str] = None
        self.plaintext_command_after_offer = False
        self.overall_status: UpgradeStatus = UpgradeStatus.UNKNOWN

    def _redact_imap_line(self, line: str) -> str:
        """Redacts plaintext passwords in IMAP LOGIN commands."""
        # Match tag LOGIN user pass
        parts = line.strip().split()
        if len(parts) >= 3 and parts[1].upper() == "LOGIN":
            # Tag, LOGIN, Username, Password...
            user = parts[2]
            return f"{parts[0]} LOGIN {user} [REDACTED]"
        return line

    def analyze_stream(self, stream: NormalizedStream) -> List[SecurityEventData]:
        self.events = []
        lines = reassemble_stream_lines(stream)

        for line_obj in lines:
            text = line_obj.line.strip()
            direction = line_obj.direction
            frames = line_obj.frame_numbers
            ts = line_obj.timestamp

            if direction == "S2C":
                # Server Greeting (e.g., "* OK ...")
                if not self.server_greeting_seen and text.startswith("* OK"):
                    self.server_greeting_seen = True
                    # Check if STARTTLS is advertised in untagged greeting capability list
                    if "STARTTLS" in text.upper():
                        self.starttls_offered = True
                        self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                        self.events.append(
                            SecurityEventData(
                                event_type="CAPABILITY_ADVERTISED",
                                protocol="IMAP",
                                observed_value="STARTTLS",
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                details={"capability": "STARTTLS", "banner": text}
                            )
                        )
                    else:
                        self.events.append(
                            SecurityEventData(
                                event_type="SERVER_GREETING",
                                protocol="IMAP",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=None,
                                details={"banner": text}
                            )
                        )
                    continue

                # Untagged CAPABILITY Response (e.g. "* CAPABILITY IMAP4rev1 ... STARTTLS ...")
                if text.startswith("* CAPABILITY") or "* OK [CAPABILITY" in text.upper():
                    if "STARTTLS" in text.upper():
                        self.starttls_offered = True
                        self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                        self.events.append(
                            SecurityEventData(
                                event_type="CAPABILITY_ADVERTISED",
                                protocol="IMAP",
                                observed_value="STARTTLS",
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                details={"capability": "STARTTLS", "line": text}
                            )
                        )
                    continue

                # Tagged response to STARTTLS request
                if self.pending_starttls_tag and text.startswith(self.pending_starttls_tag):
                    parts = text.split(maxsplit=2)
                    status_code = parts[1].upper() if len(parts) > 1 else ""
                    if status_code == "OK":
                        self.starttls_accepted = True
                        self.overall_status = UpgradeStatus.ACCEPTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_ACCEPTED",
                                protocol="IMAP",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.ACCEPTED,
                                details={"tag": self.pending_starttls_tag, "server_response": text}
                            )
                        )
                    elif status_code in ["NO", "BAD"]:
                        self.starttls_rejected = True
                        self.overall_status = UpgradeStatus.REJECTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_REJECTED",
                                protocol="IMAP",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.REJECTED,
                                details={"tag": self.pending_starttls_tag, "server_response": text}
                            )
                        )
                    self.pending_starttls_tag = None
                    continue

            elif direction == "C2S":
                parts = text.split(maxsplit=2)
                if len(parts) >= 2:
                    tag = parts[0]
                    cmd = parts[1].upper()

                    if cmd == "CAPABILITY":
                        self.client_greeting_seen = True
                        self.events.append(
                            SecurityEventData(
                                event_type="CLIENT_COMMAND",
                                protocol="IMAP",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=None,
                                details={"command": "CAPABILITY", "tag": tag}
                            )
                        )
                    elif cmd == "STARTTLS":
                        self.starttls_requested = True
                        self.pending_starttls_tag = tag
                        self.overall_status = UpgradeStatus.REQUESTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_REQUESTED",
                                protocol="IMAP",
                                observed_value="STARTTLS",
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.REQUESTED,
                                details={"command": "STARTTLS", "tag": tag}
                            )
                        )
                    elif cmd in ["LOGIN", "SELECT", "AUTHENTICATE", "EXAMINE", "LIST"]:
                        redacted_text = self._redact_imap_line(text)
                        if self.starttls_offered and not self.starttls_requested:
                            if not self.plaintext_command_after_offer:
                                self.plaintext_command_after_offer = True
                                self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                                self.events.append(
                                    SecurityEventData(
                                        event_type="PLAINTEXT_COMMAND_AFTER_OFFER",
                                        protocol="IMAP",
                                        observed_value=redacted_text,
                                        frame_numbers=frames,
                                        timestamp=ts,
                                        upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                        details={"command": cmd, "tag": tag, "risk": "UNENCRYPTED_TRANSMISSION_DESPITE_STARTTLS_CAPABILITY"}
                                    )
                                )

        # Check for TLS Handshake evidence and cryptographic posture in stream packets
        if self.starttls_accepted:
            tls_res, tls_evts = analyze_tls_stream(stream, "IMAP", self.starttls_accepted)
            if tls_res.upgrade_status != UpgradeStatus.UNKNOWN:
                self.overall_status = tls_res.upgrade_status
            for evt in tls_evts:
                self.events.append(evt)

        return self.events


