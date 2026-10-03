from typing import List, Dict, Optional, Any
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import (
    UpgradeStatus, SecurityEventData, StreamLine, reassemble_stream_lines
)
from backend.app.services.protocols.tls import analyze_tls_stream

class POP3StateMachine:
    """
    Passive, protocol-aware state machine for analyzing POP3 STLS security posture
    from reassembled TCP stream observations.
    """

    def __init__(self):
        self.events: List[SecurityEventData] = []
        self.server_greeting_seen = False
        self.client_capa_sent = False
        self.stls_offered = False
        self.stls_requested = False
        self.stls_accepted = False
        self.stls_rejected = False
        self.in_capa_response = False
        self.capa_buffer: List[StreamLine] = []
        self.plaintext_command_after_offer = False
        self.overall_status: UpgradeStatus = UpgradeStatus.UNKNOWN

    def _redact_pop3_line(self, line: str) -> str:
        """Redacts plaintext passwords in POP3 PASS commands."""
        parts = line.strip().split(maxsplit=1)
        if len(parts) >= 2 and parts[0].upper() == "PASS":
            return "PASS [REDACTED]"
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
                # Server Greeting (e.g. "+OK Dovecot ready.")
                if not self.server_greeting_seen and text.startswith("+OK") and not self.stls_requested and not self.client_capa_sent:
                    self.server_greeting_seen = True
                    self.events.append(
                        SecurityEventData(
                            event_type="SERVER_GREETING",
                            protocol="POP3",
                            observed_value=text,
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=None,
                            details={"banner": text}
                        )
                    )
                    continue

                # Multiline CAPA Response
                if self.client_capa_sent and not self.stls_requested:
                    if text.startswith("+OK"):
                        self.in_capa_response = True
                        self.capa_buffer.append(line_obj)
                        continue
                    elif self.in_capa_response:
                        self.capa_buffer.append(line_obj)
                        if text == ".":
                            self.in_capa_response = False
                            all_frames = []
                            for l in self.capa_buffer:
                                all_frames.extend(l.frame_numbers)
                            all_frames = sorted(list(set(all_frames)))

                            # Check if STLS was in capability list
                            capa_text = "\n".join(l.line.upper() for l in self.capa_buffer)
                            if "STLS" in capa_text:
                                self.stls_offered = True
                                self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                                self.events.append(
                                    SecurityEventData(
                                        event_type="CAPABILITY_ADVERTISED",
                                        protocol="POP3",
                                        observed_value="STLS",
                                        frame_numbers=all_frames,
                                        timestamp=ts,
                                        upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                        details={"capability": "STLS", "response": [l.line for l in self.capa_buffer]}
                                    )
                                )
                            else:
                                self.overall_status = UpgradeStatus.NOT_OFFERED
                                self.events.append(
                                    SecurityEventData(
                                        event_type="CAPABILITY_ADVERTISED",
                                        protocol="POP3",
                                        observed_value="STLS_NOT_ADVERTISED",
                                        frame_numbers=all_frames,
                                        timestamp=ts,
                                        upgrade_status=UpgradeStatus.NOT_OFFERED,
                                        details={"capability": None, "response": [l.line for l in self.capa_buffer]}
                                    )
                                )
                            self.capa_buffer = []
                        elif "STLS" in text.upper():
                            self.stls_offered = True
                        continue

                # Server response to STLS request
                if self.stls_requested and not self.stls_accepted and not self.stls_rejected:
                    if text.startswith("+OK"):
                        self.stls_accepted = True
                        self.overall_status = UpgradeStatus.ACCEPTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_ACCEPTED",
                                protocol="POP3",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.ACCEPTED,
                                details={"server_response": text}
                            )
                        )
                    elif text.startswith("-ERR"):
                        self.stls_rejected = True
                        self.overall_status = UpgradeStatus.REJECTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_REJECTED",
                                protocol="POP3",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.REJECTED,
                                details={"server_response": text}
                            )
                        )
                    continue

            elif direction == "C2S":
                cmd_upper = text.upper()
                if cmd_upper.startswith("CAPA"):
                    self.client_capa_sent = True
                    self.events.append(
                        SecurityEventData(
                            event_type="CLIENT_COMMAND",
                            protocol="POP3",
                            observed_value="CAPA",
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=None,
                            details={"command": "CAPA"}
                        )
                    )
                elif cmd_upper == "STLS":
                    self.stls_requested = True
                    self.overall_status = UpgradeStatus.REQUESTED
                    self.events.append(
                        SecurityEventData(
                            event_type="UPGRADE_REQUESTED",
                            protocol="POP3",
                            observed_value="STLS",
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=UpgradeStatus.REQUESTED,
                            details={"command": "STLS"}
                        )
                    )
                elif any(cmd_upper.startswith(prefix) for prefix in ["USER", "PASS", "STAT", "LIST", "RETR"]):
                    redacted_text = self._redact_pop3_line(text)
                    if self.stls_offered and not self.stls_requested:
                        if not self.plaintext_command_after_offer:
                            self.plaintext_command_after_offer = True
                            self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                            self.events.append(
                                SecurityEventData(
                                    event_type="PLAINTEXT_COMMAND_AFTER_OFFER",
                                    protocol="POP3",
                                    observed_value=redacted_text,
                                    frame_numbers=frames,
                                    timestamp=ts,
                                    upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                    details={"command": text.split()[0].upper(), "risk": "UNENCRYPTED_TRANSMISSION_DESPITE_STLS_CAPABILITY"}
                                )
                            )

        # Check for TLS Handshake evidence and cryptographic posture in stream packets
        if self.stls_accepted:
            tls_res, tls_evts = analyze_tls_stream(stream, "POP3", self.stls_accepted)
            if tls_res.upgrade_status != UpgradeStatus.UNKNOWN:
                self.overall_status = tls_res.upgrade_status
            for evt in tls_evts:
                self.events.append(evt)

        return self.events


