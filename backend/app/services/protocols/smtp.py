import json
from typing import List, Dict, Optional, Any
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import (
    UpgradeStatus, SecurityEventData, StreamLine, reassemble_stream_lines
)
from backend.app.services.protocols.tls import analyze_tls_stream

class SMTPStateMachine:


    """
    Passive, protocol-aware state machine for analyzing SMTP STARTTLS security posture
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
        self.plaintext_mail_sent_after_offer = False
        self.overall_status: UpgradeStatus = UpgradeStatus.UNKNOWN

    def analyze_stream(self, stream: NormalizedStream) -> List[SecurityEventData]:
        self.events = []
        lines = reassemble_stream_lines(stream)

        ehlo_multiline_buffer: List[StreamLine] = []
        in_ehlo_response = False

        for line_obj in lines:
            text = line_obj.line.strip()
            direction = line_obj.direction
            frames = line_obj.frame_numbers
            ts = line_obj.timestamp

            if direction == "S2C":
                # Server Greeting (e.g. "220 postfix.mailnet ESMTP...")
                if not self.server_greeting_seen and text.startswith("220") and "Ready to start TLS" not in text:
                    self.server_greeting_seen = True
                    self.events.append(
                        SecurityEventData(
                            event_type="SERVER_GREETING",
                            protocol="SMTP",
                            observed_value=text,
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=None,
                            details={"banner": text}
                        )
                    )
                    continue

                # EHLO / HELO Capability Response (e.g., "250-STARTTLS" ... "250 DSN")
                if (text.startswith("250-") or text.startswith("250 ")) and (self.client_greeting_seen or in_ehlo_response or ehlo_multiline_buffer):
                    in_ehlo_response = True
                    ehlo_multiline_buffer.append(line_obj)
                    if "STARTTLS" in text.upper():
                        self.starttls_offered = True

                    # Final line of EHLO multiline response
                    if text.startswith("250 "):
                        in_ehlo_response = False
                        self.client_greeting_seen = False
                        all_frames = []
                        for l in ehlo_multiline_buffer:
                            all_frames.extend(l.frame_numbers)
                        all_frames = sorted(list(set(all_frames)))

                        if self.starttls_offered:
                            self.overall_status = UpgradeStatus.OFFERED_NOT_USED # Interim until requested or plaintext sent
                            self.events.append(
                                SecurityEventData(
                                    event_type="CAPABILITY_ADVERTISED",
                                    protocol="SMTP",
                                    observed_value="250-STARTTLS",
                                    frame_numbers=all_frames,
                                    timestamp=ts,
                                    upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                    details={"capability": "STARTTLS", "response_lines": [l.line for l in ehlo_multiline_buffer]}
                                )
                            )
                        else:
                            self.overall_status = UpgradeStatus.NOT_OFFERED
                            self.events.append(
                                SecurityEventData(
                                    event_type="CAPABILITY_ADVERTISED",
                                    protocol="SMTP",
                                    observed_value="STARTTLS_NOT_ADVERTISED",
                                    frame_numbers=all_frames,
                                    timestamp=ts,
                                    upgrade_status=UpgradeStatus.NOT_OFFERED,
                                    details={"capability": None, "response_lines": [l.line for l in ehlo_multiline_buffer]}
                                )
                            )
                        ehlo_multiline_buffer = []
                    continue


                # Server response to STARTTLS
                if self.starttls_requested and not self.starttls_accepted and not self.starttls_rejected:
                    if text.startswith("220"):
                        self.starttls_accepted = True
                        self.overall_status = UpgradeStatus.ACCEPTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_ACCEPTED",
                                protocol="SMTP",
                                observed_value=text,
                                frame_numbers=frames,
                                timestamp=ts,
                                upgrade_status=UpgradeStatus.ACCEPTED,
                                details={"server_response": text}
                            )
                        )
                    elif text.startswith("4") or text.startswith("5"):
                        self.starttls_rejected = True
                        self.overall_status = UpgradeStatus.REJECTED
                        self.events.append(
                            SecurityEventData(
                                event_type="UPGRADE_REJECTED",
                                protocol="SMTP",
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
                if cmd_upper.startswith("EHLO") or cmd_upper.startswith("HELO"):
                    self.client_greeting_seen = True
                    self.events.append(
                        SecurityEventData(
                            event_type="CLIENT_GREETING",
                            protocol="SMTP",
                            observed_value=text,
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=None,
                            details={"command": text}
                        )
                    )
                elif cmd_upper == "STARTTLS":
                    self.starttls_requested = True
                    self.overall_status = UpgradeStatus.REQUESTED
                    self.events.append(
                        SecurityEventData(
                            event_type="UPGRADE_REQUESTED",
                            protocol="SMTP",
                            observed_value="STARTTLS",
                            frame_numbers=frames,
                            timestamp=ts,
                            upgrade_status=UpgradeStatus.REQUESTED,
                            details={"command": "STARTTLS"}
                        )
                    )
                elif any(cmd_upper.startswith(prefix) for prefix in ["MAIL FROM:", "RCPT TO:", "DATA"]):
                    # Plaintext mail command sent after STARTTLS capability was advertised without upgrading
                    if self.starttls_offered and not self.starttls_requested:
                        if not self.plaintext_mail_sent_after_offer:
                            self.plaintext_mail_sent_after_offer = True
                            self.overall_status = UpgradeStatus.OFFERED_NOT_USED
                            self.events.append(
                                SecurityEventData(
                                    event_type="PLAINTEXT_COMMAND_AFTER_OFFER",
                                    protocol="SMTP",
                                    observed_value=text,
                                    frame_numbers=frames,
                                    timestamp=ts,
                                    upgrade_status=UpgradeStatus.OFFERED_NOT_USED,
                                    details={"command": text, "risk": "UNENCRYPTED_TRANSMISSION_DESPITE_STARTTLS_CAPABILITY"}
                                )
                            )

        # Check for TLS Handshake evidence and cryptographic posture in stream packets
        if self.starttls_accepted:
            tls_res, tls_evts = analyze_tls_stream(stream, "SMTP", self.starttls_accepted)
            if tls_res.upgrade_status != UpgradeStatus.UNKNOWN:
                self.overall_status = tls_res.upgrade_status
            for evt in tls_evts:
                self.events.append(evt)

        return self.events


