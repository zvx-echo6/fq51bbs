"""
TC2-BBS-mesh Compatibility Layer

Implements TC2-BBS pipe-delimited sync protocol.
Reference: https://github.com/TheCommsChannel/TC2-BBS-mesh
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class TC2Compatibility:
    """
    Sync with TC2-BBS-mesh peers using their native protocol.

    Protocol format: TYPE|field1|field2|...|uuid
    """

    # Message types
    TYPE_BULLETIN = "BULLETIN"
    TYPE_MAIL = "MAIL"
    TYPE_DELETE_BULLETIN = "DELETE_BULLETIN"
    TYPE_DELETE_MAIL = "DELETE_MAIL"
    TYPE_CHANNEL = "CHANNEL"

    def __init__(self, interface):
        self.interface = interface

    def send_bulletin(self, msg: dict, peer_id: str):
        """
        Send bulletin in TC2 format.

        Format: BULLETIN|board|sender_short|subject|content|uuid
        """
        tc2_msg = (
            f"{self.TYPE_BULLETIN}|"
            f"{msg['board']}|"
            f"{msg['sender_short']}|"
            f"{msg['subject']}|"
            f"{msg['body']}|"
            f"{msg['uuid']}"
        )
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def send_mail(self, msg: dict, peer_id: str):
        """
        Send mail in TC2 format.

        Format: MAIL|sender|recipient|subject|content|uuid
        """
        tc2_msg = (
            f"{self.TYPE_MAIL}|"
            f"{msg['sender']}|"
            f"{msg['recipient']}|"
            f"{msg['subject']}|"
            f"{msg['body']}|"
            f"{msg['uuid']}"
        )
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def send_delete_bulletin(self, uuid: str, peer_id: str):
        """Send bulletin delete request."""
        tc2_msg = f"{self.TYPE_DELETE_BULLETIN}|{uuid}"
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def send_delete_mail(self, uuid: str, peer_id: str):
        """Send mail delete request."""
        tc2_msg = f"{self.TYPE_DELETE_MAIL}|{uuid}"
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def parse_message(self, raw: str) -> Optional[dict]:
        """
        Parse incoming TC2 format message.

        Returns parsed dict or None if not TC2 format.
        """
        parts = raw.split("|")
        if len(parts) < 2:
            return None

        msg_type = parts[0]

        if msg_type == self.TYPE_BULLETIN and len(parts) >= 6:
            return {
                "type": "bulletin",
                "board": parts[1],
                "sender_short": parts[2],
                "subject": parts[3],
                "body": parts[4],
                "uuid": parts[5],
            }

        elif msg_type == self.TYPE_MAIL and len(parts) >= 6:
            return {
                "type": "mail",
                "sender": parts[1],
                "recipient": parts[2],
                "subject": parts[3],
                "body": parts[4],
                "uuid": parts[5],
            }

        elif msg_type == self.TYPE_DELETE_BULLETIN and len(parts) >= 2:
            return {
                "type": "delete_bulletin",
                "uuid": parts[1],
            }

        elif msg_type == self.TYPE_DELETE_MAIL and len(parts) >= 2:
            return {
                "type": "delete_mail",
                "uuid": parts[1],
            }

        elif msg_type == self.TYPE_CHANNEL and len(parts) >= 3:
            return {
                "type": "channel",
                "name": parts[1],
                "url": parts[2],
            }

        return None

    def is_tc2_message(self, raw: str) -> bool:
        """Check if message is TC2 format."""
        if "|" not in raw:
            return False

        first_part = raw.split("|")[0]
        return first_part in [
            self.TYPE_BULLETIN,
            self.TYPE_MAIL,
            self.TYPE_DELETE_BULLETIN,
            self.TYPE_DELETE_MAIL,
            self.TYPE_CHANNEL,
        ]
