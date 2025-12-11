"""
meshing-around Compatibility Layer

Implements meshing-around bbslink/bbsack sync protocol.
Reference: https://github.com/SpudGunMan/meshing-around
"""

import base64
import logging
import pickle
from typing import Optional

logger = logging.getLogger(__name__)


class MeshingAroundCompatibility:
    """
    Sync with meshing-around peers using their native protocol.

    Protocol:
    - bbslink <serialized_data>: Send message data
    - bbsack <message_id>: Acknowledge receipt
    """

    def __init__(self, config, interface):
        self.config = config
        self.interface = interface
        self.sync_channel = getattr(config, 'meshing_around_channel', 0)

    def send_bbslink(self, msg: dict, peer_id: str):
        """
        Send message using bbslink format.

        meshing-around expects:
        [messageID, subject, message, fromNode, timestamp, threadID, replytoID]
        """
        payload = [
            msg.get("id", 0),
            msg.get("subject", ""),
            msg.get("body", ""),
            msg.get("sender_node", ""),
            msg.get("timestamp", 0),
            msg.get("thread_id", 0),
            msg.get("reply_to", 0),
        ]

        try:
            serialized = base64.b64encode(pickle.dumps(payload)).decode()
            bbslink_msg = f"bbslink {serialized}"
            self.interface.sendText(bbslink_msg, destinationId=peer_id)
            logger.debug(f"Sent bbslink to {peer_id}")
        except Exception as e:
            logger.error(f"Failed to serialize bbslink: {e}")

    def send_bbsack(self, message_id: str, peer_id: str):
        """Send acknowledgment for received message."""
        self.interface.sendText(f"bbsack {message_id}", destinationId=peer_id)

    def parse_bbslink(self, raw: str) -> Optional[dict]:
        """
        Parse incoming bbslink message.

        Returns parsed dict or None if invalid.
        """
        if not raw.startswith("bbslink "):
            return None

        try:
            serialized = raw[8:]  # Strip "bbslink "
            payload = pickle.loads(base64.b64decode(serialized))

            return {
                "type": "bbslink",
                "id": payload[0] if len(payload) > 0 else 0,
                "subject": payload[1] if len(payload) > 1 else "",
                "body": payload[2] if len(payload) > 2 else "",
                "sender_node": payload[3] if len(payload) > 3 else "",
                "timestamp": payload[4] if len(payload) > 4 else 0,
                "thread_id": payload[5] if len(payload) > 5 else 0,
                "reply_to": payload[6] if len(payload) > 6 else 0,
            }
        except Exception as e:
            logger.error(f"Failed to parse bbslink: {e}")
            return None

    def parse_bbsack(self, raw: str) -> Optional[str]:
        """
        Parse bbsack message.

        Returns message_id or None if not bbsack.
        """
        if raw.startswith("bbsack "):
            return raw[7:]
        return None

    def is_meshing_around_message(self, raw: str) -> bool:
        """Check if message is meshing-around format."""
        return raw.startswith("bbslink ") or raw.startswith("bbsack ")
