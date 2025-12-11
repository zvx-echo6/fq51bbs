"""
FQ51BBS Native Sync Protocol

DM-based sync for FQ51BBS-to-FQ51BBS communication.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class FQ51NativeSync:
    """
    Native FQ51BBS-to-FQ51BBS sync via DM.

    Protocol format: FQ51|<version>|<msg_type>|<payload>
    """

    VERSION = "1"

    # Message types
    MSG_HELLO = "HELLO"
    MSG_SYNC_REQ = "SYNC_REQ"
    MSG_SYNC_MSG = "SYNC_MSG"
    MSG_SYNC_ACK = "SYNC_ACK"
    MSG_SYNC_DONE = "SYNC_DONE"
    MSG_DELETE = "DELETE"

    def __init__(self, config, db, interface):
        self.config = config
        self.db = db
        self.interface = interface
        self.my_name = config.bbs.name if hasattr(config, 'bbs') else "FQ51BBS"

    async def sync_with_peer(self, peer_id: str):
        """Initiate sync with FQ51BBS peer."""
        # Send handshake
        hello = self._format_message(self.MSG_HELLO, f"{self.my_name}|mail,bulletin")
        await self._send_dm(peer_id, hello)

        # Request sync
        last_sync = self.db.get_last_sync_time(peer_id)
        sync_req = self._format_message(self.MSG_SYNC_REQ, f"{last_sync}|mail,bulletin")
        await self._send_dm(peer_id, sync_req)

    def handle_message(self, raw: str, sender: str) -> Optional[str]:
        """
        Handle incoming FQ51 protocol message.

        Returns response message or None.
        """
        parts = raw.split("|")
        if len(parts) < 3 or parts[0] != "FQ51":
            return None

        version = parts[1]
        msg_type = parts[2]
        payload = "|".join(parts[3:]) if len(parts) > 3 else ""

        handlers = {
            self.MSG_HELLO: self._handle_hello,
            self.MSG_SYNC_REQ: self._handle_sync_request,
            self.MSG_SYNC_MSG: self._handle_sync_message,
            self.MSG_SYNC_ACK: self._handle_sync_ack,
            self.MSG_SYNC_DONE: self._handle_sync_done,
            self.MSG_DELETE: self._handle_delete,
        }

        handler = handlers.get(msg_type)
        if handler:
            return handler(payload, sender)

        return None

    def _format_message(self, msg_type: str, payload: str) -> str:
        """Format a protocol message."""
        return f"FQ51|{self.VERSION}|{msg_type}|{payload}"

    async def _send_dm(self, peer_id: str, message: str):
        """Send direct message to peer."""
        await self.interface.send_dm(message, peer_id)

    def _handle_hello(self, payload: str, sender: str) -> Optional[str]:
        """Handle HELLO handshake."""
        parts = payload.split("|")
        peer_name = parts[0] if parts else "Unknown"
        capabilities = parts[1].split(",") if len(parts) > 1 else []

        logger.info(f"FQ51 handshake from {peer_name} ({sender}): {capabilities}")

        # Respond with our hello
        return self._format_message(self.MSG_HELLO, f"{self.my_name}|mail,bulletin")

    def _handle_sync_request(self, payload: str, sender: str) -> Optional[str]:
        """Handle sync request - send our messages since timestamp."""
        # TODO: Implement
        return None

    def _handle_sync_message(self, payload: str, sender: str) -> Optional[str]:
        """Handle incoming sync message."""
        # TODO: Implement
        return None

    def _handle_sync_ack(self, payload: str, sender: str) -> Optional[str]:
        """Handle sync acknowledgment."""
        # TODO: Implement
        return None

    def _handle_sync_done(self, payload: str, sender: str) -> Optional[str]:
        """Handle sync completion."""
        # TODO: Implement
        return None

    def _handle_delete(self, payload: str, sender: str) -> Optional[str]:
        """Handle delete message request."""
        # TODO: Implement
        return None
