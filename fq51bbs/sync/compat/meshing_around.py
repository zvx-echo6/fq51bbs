"""
meshing-around Compatibility Layer

Implements meshing-around bbslink/bbsack sync protocol.
Reference: https://github.com/SpudGunMan/meshing-around

Protocol:
- bbslink <serialized_data>: Send message data (pickle + base64)
- bbsack <message_id>: Acknowledge receipt
"""

import base64
import logging
import pickle
import time
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..manager import SyncManager

logger = logging.getLogger(__name__)


@dataclass
class BBSLinkMessage:
    """Parsed bbslink message."""
    msg_id: int
    subject: str
    body: str
    sender_node: str
    timestamp: int
    thread_id: int = 0
    reply_to: int = 0


class MeshingAroundCompatibility:
    """
    Sync with meshing-around peers using their native protocol.

    meshing-around uses:
    - bbslink <base64_pickle>: Send messages
    - bbsack <message_id>: Acknowledge receipt

    Message format (pickle payload):
    [messageID, subject, message, fromNode, timestamp, threadID, replytoID]
    """

    def __init__(self, sync_manager: "SyncManager"):
        self.sync_manager = sync_manager
        self.db = sync_manager.db
        self.mesh = sync_manager.mesh
        self.sync_channel = getattr(sync_manager.config, 'meshing_around_channel', 0)

        # Track pending ACKs
        self._pending_acks: dict[int, str] = {}  # msg_id -> peer_id

    async def sync_bulletins_to_peer(self, peer_id: str, since_us: int = 0):
        """
        Send bulletins to meshing-around peer.

        Args:
            peer_id: Peer node ID
            since_us: Timestamp to sync from
        """
        from ...db.messages import MessageRepository
        from ...db.users import UserRepository

        msg_repo = MessageRepository(self.db)
        user_repo = UserRepository(self.db)

        bulletins = msg_repo.get_messages_since(since_us, msg_types=["bulletin"])

        for bulletin in bulletins:
            if self._already_synced(bulletin.uuid, peer_id):
                continue

            # Get sender info
            sender = user_repo.get_user_by_id(bulletin.sender_user_id) if bulletin.sender_user_id else None

            # Decrypt for sync
            subject, body = self._decrypt_bulletin_for_sync(bulletin)
            if body is None:
                continue

            # Generate a numeric message ID for meshing-around
            # Use last 8 digits of timestamp as ID
            msg_id = int(bulletin.created_at_us % 100000000)

            await self.send_bbslink(
                msg_id=msg_id,
                subject=subject or "(no subject)",
                body=body,
                sender_node=sender.username if sender else "anon",
                timestamp=int(bulletin.created_at_us / 1_000_000),
                peer_id=peer_id
            )

            # Track pending ACK
            self._pending_acks[msg_id] = bulletin.uuid

            # Log sync as pending
            self._log_sync(bulletin.uuid, peer_id, "sent", status="pending")

            await self._rate_limit_delay()

        logger.info(f"Synced bulletins to meshing-around peer {peer_id}")

    async def send_bbslink(
        self,
        msg_id: int,
        subject: str,
        body: str,
        sender_node: str,
        timestamp: int,
        peer_id: str,
        thread_id: int = 0,
        reply_to: int = 0
    ):
        """
        Send message using bbslink format.

        meshing-around expects:
        [messageID, subject, message, fromNode, timestamp, threadID, replytoID]
        """
        payload = [
            msg_id,
            subject,
            body,
            sender_node,
            timestamp,
            thread_id,
            reply_to,
        ]

        try:
            serialized = base64.b64encode(pickle.dumps(payload)).decode()
            bbslink_msg = f"bbslink {serialized}"

            if self.mesh:
                await self.mesh.send_dm(bbslink_msg, peer_id)
                logger.debug(f"Sent bbslink to {peer_id}: msg_id={msg_id}")
        except Exception as e:
            logger.error(f"Failed to send bbslink: {e}")

    async def send_bbsack(self, message_id: int, peer_id: str):
        """Send acknowledgment for received message."""
        if self.mesh:
            await self.mesh.send_dm(f"bbsack {message_id}", peer_id)
            logger.debug(f"Sent bbsack to {peer_id}: {message_id}")

    def handle_message(self, raw: str, sender: str) -> bool:
        """
        Handle incoming meshing-around message.

        Returns True if handled, False otherwise.
        """
        if raw.startswith("bbslink "):
            return self._handle_bbslink(raw, sender)
        elif raw.startswith("bbsack "):
            return self._handle_bbsack(raw, sender)
        return False

    def _handle_bbslink(self, raw: str, sender: str) -> bool:
        """Handle incoming bbslink message."""
        parsed = self.parse_bbslink(raw)
        if not parsed:
            return False

        logger.debug(f"Received bbslink from {sender}: msg_id={parsed.msg_id}")

        # Store the message
        self._store_bbslink_message(parsed, sender)

        # Send ACK
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.send_bbsack(parsed.msg_id, sender))
            else:
                loop.run_until_complete(self.send_bbsack(parsed.msg_id, sender))
        except Exception as e:
            logger.error(f"Failed to send bbsack: {e}")

        return True

    def _handle_bbsack(self, raw: str, sender: str) -> bool:
        """Handle bbsack acknowledgment."""
        msg_id = self.parse_bbsack(raw)
        if msg_id is None:
            return False

        logger.debug(f"Received bbsack from {sender}: {msg_id}")

        # Mark sync as complete
        if msg_id in self._pending_acks:
            uuid = self._pending_acks.pop(msg_id)
            self._log_sync(uuid, sender, "sent", status="acked")
            logger.info(f"Message {uuid[:8]} acknowledged by {sender}")

        return True

    def _store_bbslink_message(self, msg: BBSLinkMessage, sender: str):
        """Store received bbslink message as bulletin."""
        from ...db.messages import MessageRepository
        from ...db.users import NodeRepository
        import uuid as uuid_lib

        msg_repo = MessageRepository(self.db)
        node_repo = NodeRepository(self.db)

        # Generate UUID for deduplication
        msg_uuid = f"ma-{msg.msg_id}-{msg.timestamp}"

        # Check for duplicate
        if msg_repo.message_exists(msg_uuid):
            logger.debug(f"Duplicate bbslink ignored: {msg_uuid}")
            return

        # Get sender node
        sender_node = node_repo.get_or_create_node(sender)

        # Get or create general board
        board_id = self._get_or_create_board("general")

        # Encrypt for storage
        body_enc = self._encrypt_for_storage(msg.body)
        subject_enc = self._encrypt_for_storage(msg.subject) if msg.subject else None

        # Store
        from ...db.models import MessageType
        msg_repo.create_message(
            msg_type=MessageType.BULLETIN,
            sender_node_id=sender_node.id,
            board_id=board_id,
            body_enc=body_enc,
            subject_enc=subject_enc,
            origin_bbs=sender,
            message_uuid=msg_uuid
        )

        self._log_sync(msg_uuid, sender, "received")
        logger.info(f"Stored bbslink message from {sender}: {msg_uuid}")

    def parse_bbslink(self, raw: str) -> Optional[BBSLinkMessage]:
        """
        Parse incoming bbslink message.

        Returns parsed BBSLinkMessage or None if invalid.
        """
        if not raw.startswith("bbslink "):
            return None

        try:
            serialized = raw[8:]  # Strip "bbslink "
            payload = pickle.loads(base64.b64decode(serialized))

            if not isinstance(payload, (list, tuple)) or len(payload) < 5:
                return None

            return BBSLinkMessage(
                msg_id=int(payload[0]) if len(payload) > 0 else 0,
                subject=str(payload[1]) if len(payload) > 1 else "",
                body=str(payload[2]) if len(payload) > 2 else "",
                sender_node=str(payload[3]) if len(payload) > 3 else "",
                timestamp=int(payload[4]) if len(payload) > 4 else 0,
                thread_id=int(payload[5]) if len(payload) > 5 else 0,
                reply_to=int(payload[6]) if len(payload) > 6 else 0,
            )
        except Exception as e:
            logger.error(f"Failed to parse bbslink: {e}")
            return None

    def parse_bbsack(self, raw: str) -> Optional[int]:
        """
        Parse bbsack message.

        Returns message_id or None if not bbsack.
        """
        if not raw.startswith("bbsack "):
            return None

        try:
            return int(raw[7:].strip())
        except ValueError:
            return None

    def is_meshing_around_message(self, raw: str) -> bool:
        """Check if message is meshing-around format."""
        return raw.startswith("bbslink ") or raw.startswith("bbsack ")

    # Helper methods

    def _already_synced(self, uuid: str, peer_id: str) -> bool:
        """Check if message already synced to peer."""
        row = self.db.fetchone("""
            SELECT 1 FROM sync_log
            WHERE message_uuid = ? AND peer_id = (
                SELECT id FROM bbs_peers WHERE node_id = ?
            ) AND direction = 'sent' AND status = 'acked'
        """, (uuid, peer_id))
        return row is not None

    def _log_sync(self, uuid: str, peer_node_id: str, direction: str, status: str = "acked"):
        """Log sync operation."""
        now_us = int(time.time() * 1_000_000)

        # Get or create peer
        peer_row = self.db.fetchone(
            "SELECT id FROM bbs_peers WHERE node_id = ?",
            (peer_node_id,)
        )

        if not peer_row:
            cursor = self.db.execute(
                "INSERT INTO bbs_peers (node_id, protocol, last_sync_us) VALUES (?, 'meshing-around', ?)",
                (peer_node_id, now_us)
            )
            peer_id = cursor.lastrowid
        else:
            peer_id = peer_row[0]
            self.db.execute(
                "UPDATE bbs_peers SET last_sync_us = ? WHERE id = ?",
                (now_us, peer_id)
            )

        # Log sync
        self.db.execute("""
            INSERT OR REPLACE INTO sync_log
            (message_uuid, peer_id, direction, status, attempts, last_attempt_us)
            VALUES (?, ?, ?, ?, 1, ?)
        """, (uuid, peer_id, direction, status, now_us))

    def _get_or_create_board(self, name: str) -> int:
        """Get board ID or create if doesn't exist."""
        row = self.db.fetchone(
            "SELECT id FROM boards WHERE name = ? COLLATE NOCASE",
            (name.lower(),)
        )
        if row:
            return row[0]

        now_us = int(time.time() * 1_000_000)
        cursor = self.db.execute(
            "INSERT INTO boards (name, created_at_us) VALUES (?, ?)",
            (name.lower(), now_us)
        )
        return cursor.lastrowid

    def _decrypt_bulletin_for_sync(self, message) -> tuple[Optional[str], Optional[str]]:
        """Decrypt bulletin content for sending to peer."""
        try:
            master_key = self.sync_manager.bbs.master_key.key
            crypto = self.sync_manager.bbs.crypto

            body = crypto.decrypt_string(message.body_enc, master_key)
            subject = None
            if message.subject_enc:
                subject = crypto.decrypt_string(message.subject_enc, master_key)

            return subject, body
        except Exception as e:
            logger.error(f"Decrypt error: {e}")
            return None, None

    def _encrypt_for_storage(self, plaintext: str) -> bytes:
        """Encrypt content for storage."""
        master_key = self.sync_manager.bbs.master_key.key
        crypto = self.sync_manager.bbs.crypto
        return crypto.encrypt_string(plaintext, master_key)

    async def _rate_limit_delay(self):
        """Apply rate limiting delay."""
        import asyncio
        await asyncio.sleep(3)
