"""
TC2-BBS-mesh Compatibility Layer

Implements TC2-BBS pipe-delimited sync protocol.
Reference: https://github.com/TheCommsChannel/TC2-BBS-mesh

Protocol format: TYPE|field1|field2|...|uuid
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..manager import SyncManager

logger = logging.getLogger(__name__)


# TC2 Message Types
TYPE_BULLETIN = "BULLETIN"
TYPE_MAIL = "MAIL"
TYPE_DELETE_BULLETIN = "DELETE_BULLETIN"
TYPE_DELETE_MAIL = "DELETE_MAIL"
TYPE_CHANNEL = "CHANNEL"

VALID_TYPES = {TYPE_BULLETIN, TYPE_MAIL, TYPE_DELETE_BULLETIN, TYPE_DELETE_MAIL, TYPE_CHANNEL}


@dataclass
class TC2Message:
    """Parsed TC2 protocol message."""
    msg_type: str
    uuid: str
    board: Optional[str] = None
    sender: Optional[str] = None
    sender_short: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    channel_name: Optional[str] = None
    channel_url: Optional[str] = None


class TC2Compatibility:
    """
    Sync with TC2-BBS-mesh peers using their native protocol.

    TC2-BBS uses pipe-delimited messages:
    - BULLETIN|board|sender_short|subject|content|uuid
    - MAIL|sender|recipient|subject|content|uuid
    - DELETE_BULLETIN|uuid
    - DELETE_MAIL|uuid
    - CHANNEL|name|url
    """

    def __init__(self, sync_manager: "SyncManager"):
        self.sync_manager = sync_manager
        self.db = sync_manager.db
        self.mesh = sync_manager.mesh

    async def sync_bulletins_to_peer(self, peer_id: str, since_us: int = 0):
        """
        Send bulletins to TC2 peer since given timestamp.

        Args:
            peer_id: TC2 peer node ID
            since_us: Timestamp in microseconds to sync from
        """
        from ...db.messages import MessageRepository
        from ...db.users import UserRepository

        msg_repo = MessageRepository(self.db)
        user_repo = UserRepository(self.db)

        # Get bulletins since last sync
        bulletins = msg_repo.get_messages_since(since_us, msg_types=["bulletin"])

        for bulletin in bulletins:
            # Check if already synced to this peer
            if self._already_synced(bulletin.uuid, peer_id):
                continue

            # Get sender info
            sender = user_repo.get_user_by_id(bulletin.sender_user_id) if bulletin.sender_user_id else None
            sender_short = (sender.username[:8] if sender else "anon")[:8]

            # Get board name
            board_name = self._get_board_name(bulletin.board_id) or "general"

            # Decrypt subject and body for sync (TC2 doesn't encrypt)
            subject, body = self._decrypt_bulletin_for_sync(bulletin)

            if body is None:
                logger.warning(f"Could not decrypt bulletin {bulletin.uuid[:8]} for sync")
                continue

            # Send in TC2 format
            await self.send_bulletin(
                board=board_name,
                sender_short=sender_short,
                subject=subject or "(no subject)",
                body=body,
                uuid=bulletin.uuid,
                peer_id=peer_id
            )

            # Log sync
            self._log_sync(bulletin.uuid, peer_id, "sent")

            # Rate limiting - don't flood
            await self._rate_limit_delay()

        logger.info(f"Synced {len(bulletins)} bulletins to TC2 peer {peer_id}")

    async def send_bulletin(
        self,
        board: str,
        sender_short: str,
        subject: str,
        body: str,
        uuid: str,
        peer_id: str
    ):
        """
        Send bulletin in TC2 format.

        Format: BULLETIN|board|sender_short|subject|content|uuid
        """
        # Escape pipe characters in content
        subject_safe = subject.replace("|", "¦")
        body_safe = body.replace("|", "¦")

        tc2_msg = f"{TYPE_BULLETIN}|{board}|{sender_short}|{subject_safe}|{body_safe}|{uuid}"

        if self.mesh:
            await self.mesh.send_dm(tc2_msg, peer_id)
            logger.debug(f"Sent TC2 bulletin to {peer_id}: {uuid[:8]}")

    async def send_mail(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        uuid: str,
        peer_id: str
    ):
        """
        Send mail in TC2 format.

        Format: MAIL|sender|recipient|subject|content|uuid
        """
        subject_safe = subject.replace("|", "¦")
        body_safe = body.replace("|", "¦")

        tc2_msg = f"{TYPE_MAIL}|{sender}|{recipient}|{subject_safe}|{body_safe}|{uuid}"

        if self.mesh:
            await self.mesh.send_dm(tc2_msg, peer_id)
            logger.debug(f"Sent TC2 mail to {peer_id}: {uuid[:8]}")

    async def send_delete_bulletin(self, uuid: str, peer_id: str):
        """Send bulletin delete request."""
        tc2_msg = f"{TYPE_DELETE_BULLETIN}|{uuid}"
        if self.mesh:
            await self.mesh.send_dm(tc2_msg, peer_id)

    async def send_delete_mail(self, uuid: str, peer_id: str):
        """Send mail delete request."""
        tc2_msg = f"{TYPE_DELETE_MAIL}|{uuid}"
        if self.mesh:
            await self.mesh.send_dm(tc2_msg, peer_id)

    def handle_message(self, raw: str, sender: str) -> bool:
        """
        Handle incoming TC2 format message.

        Returns True if message was handled, False if not TC2 format.
        """
        parsed = self.parse_message(raw)
        if not parsed:
            return False

        logger.debug(f"Received TC2 {parsed.msg_type} from {sender}")

        if parsed.msg_type == TYPE_BULLETIN:
            self._handle_bulletin(parsed, sender)
        elif parsed.msg_type == TYPE_MAIL:
            self._handle_mail(parsed, sender)
        elif parsed.msg_type == TYPE_DELETE_BULLETIN:
            self._handle_delete_bulletin(parsed, sender)
        elif parsed.msg_type == TYPE_DELETE_MAIL:
            self._handle_delete_mail(parsed, sender)
        elif parsed.msg_type == TYPE_CHANNEL:
            self._handle_channel(parsed, sender)

        return True

    def _handle_bulletin(self, msg: TC2Message, sender: str):
        """Handle incoming TC2 bulletin."""
        from ...db.messages import MessageRepository
        from ...db.users import NodeRepository

        msg_repo = MessageRepository(self.db)
        node_repo = NodeRepository(self.db)

        # Check for duplicate
        if msg_repo.message_exists(msg.uuid):
            logger.debug(f"Duplicate bulletin ignored: {msg.uuid[:8]}")
            return

        # Get or create sender node
        sender_node = node_repo.get_or_create_node(sender)

        # Find or create board
        board_id = self._get_or_create_board(msg.board or "general")

        # Encrypt for storage
        body_enc = self._encrypt_for_storage(msg.body or "")
        subject_enc = self._encrypt_for_storage(msg.subject) if msg.subject else None

        # Store message
        from ...db.models import MessageType
        msg_repo.create_message(
            msg_type=MessageType.BULLETIN,
            sender_node_id=sender_node.id,
            board_id=board_id,
            body_enc=body_enc,
            subject_enc=subject_enc,
            origin_bbs=sender,
            message_uuid=msg.uuid
        )

        # Log receipt
        self._log_sync(msg.uuid, sender, "received")

        logger.info(f"Stored TC2 bulletin from {sender}: {msg.uuid[:8]}")

    def _handle_mail(self, msg: TC2Message, sender: str):
        """Handle incoming TC2 mail."""
        from ...db.messages import MessageRepository
        from ...db.users import UserRepository, NodeRepository

        msg_repo = MessageRepository(self.db)
        user_repo = UserRepository(self.db)
        node_repo = NodeRepository(self.db)

        # Check for duplicate
        if msg_repo.message_exists(msg.uuid):
            logger.debug(f"Duplicate mail ignored: {msg.uuid[:8]}")
            return

        # Find recipient user
        recipient = user_repo.get_user_by_username(msg.recipient) if msg.recipient else None
        if not recipient:
            logger.warning(f"TC2 mail recipient not found: {msg.recipient}")
            return

        # Get sender node
        sender_node = node_repo.get_or_create_node(sender)

        # Encrypt for recipient
        body_enc = self._encrypt_for_recipient(msg.body or "", recipient)
        subject_enc = self._encrypt_for_recipient(msg.subject, recipient) if msg.subject else None

        if body_enc is None:
            logger.error(f"Failed to encrypt TC2 mail for {msg.recipient}")
            return

        # Store message
        from ...db.models import MessageType
        msg_repo.create_message(
            msg_type=MessageType.MAIL,
            sender_node_id=sender_node.id,
            recipient_user_id=recipient.id,
            body_enc=body_enc,
            subject_enc=subject_enc,
            origin_bbs=sender,
            message_uuid=msg.uuid
        )

        self._log_sync(msg.uuid, sender, "received")
        logger.info(f"Stored TC2 mail from {sender} to {msg.recipient}: {msg.uuid[:8]}")

    def _handle_delete_bulletin(self, msg: TC2Message, sender: str):
        """Handle bulletin delete request."""
        from ...db.messages import MessageRepository

        msg_repo = MessageRepository(self.db)
        message = msg_repo.get_message_by_uuid(msg.uuid)

        if message and message.origin_bbs == sender:
            msg_repo.delete_message(message.id)
            logger.info(f"Deleted bulletin by TC2 request: {msg.uuid[:8]}")

    def _handle_delete_mail(self, msg: TC2Message, sender: str):
        """Handle mail delete request."""
        from ...db.messages import MessageRepository

        msg_repo = MessageRepository(self.db)
        message = msg_repo.get_message_by_uuid(msg.uuid)

        if message and message.origin_bbs == sender:
            msg_repo.delete_message(message.id)
            logger.info(f"Deleted mail by TC2 request: {msg.uuid[:8]}")

    def _handle_channel(self, msg: TC2Message, sender: str):
        """Handle channel share (informational only)."""
        logger.info(f"TC2 channel shared by {sender}: {msg.channel_name} -> {msg.channel_url}")

    def parse_message(self, raw: str) -> Optional[TC2Message]:
        """
        Parse incoming TC2 format message.

        Returns parsed TC2Message or None if not TC2 format.
        """
        if "|" not in raw:
            return None

        parts = raw.split("|")
        if len(parts) < 2:
            return None

        msg_type = parts[0]
        if msg_type not in VALID_TYPES:
            return None

        try:
            if msg_type == TYPE_BULLETIN and len(parts) >= 6:
                return TC2Message(
                    msg_type=msg_type,
                    board=parts[1],
                    sender_short=parts[2],
                    subject=parts[3].replace("¦", "|"),
                    body=parts[4].replace("¦", "|"),
                    uuid=parts[5],
                )

            elif msg_type == TYPE_MAIL and len(parts) >= 6:
                return TC2Message(
                    msg_type=msg_type,
                    sender=parts[1],
                    recipient=parts[2],
                    subject=parts[3].replace("¦", "|"),
                    body=parts[4].replace("¦", "|"),
                    uuid=parts[5],
                )

            elif msg_type == TYPE_DELETE_BULLETIN and len(parts) >= 2:
                return TC2Message(
                    msg_type=msg_type,
                    uuid=parts[1],
                )

            elif msg_type == TYPE_DELETE_MAIL and len(parts) >= 2:
                return TC2Message(
                    msg_type=msg_type,
                    uuid=parts[1],
                )

            elif msg_type == TYPE_CHANNEL and len(parts) >= 3:
                return TC2Message(
                    msg_type=msg_type,
                    uuid="",
                    channel_name=parts[1],
                    channel_url=parts[2],
                )

        except Exception as e:
            logger.error(f"Error parsing TC2 message: {e}")

        return None

    def is_tc2_message(self, raw: str) -> bool:
        """Check if message is TC2 format."""
        if "|" not in raw:
            return False
        first_part = raw.split("|")[0]
        return first_part in VALID_TYPES

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

    def _log_sync(self, uuid: str, peer_node_id: str, direction: str):
        """Log sync operation."""
        now_us = int(time.time() * 1_000_000)

        # Get or create peer
        peer_row = self.db.fetchone(
            "SELECT id FROM bbs_peers WHERE node_id = ?",
            (peer_node_id,)
        )

        if not peer_row:
            cursor = self.db.execute(
                "INSERT INTO bbs_peers (node_id, protocol, last_sync_us) VALUES (?, 'tc2', ?)",
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
            VALUES (?, ?, ?, 'acked', 1, ?)
        """, (uuid, peer_id, direction, now_us))

    def _get_board_name(self, board_id: Optional[int]) -> Optional[str]:
        """Get board name by ID."""
        if not board_id:
            return None
        row = self.db.fetchone("SELECT name FROM boards WHERE id = ?", (board_id,))
        return row[0] if row else None

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
        """Decrypt bulletin content for sending to TC2 peer."""
        try:
            # Public boards use master key
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
        """Encrypt content for storage (using master key for boards)."""
        master_key = self.sync_manager.bbs.master_key.key
        crypto = self.sync_manager.bbs.crypto
        return crypto.encrypt_string(plaintext, master_key)

    def _encrypt_for_recipient(self, plaintext: str, recipient) -> Optional[bytes]:
        """Encrypt content for specific recipient."""
        try:
            master_key = self.sync_manager.bbs.master_key
            crypto = self.sync_manager.bbs.crypto

            # Decrypt recipient's key
            recipient_key = master_key.decrypt_user_key(recipient.encryption_key)
            return crypto.encrypt_string(plaintext, recipient_key)
        except Exception as e:
            logger.error(f"Encrypt for recipient error: {e}")
            return None

    async def _rate_limit_delay(self):
        """Apply rate limiting delay between sync messages."""
        import asyncio
        await asyncio.sleep(3)  # 1 message per 3 seconds
