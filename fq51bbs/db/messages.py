"""
FQ51BBS Message Database Operations

CRUD operations for messages (mail and bulletins).
"""

import time
import uuid
import logging
from typing import Optional

from .connection import Database
from .models import Message, MessageType

logger = logging.getLogger(__name__)


class MessageRepository:
    """Repository for message-related database operations."""

    def __init__(self, db: Database):
        self.db = db

    def create_message(
        self,
        msg_type: MessageType,
        sender_node_id: int,
        body_enc: bytes,
        sender_user_id: Optional[int] = None,
        recipient_user_id: Optional[int] = None,
        recipient_node_id: Optional[int] = None,
        board_id: Optional[int] = None,
        subject_enc: Optional[bytes] = None,
        origin_bbs: Optional[str] = None,
        message_uuid: Optional[str] = None,
        expires_at_us: Optional[int] = None
    ) -> Message:
        """Create a new message."""
        now_us = int(time.time() * 1_000_000)
        msg_uuid = message_uuid or str(uuid.uuid4())

        cursor = self.db.execute("""
            INSERT INTO messages (
                uuid, msg_type, board_id, sender_user_id, sender_node_id,
                recipient_user_id, recipient_node_id, subject_enc, body_enc,
                created_at_us, origin_bbs, expires_at_us
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            msg_uuid,
            msg_type.value,
            board_id,
            sender_user_id,
            sender_node_id,
            recipient_user_id,
            recipient_node_id,
            subject_enc,
            body_enc,
            now_us,
            origin_bbs,
            expires_at_us
        ))

        return Message(
            id=cursor.lastrowid,
            uuid=msg_uuid,
            msg_type=msg_type,
            board_id=board_id,
            sender_user_id=sender_user_id,
            sender_node_id=sender_node_id,
            recipient_user_id=recipient_user_id,
            recipient_node_id=recipient_node_id,
            subject_enc=subject_enc,
            body_enc=body_enc,
            created_at_us=now_us,
            origin_bbs=origin_bbs,
            expires_at_us=expires_at_us
        )

    def get_message_by_id(self, message_id: int) -> Optional[Message]:
        """Get message by ID."""
        row = self.db.fetchone("SELECT * FROM messages WHERE id = ?", (message_id,))
        return self._row_to_message(row) if row else None

    def get_message_by_uuid(self, uuid: str) -> Optional[Message]:
        """Get message by UUID."""
        row = self.db.fetchone("SELECT * FROM messages WHERE uuid = ?", (uuid,))
        return self._row_to_message(row) if row else None

    def get_user_mail(
        self,
        user_id: int,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> list[Message]:
        """Get mail messages for a user."""
        sql = """
            SELECT * FROM messages
            WHERE recipient_user_id = ? AND msg_type = 'mail'
        """
        params = [user_id]

        if unread_only:
            sql += " AND read_at_us IS NULL"

        sql += " ORDER BY created_at_us DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.db.fetchall(sql, tuple(params))
        return [self._row_to_message(row) for row in rows]

    def get_mail_for_node(
        self,
        node_id: int,
        unread_only: bool = False,
        limit: int = 50
    ) -> list[Message]:
        """Get mail messages addressed to a specific node."""
        sql = """
            SELECT * FROM messages
            WHERE recipient_node_id = ? AND msg_type = 'mail'
        """
        params = [node_id]

        if unread_only:
            sql += " AND read_at_us IS NULL"

        sql += " ORDER BY created_at_us DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(sql, tuple(params))
        return [self._row_to_message(row) for row in rows]

    def count_unread_mail(self, user_id: int) -> int:
        """Count unread mail for a user."""
        row = self.db.fetchone("""
            SELECT COUNT(*) FROM messages
            WHERE recipient_user_id = ?
            AND msg_type = 'mail'
            AND read_at_us IS NULL
        """, (user_id,))
        return row[0] if row else 0

    def mark_as_read(self, message_id: int):
        """Mark a message as read."""
        now_us = int(time.time() * 1_000_000)
        self.db.execute(
            "UPDATE messages SET read_at_us = ? WHERE id = ?",
            (now_us, message_id)
        )

    def mark_as_delivered(self, message_id: int):
        """Mark a message as delivered."""
        now_us = int(time.time() * 1_000_000)
        self.db.execute(
            "UPDATE messages SET delivered_at_us = ? WHERE id = ?",
            (now_us, message_id)
        )

    def update_delivery_attempt(self, message_id: int, forwarded_to: Optional[str] = None):
        """Update delivery attempt tracking."""
        now_us = int(time.time() * 1_000_000)

        if forwarded_to:
            self.db.execute("""
                UPDATE messages
                SET delivery_attempts = delivery_attempts + 1,
                    last_attempt_us = ?,
                    forwarded_to = ?,
                    hop_count = hop_count + 1
                WHERE id = ?
            """, (now_us, forwarded_to, message_id))
        else:
            self.db.execute("""
                UPDATE messages
                SET delivery_attempts = delivery_attempts + 1,
                    last_attempt_us = ?
                WHERE id = ?
            """, (now_us, message_id))

    def delete_message(self, message_id: int) -> bool:
        """Delete a message."""
        cursor = self.db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        return cursor.rowcount > 0

    def delete_user_messages(self, user_id: int) -> int:
        """Delete all messages for a user (sent and received)."""
        cursor = self.db.execute("""
            DELETE FROM messages
            WHERE sender_user_id = ? OR recipient_user_id = ?
        """, (user_id, user_id))
        return cursor.rowcount

    def get_board_messages(
        self,
        board_id: int,
        limit: int = 50,
        offset: int = 0,
        since_us: Optional[int] = None
    ) -> list[Message]:
        """Get messages for a bulletin board."""
        sql = """
            SELECT * FROM messages
            WHERE board_id = ? AND msg_type = 'bulletin'
        """
        params = [board_id]

        if since_us is not None:
            sql += " AND created_at_us > ?"
            params.append(since_us)

        sql += " ORDER BY created_at_us DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.db.fetchall(sql, tuple(params))
        return [self._row_to_message(row) for row in rows]

    def count_board_messages(self, board_id: int) -> int:
        """Count messages on a board."""
        row = self.db.fetchone(
            "SELECT COUNT(*) FROM messages WHERE board_id = ? AND msg_type = 'bulletin'",
            (board_id,)
        )
        return row[0] if row else 0

    def get_pending_deliveries(self, limit: int = 10) -> list[Message]:
        """Get messages pending delivery."""
        rows = self.db.fetchall("""
            SELECT * FROM messages
            WHERE msg_type = 'mail'
            AND delivered_at_us IS NULL
            AND delivery_attempts < 3
            AND hop_count < 3
            ORDER BY created_at_us
            LIMIT ?
        """, (limit,))
        return [self._row_to_message(row) for row in rows]

    def get_messages_since(
        self,
        since_us: int,
        msg_types: Optional[list[str]] = None
    ) -> list[Message]:
        """Get messages created since timestamp (for sync)."""
        sql = "SELECT * FROM messages WHERE created_at_us > ?"
        params = [since_us]

        if msg_types:
            placeholders = ",".join("?" for _ in msg_types)
            sql += f" AND msg_type IN ({placeholders})"
            params.extend(msg_types)

        sql += " ORDER BY created_at_us"

        rows = self.db.fetchall(sql, tuple(params))
        return [self._row_to_message(row) for row in rows]

    def delete_expired_messages(self) -> int:
        """Delete expired messages."""
        now_us = int(time.time() * 1_000_000)
        cursor = self.db.execute(
            "DELETE FROM messages WHERE expires_at_us IS NOT NULL AND expires_at_us < ?",
            (now_us,)
        )
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(f"Deleted {deleted} expired messages")
        return deleted

    def message_exists(self, uuid: str) -> bool:
        """Check if a message with UUID exists (for deduplication)."""
        row = self.db.fetchone(
            "SELECT 1 FROM messages WHERE uuid = ?",
            (uuid,)
        )
        return row is not None

    def _row_to_message(self, row) -> Message:
        """Convert database row to Message object."""
        return Message(
            id=row["id"],
            uuid=row["uuid"],
            msg_type=MessageType(row["msg_type"]),
            board_id=row["board_id"],
            sender_user_id=row["sender_user_id"],
            sender_node_id=row["sender_node_id"],
            recipient_user_id=row["recipient_user_id"],
            recipient_node_id=row["recipient_node_id"],
            subject_enc=row["subject_enc"],
            body_enc=row["body_enc"],
            created_at_us=row["created_at_us"],
            delivered_at_us=row["delivered_at_us"],
            read_at_us=row["read_at_us"],
            expires_at_us=row["expires_at_us"],
            origin_bbs=row["origin_bbs"],
            delivery_attempts=row["delivery_attempts"],
            last_attempt_us=row["last_attempt_us"],
            forwarded_to=row["forwarded_to"],
            hop_count=row["hop_count"]
        )
