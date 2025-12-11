"""
Tests for FQ51BBS Sync Protocols

Tests TC2-BBS, meshing-around, and FQ51 native sync protocols.
"""

import base64
import json
import pickle
import pytest
from unittest.mock import MagicMock, AsyncMock

from fq51bbs.sync.compat.tc2_bbs import TC2Compatibility, TC2Message, TYPE_BULLETIN, TYPE_MAIL
from fq51bbs.sync.compat.meshing_around import MeshingAroundCompatibility, BBSLinkMessage
from fq51bbs.sync.compat.fq51_native import FQ51NativeSync, FQ51SyncMessage


class MockSyncManager:
    """Mock sync manager for testing protocol handlers."""

    def __init__(self):
        self.db = MagicMock()
        self.mesh = AsyncMock()
        self.bbs = MagicMock()
        self.config = MagicMock()
        self.config.bbs_name = "TestBBS"
        self.config.callsign = "TEST"

        # Mock database methods
        self.db.fetchone = MagicMock(return_value=None)
        self.db.execute = MagicMock()

        # Mock BBS crypto
        self.bbs.crypto = MagicMock()
        self.bbs.crypto.encrypt_string = MagicMock(return_value=b"encrypted")
        self.bbs.crypto.decrypt_string = MagicMock(return_value="decrypted")
        self.bbs.master_key = MagicMock()
        self.bbs.master_key.key = b"testkey"


class TestTC2Protocol:
    """Tests for TC2-BBS protocol."""

    def setup_method(self):
        self.sync_manager = MockSyncManager()
        self.tc2 = TC2Compatibility(self.sync_manager)

    def test_is_tc2_message_bulletin(self):
        """Test TC2 message detection for bulletin."""
        assert self.tc2.is_tc2_message("BULLETIN|general|user|subject|body|uuid123")
        assert self.tc2.is_tc2_message("MAIL|sender|recipient|subject|body|uuid123")
        assert self.tc2.is_tc2_message("DELETE_BULLETIN|uuid123")
        assert self.tc2.is_tc2_message("DELETE_MAIL|uuid123")

    def test_is_not_tc2_message(self):
        """Test non-TC2 messages."""
        assert not self.tc2.is_tc2_message("Hello world")
        assert not self.tc2.is_tc2_message("FQ51|1|HELLO|payload")
        assert not self.tc2.is_tc2_message("bbslink data")
        assert not self.tc2.is_tc2_message("UNKNOWN|field|field")

    def test_parse_bulletin(self):
        """Test parsing TC2 bulletin message."""
        raw = "BULLETIN|general|testuser|Test Subject|Test body content|uuid-12345"
        msg = self.tc2.parse_message(raw)

        assert msg is not None
        assert msg.msg_type == TYPE_BULLETIN
        assert msg.board == "general"
        assert msg.sender_short == "testuser"
        assert msg.subject == "Test Subject"
        assert msg.body == "Test body content"
        assert msg.uuid == "uuid-12345"

    def test_parse_mail(self):
        """Test parsing TC2 mail message."""
        raw = "MAIL|sender@bbs|recipient|Hello|Message body|mail-uuid"
        msg = self.tc2.parse_message(raw)

        assert msg is not None
        assert msg.msg_type == TYPE_MAIL
        assert msg.sender == "sender@bbs"
        assert msg.recipient == "recipient"
        assert msg.subject == "Hello"
        assert msg.body == "Message body"
        assert msg.uuid == "mail-uuid"

    def test_parse_delete_bulletin(self):
        """Test parsing TC2 delete bulletin."""
        raw = "DELETE_BULLETIN|uuid-to-delete"
        msg = self.tc2.parse_message(raw)

        assert msg is not None
        assert msg.msg_type == "DELETE_BULLETIN"
        assert msg.uuid == "uuid-to-delete"

    def test_parse_delete_mail(self):
        """Test parsing TC2 delete mail."""
        raw = "DELETE_MAIL|mail-uuid-to-delete"
        msg = self.tc2.parse_message(raw)

        assert msg is not None
        assert msg.msg_type == "DELETE_MAIL"
        assert msg.uuid == "mail-uuid-to-delete"

    def test_parse_with_pipe_escape(self):
        """Test parsing message with escaped pipe characters."""
        raw = "BULLETIN|general|user|Subject¦with¦pipes|Body¦content|uuid"
        msg = self.tc2.parse_message(raw)

        assert msg is not None
        assert msg.subject == "Subject|with|pipes"
        assert msg.body == "Body|content"

    def test_parse_invalid_message(self):
        """Test parsing invalid messages returns None."""
        assert self.tc2.parse_message("") is None
        assert self.tc2.parse_message("no pipes here") is None
        assert self.tc2.parse_message("BULLETIN|too|few") is None
        assert self.tc2.parse_message("UNKNOWN|type|here|more|fields|uuid") is None


class TestMeshingAroundProtocol:
    """Tests for meshing-around bbslink/bbsack protocol."""

    def setup_method(self):
        self.sync_manager = MockSyncManager()
        self.ma = MeshingAroundCompatibility(self.sync_manager)

    def test_is_meshing_around_message(self):
        """Test meshing-around message detection."""
        # Create valid bbslink message
        payload = [123, "Subject", "Body", "sender", 1234567890, 0, 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()

        assert self.ma.is_meshing_around_message(f"bbslink {encoded}")
        assert self.ma.is_meshing_around_message("bbsack 123")

    def test_is_not_meshing_around_message(self):
        """Test non-meshing-around messages."""
        assert not self.ma.is_meshing_around_message("Hello world")
        assert not self.ma.is_meshing_around_message("FQ51|1|HELLO|payload")
        assert not self.ma.is_meshing_around_message("BULLETIN|general|user|subj|body|uuid")

    def test_parse_bbslink(self):
        """Test parsing bbslink message."""
        payload = [42, "Test Subject", "Test Body", "testsender", 1702000000, 0, 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        raw = f"bbslink {encoded}"

        msg = self.ma.parse_bbslink(raw)

        assert msg is not None
        assert msg.msg_id == 42
        assert msg.subject == "Test Subject"
        assert msg.body == "Test Body"
        assert msg.sender_node == "testsender"
        assert msg.timestamp == 1702000000
        assert msg.thread_id == 0
        assert msg.reply_to == 0

    def test_parse_bbslink_with_thread(self):
        """Test parsing bbslink with thread info."""
        payload = [99, "Reply", "Reply body", "sender", 1702000000, 42, 41]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        raw = f"bbslink {encoded}"

        msg = self.ma.parse_bbslink(raw)

        assert msg is not None
        assert msg.thread_id == 42
        assert msg.reply_to == 41

    def test_parse_bbsack(self):
        """Test parsing bbsack message."""
        assert self.ma.parse_bbsack("bbsack 12345") == 12345
        assert self.ma.parse_bbsack("bbsack 0") == 0
        assert self.ma.parse_bbsack("bbsack 999999") == 999999

    def test_parse_bbsack_invalid(self):
        """Test parsing invalid bbsack messages."""
        assert self.ma.parse_bbsack("bbsack abc") is None
        assert self.ma.parse_bbsack("not bbsack") is None
        assert self.ma.parse_bbsack("") is None

    def test_parse_bbslink_invalid(self):
        """Test parsing invalid bbslink messages."""
        assert self.ma.parse_bbslink("not bbslink") is None
        assert self.ma.parse_bbslink("bbslink invalid_base64!!!") is None
        assert self.ma.parse_bbslink("bbslink ") is None

        # Valid base64 but not pickle or wrong format
        bad_payload = base64.b64encode(b"not pickle").decode()
        assert self.ma.parse_bbslink(f"bbslink {bad_payload}") is None


class TestFQ51Protocol:
    """Tests for FQ51 native protocol."""

    def setup_method(self):
        self.sync_manager = MockSyncManager()
        self.fq51 = FQ51NativeSync(self.sync_manager)

    def test_is_fq51_message(self):
        """Test FQ51 message detection."""
        assert self.fq51.is_fq51_message("FQ51|1|HELLO|payload")
        assert self.fq51.is_fq51_message("FQ51|1|SYNC_REQ|1234|bulletin")
        assert self.fq51.is_fq51_message("FQ51|1|SYNC_ACK|uuid")
        assert self.fq51.is_fq51_message("FQ51|1|SYNC_DONE|5")
        assert self.fq51.is_fq51_message("FQ51|1|DELETE|uuid")

    def test_is_not_fq51_message(self):
        """Test non-FQ51 messages."""
        assert not self.fq51.is_fq51_message("Hello world")
        assert not self.fq51.is_fq51_message("BULLETIN|general|user|subj|body|uuid")
        assert not self.fq51.is_fq51_message("bbslink data")
        assert not self.fq51.is_fq51_message("FQ51|1|UNKNOWN|payload")
        assert not self.fq51.is_fq51_message("FQ51|")

    def test_format_message(self):
        """Test message formatting."""
        msg = self.fq51._format_message("HELLO", "TEST:TestBBS|mail,bulletin")
        assert msg == "FQ51|1|HELLO|TEST:TestBBS|mail,bulletin"

        msg = self.fq51._format_message("SYNC_ACK", "uuid-123")
        assert msg == "FQ51|1|SYNC_ACK|uuid-123"

    def test_sync_message_encoding(self):
        """Test sync message JSON/base64 encoding."""
        sync_msg = FQ51SyncMessage(
            uuid="test-uuid-123",
            msg_type="bulletin",
            board="general",
            sender="testuser",
            subject="Test Subject",
            body="Test body content",
            timestamp_us=1702000000000000,
            origin_bbs="TEST"
        )

        # Encode like the protocol does
        from dataclasses import asdict
        msg_dict = asdict(sync_msg)
        json_str = json.dumps(msg_dict, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode()).decode()

        # Decode and verify
        decoded_json = base64.b64decode(encoded).decode()
        decoded_dict = json.loads(decoded_json)

        assert decoded_dict["uuid"] == "test-uuid-123"
        assert decoded_dict["msg_type"] == "bulletin"
        assert decoded_dict["board"] == "general"
        assert decoded_dict["sender"] == "testuser"
        assert decoded_dict["subject"] == "Test Subject"
        assert decoded_dict["body"] == "Test body content"

    def test_handle_hello(self):
        """Test handling HELLO message."""
        # The handler should register the peer
        self.fq51._handle_hello("PEER:PeerBBS|mail,bulletin", "!peernode")

        # Verify peer was registered
        self.sync_manager.db.execute.assert_called()


class TestProtocolDetection:
    """Tests for protocol auto-detection in sync manager."""

    def setup_method(self):
        self.sync_manager = MockSyncManager()
        self.tc2 = TC2Compatibility(self.sync_manager)
        self.ma = MeshingAroundCompatibility(self.sync_manager)
        self.fq51 = FQ51NativeSync(self.sync_manager)

    def test_detect_tc2(self):
        """Test TC2 protocol detection."""
        msg = "BULLETIN|general|user|subject|body|uuid"
        assert self.tc2.is_tc2_message(msg)
        assert not self.ma.is_meshing_around_message(msg)
        assert not self.fq51.is_fq51_message(msg)

    def test_detect_meshing_around(self):
        """Test meshing-around protocol detection."""
        payload = [1, "subj", "body", "sender", 123, 0, 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        msg = f"bbslink {encoded}"

        assert self.ma.is_meshing_around_message(msg)
        assert not self.tc2.is_tc2_message(msg)
        assert not self.fq51.is_fq51_message(msg)

    def test_detect_fq51(self):
        """Test FQ51 protocol detection."""
        msg = "FQ51|1|HELLO|TEST:TestBBS|mail,bulletin"
        assert self.fq51.is_fq51_message(msg)
        assert not self.tc2.is_tc2_message(msg)
        assert not self.ma.is_meshing_around_message(msg)

    def test_detect_none(self):
        """Test detection of non-sync messages."""
        msg = "Hello, this is a regular chat message"
        assert not self.tc2.is_tc2_message(msg)
        assert not self.ma.is_meshing_around_message(msg)
        assert not self.fq51.is_fq51_message(msg)


class TestSyncMessageDataclasses:
    """Tests for sync message dataclasses."""

    def test_tc2_message(self):
        """Test TC2Message dataclass."""
        msg = TC2Message(
            msg_type="BULLETIN",
            uuid="test-uuid",
            board="general",
            sender_short="testuser",
            subject="Subject",
            body="Body"
        )
        assert msg.msg_type == "BULLETIN"
        assert msg.uuid == "test-uuid"
        assert msg.board == "general"

    def test_bbslink_message(self):
        """Test BBSLinkMessage dataclass."""
        msg = BBSLinkMessage(
            msg_id=123,
            subject="Subject",
            body="Body",
            sender_node="!node123",
            timestamp=1702000000
        )
        assert msg.msg_id == 123
        assert msg.subject == "Subject"
        assert msg.thread_id == 0  # default
        assert msg.reply_to == 0  # default

    def test_fq51_sync_message(self):
        """Test FQ51SyncMessage dataclass."""
        msg = FQ51SyncMessage(
            uuid="test-uuid",
            msg_type="bulletin",
            board="general",
            sender="testuser",
            subject="Subject",
            body="Body",
            timestamp_us=1702000000000000,
            origin_bbs="TEST"
        )
        assert msg.uuid == "test-uuid"
        assert msg.msg_type == "bulletin"
        assert msg.timestamp_us == 1702000000000000


class TestEdgeCases:
    """Edge case tests for sync protocols."""

    def setup_method(self):
        self.sync_manager = MockSyncManager()

    def test_tc2_empty_fields(self):
        """Test TC2 with empty fields."""
        tc2 = TC2Compatibility(self.sync_manager)

        msg = tc2.parse_message("BULLETIN|||||uuid")
        assert msg is not None
        assert msg.board == ""
        assert msg.sender_short == ""

    def test_meshing_around_minimal_payload(self):
        """Test meshing-around with minimal payload."""
        ma = MeshingAroundCompatibility(self.sync_manager)

        # Minimum 5 fields required
        payload = [1, "s", "b", "n", 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        msg = ma.parse_bbslink(f"bbslink {encoded}")

        assert msg is not None
        assert msg.msg_id == 1
        assert msg.thread_id == 0  # default

    def test_fq51_empty_payload(self):
        """Test FQ51 with empty payload."""
        fq51 = FQ51NativeSync(self.sync_manager)

        # SYNC_ACK with empty payload
        assert fq51.is_fq51_message("FQ51|1|SYNC_DONE|")

    def test_unicode_content(self):
        """Test protocols with unicode content."""
        tc2 = TC2Compatibility(self.sync_manager)

        # TC2 with unicode
        msg = tc2.parse_message("BULLETIN|general|用户|主题|内容|uuid")
        assert msg is not None
        assert msg.sender_short == "用户"
        assert msg.subject == "主题"

        # meshing-around with unicode
        ma = MeshingAroundCompatibility(self.sync_manager)
        payload = [1, "主题", "内容", "用户", 0, 0, 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        msg = ma.parse_bbslink(f"bbslink {encoded}")
        assert msg is not None
        assert msg.subject == "主题"

    def test_large_message(self):
        """Test handling large messages."""
        ma = MeshingAroundCompatibility(self.sync_manager)

        # Large body
        large_body = "x" * 10000
        payload = [1, "subject", large_body, "sender", 0, 0, 0]
        encoded = base64.b64encode(pickle.dumps(payload)).decode()
        msg = ma.parse_bbslink(f"bbslink {encoded}")

        assert msg is not None
        assert len(msg.body) == 10000
