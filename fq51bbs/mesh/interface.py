"""
FQ51BBS Meshtastic Interface

Handles connection to Meshtastic device and message pub/sub.
"""

import asyncio
import logging
import time
from typing import Callable, Optional

try:
    import meshtastic
    import meshtastic.serial_interface
    import meshtastic.tcp_interface
    from pubsub import pub
    MESHTASTIC_AVAILABLE = True
except ImportError:
    MESHTASTIC_AVAILABLE = False

from ..config import MeshtasticConfig

logger = logging.getLogger(__name__)


class MeshInterface:
    """
    Meshtastic connection interface.

    Supports Serial, TCP, and BLE connections.
    Uses pub/sub for async message handling.
    """

    # Broadcast address
    BROADCAST_ADDR = "^all"

    def __init__(self, config: MeshtasticConfig):
        """
        Initialize mesh interface with configuration.

        Args:
            config: Meshtastic connection settings
        """
        if not MESHTASTIC_AVAILABLE:
            raise ImportError(
                "Meshtastic library not installed. "
                "Install with: pip install meshtastic"
            )

        self.config = config
        self._interface = None
        self._connected = False
        self._message_handlers: list[Callable] = []
        self._node_id: Optional[str] = None

    @property
    def connected(self) -> bool:
        """Check if connected to Meshtastic device."""
        return self._connected and self._interface is not None

    @property
    def node_id(self) -> Optional[str]:
        """Get our node ID."""
        return self._node_id

    def connect(self):
        """Establish connection to Meshtastic device."""
        logger.info(
            f"Connecting to Meshtastic via {self.config.connection_type}..."
        )

        try:
            if self.config.connection_type == "serial":
                self._interface = meshtastic.serial_interface.SerialInterface(
                    devPath=self.config.serial_port
                )
            elif self.config.connection_type == "tcp":
                self._interface = meshtastic.tcp_interface.TCPInterface(
                    hostname=self.config.tcp_host,
                    portNumber=self.config.tcp_port
                )
            elif self.config.connection_type == "ble":
                # BLE support requires additional setup
                raise NotImplementedError("BLE connection not yet implemented")
            else:
                raise ValueError(
                    f"Unknown connection type: {self.config.connection_type}"
                )

            # Get our node info
            my_info = self._interface.getMyNodeInfo()
            if my_info:
                self._node_id = my_info.get("user", {}).get("id")

            # Subscribe to message events
            pub.subscribe(self._on_receive, "meshtastic.receive.text")
            pub.subscribe(self._on_connection, "meshtastic.connection.established")
            pub.subscribe(self._on_disconnect, "meshtastic.connection.lost")

            self._connected = True
            logger.info(f"Connected to Meshtastic. Node ID: {self._node_id}")

        except Exception as e:
            logger.error(f"Failed to connect to Meshtastic: {e}")
            self._connected = False
            raise

    def disconnect(self):
        """Disconnect from Meshtastic device."""
        if self._interface:
            try:
                self._interface.close()
            except Exception as e:
                logger.warning(f"Error closing interface: {e}")
            finally:
                self._interface = None
                self._connected = False
                logger.info("Disconnected from Meshtastic")

    def on_message(self, handler: Callable[[dict], None]):
        """
        Register a message handler.

        Handler receives packet dict with keys:
        - fromId: Sender node ID
        - toId: Destination node ID
        - text: Message text
        - channel: Channel index
        """
        self._message_handlers.append(handler)

    def _on_receive(self, packet, interface):
        """Internal handler for received text messages."""
        if not packet:
            return

        # Extract relevant fields
        message_data = {
            "fromId": packet.get("fromId", ""),
            "toId": packet.get("toId", ""),
            "text": packet.get("decoded", {}).get("text", ""),
            "channel": packet.get("channel", 0),
            "hopLimit": packet.get("hopLimit"),
            "rxTime": packet.get("rxTime"),
            "rxSnr": packet.get("rxSnr"),
            "rxRssi": packet.get("rxRssi"),
        }

        # Call all registered handlers
        for handler in self._message_handlers:
            try:
                handler(message_data)
            except Exception as e:
                logger.error(f"Error in message handler: {e}")

    def _on_connection(self, interface, topic=pub.AUTO_TOPIC):
        """Handle connection established event."""
        self._connected = True
        logger.info("Meshtastic connection established")

    def _on_disconnect(self, interface, topic=pub.AUTO_TOPIC):
        """Handle disconnection event."""
        self._connected = False
        logger.warning("Meshtastic connection lost")

    async def send_text(
        self,
        text: str,
        destination: str,
        channel: int = 0,
        want_ack: bool = False
    ) -> bool:
        """
        Send text message.

        Args:
            text: Message text
            destination: Destination node ID or "^all" for broadcast
            channel: Channel index
            want_ack: Request acknowledgment

        Returns:
            True if message was sent (not necessarily delivered)
        """
        if not self.connected:
            logger.error("Cannot send: not connected")
            return False

        try:
            self._interface.sendText(
                text=text,
                destinationId=destination,
                channelIndex=channel,
                wantAck=want_ack
            )
            logger.debug(f"Sent to {destination}: {text[:50]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    async def send_dm(self, text: str, destination: str, want_ack: bool = True) -> bool:
        """Send direct message to specific node."""
        return await self.send_text(
            text,
            destination,
            channel=self.config.channel_index,
            want_ack=want_ack
        )

    async def send_broadcast(self, text: str, channel: int = 0) -> bool:
        """Send broadcast message to channel."""
        return await self.send_text(
            text,
            self.BROADCAST_ADDR,
            channel=channel,
            want_ack=False
        )

    def get_node_info(self, node_id: str) -> Optional[dict]:
        """Get information about a specific node."""
        if not self.connected:
            return None

        try:
            nodes = self._interface.nodes
            return nodes.get(node_id)
        except Exception:
            return None

    def get_all_nodes(self) -> dict:
        """Get all known nodes."""
        if not self.connected:
            return {}

        try:
            return self._interface.nodes or {}
        except Exception:
            return {}


class MockMeshInterface(MeshInterface):
    """
    Mock Meshtastic interface for testing.

    Useful for development without actual hardware.
    """

    def __init__(self, config: MeshtasticConfig):
        self.config = config
        self._connected = False
        self._message_handlers: list[Callable] = []
        self._node_id = "!mock1234"
        self._sent_messages: list[dict] = []

    def connect(self):
        """Simulate connection."""
        self._connected = True
        logger.info("Mock Meshtastic interface connected")

    def disconnect(self):
        """Simulate disconnection."""
        self._connected = False
        logger.info("Mock Meshtastic interface disconnected")

    async def send_text(
        self,
        text: str,
        destination: str,
        channel: int = 0,
        want_ack: bool = False
    ) -> bool:
        """Record sent message for testing."""
        if not self._connected:
            return False

        self._sent_messages.append({
            "text": text,
            "destination": destination,
            "channel": channel,
            "want_ack": want_ack,
            "timestamp": time.time()
        })

        logger.debug(f"Mock sent to {destination}: {text}")
        return True

    def simulate_receive(self, from_id: str, text: str, channel: int = 0):
        """Simulate receiving a message (for testing)."""
        message_data = {
            "fromId": from_id,
            "toId": self._node_id,
            "text": text,
            "channel": channel,
        }

        for handler in self._message_handlers:
            handler(message_data)

    def get_sent_messages(self) -> list[dict]:
        """Get list of sent messages for verification."""
        return self._sent_messages

    def clear_sent_messages(self):
        """Clear sent message history."""
        self._sent_messages = []
