"""
FQ51BBS Main BBS Class

Central orchestrator for the BBS system.
"""

import asyncio
import logging
import signal
import time
from typing import Optional

from ..config import Config
from .crypto import CryptoManager, MasterKeyManager
from .rate_limiter import RateLimiter, CommandThrottler

logger = logging.getLogger(__name__)


class FQ51BBS:
    """
    Main FQ51BBS class - orchestrates all BBS components.

    Responsibilities:
    - Initialize and manage database connection
    - Manage Meshtastic interface
    - Route messages to command dispatcher
    - Coordinate inter-BBS sync
    - Handle graceful shutdown
    """

    def __init__(self, config: Config):
        """
        Initialize FQ51BBS with configuration.

        Args:
            config: Loaded configuration object
        """
        self.config = config
        self.running = False
        self.start_time: float = 0

        # Core components
        self.crypto = CryptoManager(
            time_cost=config.crypto.argon2_time_cost,
            memory_cost_kb=config.crypto.argon2_memory_kb,
            parallelism=config.crypto.argon2_parallelism
        )
        self.master_key = MasterKeyManager(self.crypto)

        # Rate limiting
        self.rate_limiter = RateLimiter(
            messages_per_minute=config.rate_limits.messages_per_minute,
            sync_messages_per_minute=config.rate_limits.sync_messages_per_minute,
            commands_per_minute=config.rate_limits.commands_per_minute
        )
        self.throttler = CommandThrottler()

        # These will be initialized in setup()
        self.db = None
        self.mesh = None
        self.dispatcher = None
        self.sync_manager = None
        self.mail_service = None
        self.board_service = None

        # Session tracking
        self._sessions: dict = {}  # node_id -> session info

        # Statistics
        self.stats = BBSStats()

        logger.info(f"FQ51BBS initialized: {config.bbs.name}")

    def setup(self):
        """
        Initialize all components.

        Called before run() to set up database, mesh connection, etc.
        """
        logger.info("Setting up FQ51BBS components...")

        # Initialize master key from admin password
        # In production, salt should be loaded from database
        self.master_key.initialize(self.config.bbs.admin_password)

        # Initialize database
        from ..db.connection import Database
        self.db = Database(self.config.database.path)
        self.db.initialize()

        # Initialize Meshtastic interface
        from ..mesh.interface import MeshInterface
        self.mesh = MeshInterface(self.config.meshtastic)

        # Initialize mail service
        if self.config.features.mail_enabled:
            from .mail import MailService
            self.mail_service = MailService(self)
            logger.info("Mail service initialized")

        # Initialize board service
        if self.config.features.boards_enabled:
            from .boards import BoardService
            self.board_service = BoardService(self)
            logger.info("Board service initialized")

        # Initialize command dispatcher
        from ..commands.dispatcher import CommandDispatcher
        self.dispatcher = CommandDispatcher(self)

        # Initialize sync manager if enabled
        if self.config.sync.enabled:
            from ..sync.manager import SyncManager
            self.sync_manager = SyncManager(self.config.sync, self.db, self.mesh)

        logger.info("FQ51BBS setup complete")

    def run(self):
        """
        Main run loop - starts the BBS.

        Connects to Meshtastic, registers handlers, and runs until shutdown.
        """
        self.setup()
        self.running = True
        self.start_time = time.time()

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info(f"Starting {self.config.bbs.name}...")

        try:
            # Connect to Meshtastic
            self.mesh.connect()
            self.mesh.on_message(self._handle_message)

            # Start async event loop
            asyncio.run(self._main_loop())

        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            raise
        finally:
            self.shutdown()

    async def _main_loop(self):
        """Main async event loop."""
        logger.info(f"{self.config.bbs.name} is now running")

        # Send startup announcement if configured
        if self.config.bbs.announcement_interval_hours > 0:
            await self._announce()

        # Main loop
        while self.running:
            try:
                # Process pending tasks
                await self._process_pending()

                # Periodic maintenance
                await self._maintenance()

                # Small sleep to prevent busy loop
                await asyncio.sleep(0.1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in main loop iteration: {e}")

    async def _process_pending(self):
        """Process any pending operations."""
        # Check for pending mail deliveries
        if self.config.features.mail_enabled:
            await self._process_mail_queue()

        # Check for sync operations
        if self.sync_manager:
            await self.sync_manager.tick()

    async def _maintenance(self):
        """Periodic maintenance tasks."""
        # Run every 5 minutes
        if not hasattr(self, '_last_maintenance'):
            self._last_maintenance = 0

        now = time.time()
        if now - self._last_maintenance < 300:
            return

        self._last_maintenance = now

        # Clean up rate limiter buckets
        self.rate_limiter.cleanup()

        # Clean up expired sessions
        self._cleanup_sessions()

        # Log stats
        logger.info(f"Stats: {self.stats}")

    async def _process_mail_queue(self):
        """Process pending mail deliveries."""
        if self.mail_service:
            await self.mail_service._process_pending_deliveries()

    async def _announce(self):
        """Send BBS announcement to mesh."""
        if not self.mesh.connected:
            return

        msg = f"[{self.config.bbs.callsign}] {self.config.bbs.name} online. Send H for help."
        await self.mesh.send_broadcast(msg, self.config.meshtastic.public_channel)
        logger.info("Sent startup announcement")

    def _handle_message(self, packet: dict):
        """
        Handle incoming Meshtastic message.

        This is the main entry point for all incoming messages.
        """
        sender = packet.get("fromId", "")
        text = packet.get("text", "")
        channel = packet.get("channel", 0)

        if not text or not sender:
            return

        self.stats.messages_received += 1

        # Rate limiting
        if not self.rate_limiter.check(sender, "command"):
            logger.warning(f"Rate limited: {sender}")
            return

        # Check operating mode
        if self.config.operating_mode.mode == "repeater":
            self._handle_repeater_mode(packet)
            return

        # Dispatch command
        try:
            response = self.dispatcher.dispatch(text, sender, channel)
            if response:
                asyncio.create_task(self._send_response(sender, response))
        except Exception as e:
            logger.error(f"Error handling message from {sender}: {e}")

    def _handle_repeater_mode(self, packet: dict):
        """Handle message in repeater mode (forward only)."""
        # TODO: Implement repeater forwarding
        pass

    async def _send_response(self, destination: str, message: str):
        """Send response with throttling."""
        should_send, delay = self.throttler.should_respond(destination)

        if not should_send:
            return

        if delay > 0:
            await asyncio.sleep(delay)

        await self.mesh.send_dm(message, destination)
        self.throttler.record_response(destination)
        self.stats.messages_sent += 1

    def _cleanup_sessions(self):
        """Remove expired sessions."""
        now = time.time()
        timeout = 3600  # 1 hour session timeout

        expired = [
            node_id for node_id, session in self._sessions.items()
            if now - session.get("last_activity", 0) > timeout
        ]

        for node_id in expired:
            del self._sessions[node_id]
            logger.debug(f"Session expired: {node_id}")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False

    def shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down FQ51BBS...")

        self.running = False

        # Disconnect from mesh
        if self.mesh:
            self.mesh.disconnect()

        # Close database
        if self.db:
            self.db.close()

        # Clear master key from memory
        self.master_key.clear()

        logger.info("FQ51BBS shutdown complete")

    @property
    def uptime(self) -> float:
        """Return uptime in seconds."""
        if self.start_time == 0:
            return 0
        return time.time() - self.start_time

    @property
    def session_count(self) -> int:
        """Return number of active sessions."""
        return len(self._sessions)


class BBSStats:
    """Statistics tracking for BBS."""

    def __init__(self):
        self.messages_received: int = 0
        self.messages_sent: int = 0
        self.commands_processed: int = 0
        self.users_registered: int = 0
        self.sync_operations: int = 0
        self.errors: int = 0
        self.start_time: float = time.time()

    @property
    def messages_today(self) -> int:
        """Messages received today (approximate)."""
        # Simple approximation - in production would use daily counter
        return self.messages_received

    def __str__(self) -> str:
        return (
            f"rx={self.messages_received}, tx={self.messages_sent}, "
            f"cmds={self.commands_processed}, errs={self.errors}"
        )
