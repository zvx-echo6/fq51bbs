"""
FQ51BBS Sync Manager

Coordinates inter-BBS synchronization using polyglot protocol support.
Supports FQ51 native, TC2-BBS-mesh, and meshing-around protocols.
"""

import asyncio
import logging
import time
from typing import Optional, TYPE_CHECKING

from ..config import SyncConfig
from .compat.fq51_native import FQ51NativeSync
from .compat.tc2_bbs import TC2Compatibility
from .compat.meshing_around import MeshingAroundCompatibility

if TYPE_CHECKING:
    from ..core.bbs import FQ51BBS

logger = logging.getLogger(__name__)


class SyncManager:
    """
    Manages synchronization with peer BBS nodes.

    Supports multiple protocols:
    - fq51: Native FQ51BBS DM-based protocol (JSON/base64)
    - tc2: TC2-BBS-mesh pipe-delimited protocol
    - meshing-around: bbslink/bbsack protocol (pickle/base64)

    Features:
    - Automatic protocol detection for incoming messages
    - Per-peer protocol selection for outgoing sync
    - Rate-limited sync to prevent mesh flooding
    - UUID-based deduplication
    - Acknowledgment tracking for reliable delivery
    """

    def __init__(self, config: SyncConfig, db, mesh, bbs: Optional["FQ51BBS"] = None):
        """
        Initialize sync manager.

        Args:
            config: Sync configuration
            db: Database instance
            mesh: Mesh interface instance
            bbs: FQ51BBS instance (for encryption operations)
        """
        self.config = config
        self.db = db
        self.mesh = mesh
        self.bbs = bbs

        # Peer state tracking
        self._peers = {p.node_id: p for p in config.peers} if config.peers else {}
        self._peer_status = {}  # node_id -> {online, last_seen, last_sync}

        # Sync state
        self._last_bulletin_sync = 0
        self._pending_syncs = []
        self._sync_lock = asyncio.Lock()

        # Protocol handlers
        self._fq51 = FQ51NativeSync(self)
        self._tc2 = TC2Compatibility(self)
        self._meshing_around = MeshingAroundCompatibility(self)

        logger.info(f"SyncManager initialized with {len(self._peers)} peers")

    @property
    def total_peer_count(self) -> int:
        """Total configured peers."""
        return len(self._peers)

    @property
    def online_peer_count(self) -> int:
        """Count of recently seen peers."""
        now = time.time()
        timeout = 300  # 5 minutes
        return sum(
            1 for status in self._peer_status.values()
            if now - status.get("last_seen", 0) < timeout
        )

    @property
    def last_sync_time(self) -> float:
        """Timestamp of last sync operation."""
        return self._last_bulletin_sync

    @property
    def fq51_handler(self) -> FQ51NativeSync:
        """Get FQ51 native protocol handler."""
        return self._fq51

    @property
    def tc2_handler(self) -> TC2Compatibility:
        """Get TC2-BBS protocol handler."""
        return self._tc2

    @property
    def meshing_around_handler(self) -> MeshingAroundCompatibility:
        """Get meshing-around protocol handler."""
        return self._meshing_around

    async def tick(self):
        """
        Called periodically from main loop.

        Handles scheduled syncs and pending operations.
        """
        if not self.config.enabled:
            return

        now = time.time()

        # Check for scheduled bulletin sync
        sync_interval = self.config.bulletin_sync_interval_minutes * 60
        if now - self._last_bulletin_sync > sync_interval:
            await self._sync_bulletins()
            self._last_bulletin_sync = now

        # Process pending sync operations
        await self._process_pending()

        # Clean up stale pending ACKs
        await self._cleanup_pending_acks()

    async def _sync_bulletins(self):
        """Sync bulletins with all peers."""
        async with self._sync_lock:
            logger.info("Starting scheduled bulletin sync...")

            for node_id, peer in self._peers.items():
                if not peer.protocol:
                    continue

                try:
                    await self._sync_with_peer(node_id, peer.protocol)
                except Exception as e:
                    logger.error(f"Error syncing with {peer.name}: {e}")

            logger.info("Scheduled bulletin sync complete")

    async def _sync_with_peer(self, node_id: str, protocol: str):
        """Sync with a specific peer using their protocol."""
        logger.debug(f"Syncing with {node_id} using {protocol} protocol")

        # Get last sync timestamp for this peer
        since_us = self._get_last_sync_time(node_id)

        if protocol == "fq51":
            await self._fq51.sync_bulletins_to_peer(node_id, since_us)
        elif protocol == "tc2":
            await self._tc2.sync_bulletins_to_peer(node_id, since_us)
        elif protocol == "meshing-around":
            await self._meshing_around.sync_bulletins_to_peer(node_id, since_us)
        else:
            logger.warning(f"Unknown protocol: {protocol}")

    def _get_last_sync_time(self, node_id: str) -> int:
        """Get last sync timestamp for peer in microseconds."""
        row = self.db.fetchone(
            "SELECT last_sync_us FROM bbs_peers WHERE node_id = ?",
            (node_id,)
        )
        return row[0] if row else 0

    async def _process_pending(self):
        """Process pending sync operations."""
        if not self._pending_syncs:
            return

        # Process up to 5 pending syncs per tick
        for _ in range(min(5, len(self._pending_syncs))):
            if not self._pending_syncs:
                break

            sync_op = self._pending_syncs.pop(0)
            try:
                await self._execute_sync_op(sync_op)
            except Exception as e:
                logger.error(f"Error processing pending sync: {e}")

    async def _execute_sync_op(self, sync_op: dict):
        """Execute a pending sync operation."""
        op_type = sync_op.get("type")
        node_id = sync_op.get("node_id")
        protocol = sync_op.get("protocol")

        if op_type == "full_sync":
            await self._sync_with_peer(node_id, protocol)
        elif op_type == "delete":
            uuid = sync_op.get("uuid")
            if protocol == "fq51":
                await self._fq51.send_delete(uuid, node_id)
            elif protocol == "tc2":
                await self._tc2.send_delete_bulletin(uuid, node_id)

    async def _cleanup_pending_acks(self):
        """Clean up stale pending ACKs (older than 10 minutes)."""
        now = time.time()
        timeout = 600  # 10 minutes

        # Clean FQ51 pending ACKs
        stale_fq51 = [
            uuid for uuid, (_, ts) in self._fq51._pending_acks.items()
            if now - ts > timeout
        ]
        for uuid in stale_fq51:
            del self._fq51._pending_acks[uuid]
            logger.warning(f"FQ51 ACK timeout for {uuid[:8]}")

        # Clean meshing-around pending ACKs
        stale_ma = [
            msg_id for msg_id, ts in self._meshing_around._pending_acks.items()
            if isinstance(ts, float) and now - ts > timeout
        ]
        for msg_id in stale_ma:
            del self._meshing_around._pending_acks[msg_id]
            logger.warning(f"meshing-around ACK timeout for {msg_id}")

    def handle_sync_message(self, message: str, sender: str) -> bool:
        """
        Handle incoming sync message from peer.

        Routes to appropriate protocol handler based on message format.

        Returns True if message was handled, False otherwise.
        """
        if not self.config.enabled:
            return False

        # Update peer status
        self._update_peer_status(sender)

        # Try FQ51 native first (most specific prefix)
        if self._fq51.is_fq51_message(message):
            return self._fq51.handle_message(message, sender)

        # Try meshing-around (also specific prefixes)
        if self._meshing_around.is_meshing_around_message(message):
            return self._meshing_around.handle_message(message, sender)

        # Try TC2 (generic pipe format - check last)
        if self._tc2.is_tc2_message(message):
            return self._tc2.handle_message(message, sender)

        return False

    def _update_peer_status(self, node_id: str):
        """Update peer's last seen timestamp."""
        now = time.time()
        if node_id not in self._peer_status:
            self._peer_status[node_id] = {}
        self._peer_status[node_id]["last_seen"] = now
        self._peer_status[node_id]["online"] = True

    async def force_sync(self, peer_id: Optional[str] = None):
        """
        Force immediate sync with peer(s).

        Args:
            peer_id: Specific peer to sync with, or None for all peers
        """
        async with self._sync_lock:
            if peer_id:
                if peer_id in self._peers:
                    peer = self._peers[peer_id]
                    logger.info(f"Forcing sync with {peer.name} ({peer_id})")
                    await self._sync_with_peer(peer_id, peer.protocol)
                else:
                    logger.warning(f"Unknown peer: {peer_id}")
            else:
                logger.info("Forcing sync with all peers")
                await self._sync_bulletins()

    async def sync_new_message(self, message_uuid: str, msg_type: str = "bulletin"):
        """
        Queue sync of newly created message to all peers.

        Args:
            message_uuid: UUID of the new message
            msg_type: Type of message ("bulletin" or "mail")
        """
        for node_id, peer in self._peers.items():
            if not peer.protocol:
                continue

            self._pending_syncs.append({
                "type": "new_message",
                "node_id": node_id,
                "protocol": peer.protocol,
                "uuid": message_uuid,
                "msg_type": msg_type,
            })

        logger.debug(f"Queued sync for new {msg_type}: {message_uuid[:8]}")

    async def propagate_delete(self, message_uuid: str):
        """
        Propagate message deletion to all peers.

        Args:
            message_uuid: UUID of the deleted message
        """
        for node_id, peer in self._peers.items():
            if not peer.protocol:
                continue

            self._pending_syncs.append({
                "type": "delete",
                "node_id": node_id,
                "protocol": peer.protocol,
                "uuid": message_uuid,
            })

        logger.debug(f"Queued delete propagation for {message_uuid[:8]}")

    def add_peer(self, node_id: str, name: str, protocol: str):
        """
        Add a new peer for sync.

        Args:
            node_id: Peer's Meshtastic node ID
            name: Human-readable peer name
            protocol: Sync protocol to use
        """
        from ..config import PeerConfig
        peer = PeerConfig(node_id=node_id, name=name, protocol=protocol)
        self._peers[node_id] = peer

        # Also add to database
        now_us = int(time.time() * 1_000_000)
        self.db.execute("""
            INSERT OR REPLACE INTO bbs_peers (node_id, name, protocol, last_sync_us)
            VALUES (?, ?, ?, ?)
        """, (node_id, name, protocol, now_us))

        logger.info(f"Added sync peer: {name} ({node_id}) using {protocol}")

    def remove_peer(self, node_id: str):
        """
        Remove a peer from sync.

        Args:
            node_id: Peer's Meshtastic node ID
        """
        if node_id in self._peers:
            peer = self._peers.pop(node_id)
            if node_id in self._peer_status:
                del self._peer_status[node_id]
            logger.info(f"Removed sync peer: {peer.name} ({node_id})")

    def get_peer_status(self) -> list[dict]:
        """
        Get status of all configured peers.

        Returns list of peer status dicts with:
        - node_id, name, protocol
        - online, last_seen, last_sync
        """
        result = []
        for node_id, peer in self._peers.items():
            status = self._peer_status.get(node_id, {})
            last_sync_us = self._get_last_sync_time(node_id)

            result.append({
                "node_id": node_id,
                "name": peer.name,
                "protocol": peer.protocol,
                "online": status.get("online", False),
                "last_seen": status.get("last_seen", 0),
                "last_sync_us": last_sync_us,
            })

        return result

    def get_sync_stats(self) -> dict:
        """
        Get sync statistics.

        Returns dict with:
        - total_peers, online_peers
        - pending_syncs, pending_acks
        - last_sync_time
        """
        return {
            "total_peers": self.total_peer_count,
            "online_peers": self.online_peer_count,
            "pending_syncs": len(self._pending_syncs),
            "pending_fq51_acks": len(self._fq51._pending_acks),
            "pending_ma_acks": len(self._meshing_around._pending_acks),
            "last_sync_time": self._last_bulletin_sync,
            "sync_enabled": self.config.enabled,
            "sync_interval_minutes": self.config.bulletin_sync_interval_minutes,
        }
