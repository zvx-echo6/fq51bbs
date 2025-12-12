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

        # Remote mail state
        self._pending_remote_mail = {}  # uuid -> {chunks, dest_node, timestamp}
        self._incoming_remote_mail = {}  # uuid -> {from/to info, received_parts}
        self._relay_mail = {}  # uuid -> {origin_node, dest_node}

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

        # Check for remote mail protocol first
        if message.startswith("MAIL"):
            if self.handle_mail_protocol(message, sender):
                return True

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

    def list_peers(self) -> list[dict]:
        """
        List all configured peers for PEERS command.

        Returns list of dicts with name, online status.
        """
        result = []
        now = time.time()
        timeout = 300  # 5 minutes for online status

        for node_id, peer in self._peers.items():
            status = self._peer_status.get(node_id, {})
            last_seen = status.get("last_seen", 0)
            online = (now - last_seen) < timeout if last_seen else False

            result.append({
                "name": peer.name.upper(),
                "node_id": node_id,
                "protocol": peer.protocol,
                "online": online,
            })

        return result

    def get_peer_by_name(self, name: str):
        """
        Find a peer by name (case-insensitive).

        Args:
            name: Peer BBS name to look up

        Returns:
            Peer config object or None if not found
        """
        name_upper = name.upper()
        for node_id, peer in self._peers.items():
            if peer.name.upper() == name_upper:
                return peer
        return None

    def get_peer_node_id(self, name: str) -> Optional[str]:
        """
        Get peer's node ID by name.

        Args:
            name: Peer BBS name

        Returns:
            Node ID or None if not found
        """
        name_upper = name.upper()
        for node_id, peer in self._peers.items():
            if peer.name.upper() == name_upper:
                return node_id
        return None

    def is_peer(self, node_id: str) -> bool:
        """
        Check if a node ID is a configured peer.

        Args:
            node_id: Node ID to check (e.g., !abcd1234)

        Returns:
            True if node is a configured and enabled peer
        """
        peer = self._peers.get(node_id)
        return peer is not None and peer.enabled

    # === Remote Mail Protocol ===

    async def send_remote_mail(
        self,
        sender_username: str,
        sender_bbs: str,
        recipient_username: str,
        recipient_bbs: str,
        body: str,
        mail_uuid: str
    ) -> tuple[bool, str]:
        """
        Send mail to a user on a remote BBS.

        Protocol:
        1. MAILREQ - Request delivery (check route)
        2. Wait for MAILACK/MAILNAK
        3. MAILDAT - Send body chunks (max 3 x 150 chars)

        Args:
            sender_username: Sending user
            sender_bbs: Sender's home BBS callsign
            recipient_username: Destination user
            recipient_bbs: Destination BBS callsign
            body: Message body (max 450 chars)
            mail_uuid: Unique message ID

        Returns:
            (success, error_message)
        """
        # Pre-flight check
        max_body_len = 450  # 3 chunks x 150 chars
        if len(body) > max_body_len:
            return False, f"Message too long for remote delivery (max {max_body_len} chars)"

        # Find route to destination
        dest_node = self.get_peer_node_id(recipient_bbs)

        if dest_node:
            # Direct peer - send straight there
            route = [sender_bbs]
        else:
            # Not a direct peer - try to find relay
            # For now, just try the first peer as relay
            if not self._peers:
                return False, f"No route to {recipient_bbs}"

            # Pick first peer as relay (could be smarter)
            relay_node = next(iter(self._peers.keys()))
            dest_node = relay_node
            route = [sender_bbs]

        # Calculate chunks
        chunks = self._chunk_message(body, 150)
        num_parts = len(chunks)

        # Build MAILREQ
        # Format: MAILREQ|uuid|from_user|from_bbs|to_user|to_bbs|hop|parts|route
        hop = 1
        route_str = ",".join(route)
        mailreq = f"MAILREQ|{mail_uuid}|{sender_username}|{sender_bbs}|{recipient_username}|{recipient_bbs}|{hop}|{num_parts}|{route_str}"

        # Send MAILREQ
        try:
            await self.mesh.send_dm(mailreq, dest_node)
            logger.info(f"Sent MAILREQ for {mail_uuid[:8]} to {dest_node}")

            # Store pending mail for when we receive ACK
            self._pending_remote_mail[mail_uuid] = {
                "chunks": chunks,
                "dest_node": dest_node,
                "timestamp": time.time(),
                "recipient": f"{recipient_username}@{recipient_bbs}",
            }

            return True, ""

        except Exception as e:
            logger.error(f"Failed to send MAILREQ: {e}")
            return False, f"Failed to send: {e}"

    def _chunk_message(self, body: str, chunk_size: int) -> list[str]:
        """Split message into chunks."""
        chunks = []
        for i in range(0, len(body), chunk_size):
            chunks.append(body[i:i + chunk_size])
        return chunks

    def handle_mail_protocol(self, message: str, sender: str) -> bool:
        """
        Handle incoming mail protocol messages.

        Only accepts messages from configured peers for security.
        Returns True if message was handled.
        """
        # Security: Only accept BBS protocol messages from configured peers
        if not self.is_peer(sender):
            logger.warning(f"Rejected BBS protocol message from non-peer: {sender}")
            return False

        if message.startswith("MAILREQ|"):
            return self._handle_mailreq(message, sender)
        elif message.startswith("MAILACK|"):
            return self._handle_mailack(message, sender)
        elif message.startswith("MAILNAK|"):
            return self._handle_mailnak(message, sender)
        elif message.startswith("MAILDAT|"):
            return self._handle_maildat(message, sender)
        elif message.startswith("MAILDLV|"):
            return self._handle_maildlv(message, sender)
        return False

    def _handle_mailreq(self, message: str, sender: str) -> bool:
        """Handle incoming MAILREQ - route check."""
        try:
            parts = message.split("|")
            if len(parts) < 9:
                logger.warning(f"Invalid MAILREQ format: {message}")
                return False

            _, uuid, from_user, from_bbs, to_user, to_bbs, hop, num_parts, route = parts[:9]
            hop = int(hop)
            num_parts = int(num_parts)
            route_list = route.split(",")

            my_callsign = self.bbs.config.bbs.callsign.upper()

            # Check for loop (am I already in route?)
            if my_callsign in [r.upper() for r in route_list]:
                # Loop detected - NAK
                asyncio.create_task(
                    self.mesh.send_dm(f"MAILNAK|{uuid}|LOOP", sender)
                )
                logger.warning(f"Loop detected for {uuid[:8]}")
                return True

            # Check max hops
            if hop > 5:
                asyncio.create_task(
                    self.mesh.send_dm(f"MAILNAK|{uuid}|MAXHOPS", sender)
                )
                return True

            # Is this mail for us (our BBS)?
            if to_bbs.upper() == my_callsign:
                # Check if recipient exists locally
                from ..db.users import UserRepository
                user_repo = UserRepository(self.db)
                recipient = user_repo.get_user_by_username(to_user)

                if not recipient:
                    asyncio.create_task(
                        self.mesh.send_dm(f"MAILNAK|{uuid}|NOUSER", sender)
                    )
                    return True

                # Accept - store pending and ACK
                self._incoming_remote_mail[uuid] = {
                    "from_user": from_user,
                    "from_bbs": from_bbs,
                    "to_user": to_user,
                    "to_bbs": to_bbs,
                    "num_parts": num_parts,
                    "received_parts": {},
                    "sender_node": sender,
                    "timestamp": time.time(),
                }
                asyncio.create_task(
                    self.mesh.send_dm(f"MAILACK|{uuid}|OK", sender)
                )
                logger.info(f"Accepted MAILREQ {uuid[:8]} for {to_user}")
                return True

            # Not for us - need to relay
            dest_node = self.get_peer_node_id(to_bbs)
            if not dest_node:
                # Don't know destination - try to relay to another peer
                # For now, just NAK
                asyncio.create_task(
                    self.mesh.send_dm(f"MAILNAK|{uuid}|NOROUTE", sender)
                )
                return True

            # Relay the request
            route_list.append(my_callsign)
            new_route = ",".join(route_list)
            relay_req = f"MAILREQ|{uuid}|{from_user}|{from_bbs}|{to_user}|{to_bbs}|{hop+1}|{num_parts}|{new_route}"

            # Store relay state
            self._relay_mail[uuid] = {
                "origin_node": sender,
                "dest_node": dest_node,
                "timestamp": time.time(),
            }

            asyncio.create_task(self.mesh.send_dm(relay_req, dest_node))
            logger.info(f"Relaying MAILREQ {uuid[:8]} to {to_bbs}")
            return True

        except Exception as e:
            logger.error(f"Error handling MAILREQ: {e}")
            return False

    def _handle_mailack(self, message: str, sender: str) -> bool:
        """Handle MAILACK - send message chunks."""
        try:
            parts = message.split("|")
            if len(parts) < 3:
                return False

            _, uuid, status = parts[:3]

            # Check if this is a relay ACK
            if uuid in self._relay_mail:
                # Forward ACK back to origin
                relay = self._relay_mail[uuid]
                asyncio.create_task(
                    self.mesh.send_dm(message, relay["origin_node"])
                )
                return True

            # Check if we have pending mail for this UUID
            if uuid not in self._pending_remote_mail:
                logger.warning(f"Unexpected MAILACK for {uuid[:8]}")
                return False

            pending = self._pending_remote_mail[uuid]
            chunks = pending["chunks"]
            dest_node = pending["dest_node"]

            # Send chunks with delay
            asyncio.create_task(self._send_mail_chunks(uuid, chunks, dest_node))

            return True

        except Exception as e:
            logger.error(f"Error handling MAILACK: {e}")
            return False

    async def _send_mail_chunks(self, uuid: str, chunks: list[str], dest_node: str):
        """Send message body chunks with delays."""
        import random
        total = len(chunks)

        for i, chunk in enumerate(chunks, 1):
            # Format: MAILDAT|uuid|part/total|data
            maildat = f"MAILDAT|{uuid}|{i}/{total}|{chunk}"
            await self.mesh.send_dm(maildat, dest_node)

            if i < total:
                # Delay between chunks
                await asyncio.sleep(random.uniform(2.2, 2.6))

        logger.info(f"Sent {total} chunks for {uuid[:8]}")

        # Clean up pending
        if uuid in self._pending_remote_mail:
            del self._pending_remote_mail[uuid]

    def _handle_mailnak(self, message: str, sender: str) -> bool:
        """Handle MAILNAK - delivery rejected."""
        try:
            parts = message.split("|")
            if len(parts) < 3:
                return False

            _, uuid, reason = parts[:3]

            # Check if relay
            if uuid in self._relay_mail:
                relay = self._relay_mail.pop(uuid)
                asyncio.create_task(
                    self.mesh.send_dm(message, relay["origin_node"])
                )
                return True

            # Clean up pending
            if uuid in self._pending_remote_mail:
                pending = self._pending_remote_mail.pop(uuid)
                logger.warning(f"Mail {uuid[:8]} rejected: {reason}")
                # TODO: Notify sender of failure

            return True

        except Exception as e:
            logger.error(f"Error handling MAILNAK: {e}")
            return False

    def _handle_maildat(self, message: str, sender: str) -> bool:
        """Handle MAILDAT - message chunk received."""
        try:
            parts = message.split("|", 3)
            if len(parts) < 4:
                return False

            _, uuid, part_info, data = parts
            part_num, total_parts = map(int, part_info.split("/"))

            # Check if relay
            if uuid in self._relay_mail:
                relay = self._relay_mail[uuid]
                asyncio.create_task(
                    self.mesh.send_dm(message, relay["dest_node"])
                )
                return True

            # Store chunk
            if uuid not in self._incoming_remote_mail:
                logger.warning(f"Unexpected MAILDAT for {uuid[:8]}")
                return False

            incoming = self._incoming_remote_mail[uuid]
            incoming["received_parts"][part_num] = data

            # Check if all parts received
            if len(incoming["received_parts"]) >= incoming["num_parts"]:
                # Reassemble and deliver
                asyncio.create_task(self._deliver_remote_mail(uuid, incoming))

            return True

        except Exception as e:
            logger.error(f"Error handling MAILDAT: {e}")
            return False

    async def _deliver_remote_mail(self, uuid: str, incoming: dict):
        """Reassemble and deliver remote mail locally."""
        try:
            # Reassemble body
            body_parts = []
            for i in range(1, incoming["num_parts"] + 1):
                if i in incoming["received_parts"]:
                    body_parts.append(incoming["received_parts"][i])
            body = "".join(body_parts)

            # Look up local recipient
            from ..db.users import UserRepository
            user_repo = UserRepository(self.db)
            recipient = user_repo.get_user_by_username(incoming["to_user"])

            if not recipient:
                logger.error(f"Recipient not found for {uuid[:8]}")
                return

            # Create local mail message
            from ..db.messages import MessageRepository
            msg_repo = MessageRepository(self.db)

            msg_repo.create_incoming_remote_mail(
                uuid=uuid,
                from_user=incoming["from_user"],
                from_bbs=incoming["from_bbs"],
                to_user_id=recipient.id,
                body=body
            )

            # Send delivery confirmation back
            dlv = f"MAILDLV|{uuid}|OK|{incoming['to_user']}@{self.bbs.config.bbs.callsign}"
            await self.mesh.send_dm(dlv, incoming["sender_node"])

            logger.info(f"Delivered remote mail {uuid[:8]} to {incoming['to_user']}")

            # Clean up
            if uuid in self._incoming_remote_mail:
                del self._incoming_remote_mail[uuid]

        except Exception as e:
            logger.error(f"Error delivering remote mail: {e}")

    def _handle_maildlv(self, message: str, sender: str) -> bool:
        """Handle MAILDLV - delivery confirmation."""
        try:
            parts = message.split("|")
            if len(parts) < 4:
                return False

            _, uuid, status, dest = parts[:4]

            # Check if relay
            if uuid in self._relay_mail:
                relay = self._relay_mail.pop(uuid)
                asyncio.create_task(
                    self.mesh.send_dm(message, relay["origin_node"])
                )
                return True

            logger.info(f"Mail {uuid[:8]} delivered to {dest}")
            # TODO: Update message status in database

            return True

        except Exception as e:
            logger.error(f"Error handling MAILDLV: {e}")
            return False
