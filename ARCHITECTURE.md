# FQ51BBS Architecture Design

**Version:** 1.3-FINAL-DRAFT
**Date:** 2025-12-10
**Status:** ALL QUESTIONS RESOLVED - AWAITING APPROVAL

---

## Executive Summary

FQ51BBS is a lightweight, encryption-first BBS for Meshtastic mesh networks. It draws on proven concepts from existing mesh BBS systems while adding unique capabilities around encryption, multi-node user identity, and inter-BBS message forwarding.

### Design Philosophy

1. **Lightweight First** - Must run comfortably on Raspberry Pi Zero 2 W (512MB RAM, quad-core 1GHz ARM)
2. **Encryption Native** - All messages encrypted at rest; user passwords derive encryption keys
3. **Mesh Friendly** - Never flood the mesh; respect bandwidth constraints
4. **Interoperable** - Compatible with meshing-around, TC2-BBS-mesh, and frozenbbs
5. **CLI Only** - No GUI, no web interface, pure terminal interaction

### Target Hardware Constraints

| Resource | RPi Zero 2 W | FQ51BBS Target |
|----------|--------------|----------------|
| RAM | 512MB | <100MB runtime |
| CPU | 4x 1GHz ARM Cortex-A53 | Single-threaded + async I/O |
| Storage | SD Card | <50MB database typical |
| Power | 1.2W typical | No CPU-intensive operations |

---

## Research Summary

### Existing BBS Systems Analyzed

| System | Language | Storage | Strengths | Weaknesses |
|--------|----------|---------|-----------|------------|
| **meshing-around** | Python | Pickle | Feature-rich, 100+ commands, bbslink sync | Heavy dependencies, global state |
| **TC2-BBS-mesh** | Python | SQLite | Simple pipe-delimited sync, UUIDs | No encryption focus |
| **frozenbbs** | Rust | SQLite | Minimal, stateless, fast | No inter-BBS protocol |

### Key Learnings

1. **SQLite preferred** - More robust than pickle, thread-safe, queryable
2. **150-byte message limit** - LoRa constraint requires chunking with multi-message support
3. **Pub/sub pattern** - Non-blocking message handling essential
4. **UUIDs for deduplication** - Critical for distributed sync
5. **Stateless commands** - Simplifies recovery and reduces memory
6. **Rate limiting** - Essential to avoid mesh flooding
7. **Togglable features** - Mail, boards, and repeater modes independently configurable

---

## Data Models

### Entity Relationship Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Users     │────<│  UserNodes  │>────│   Nodes     │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                       │
       │                                       │
       ▼                                       ▼
┌─────────────┐                         ┌─────────────┐
│  Messages   │                         │  BBSPeers   │
└─────────────┘                         └─────────────┘
       │
       ▼
┌─────────────┐
│   Boards    │
└─────────────┘
```

### Users Table

Registered BBS users with encrypted credentials.

```sql
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,           -- BBS username (case-insensitive)
    password_hash   BLOB NOT NULL,                  -- Argon2id hash
    salt            BLOB NOT NULL,                  -- Unique per-user salt
    encryption_key  BLOB NOT NULL,                  -- Derived key (encrypted with master)
    created_at_us   INTEGER NOT NULL,               -- Microseconds since epoch
    last_seen_at_us INTEGER,                        -- Last activity timestamp
    is_admin        INTEGER DEFAULT 0,              -- Admin flag
    is_banned       INTEGER DEFAULT 0               -- Ban flag
);
CREATE INDEX idx_users_username ON users(username COLLATE NOCASE);
```

### Nodes Table

Known Meshtastic nodes (may or may not be registered users).

```sql
CREATE TABLE nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT UNIQUE NOT NULL,           -- Meshtastic node ID (!abcdef12)
    short_name      TEXT,                           -- Node short name
    long_name       TEXT,                           -- Node long name
    first_seen_us   INTEGER NOT NULL,               -- First observation
    last_seen_us    INTEGER NOT NULL,               -- Last observation
    last_snr        REAL,                           -- Last signal-to-noise ratio
    last_rssi       INTEGER                         -- Last received signal strength
);
CREATE INDEX idx_nodes_node_id ON nodes(node_id);
```

### UserNodes Table (Multi-Node Identity)

Associates users with multiple Meshtastic nodes.

```sql
CREATE TABLE user_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id         INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    registered_at_us INTEGER NOT NULL,              -- When node was associated
    is_primary      INTEGER DEFAULT 0,              -- Primary node flag
    UNIQUE(user_id, node_id)
);
CREATE INDEX idx_user_nodes_user ON user_nodes(user_id);
CREATE INDEX idx_user_nodes_node ON user_nodes(node_id);
```

### Messages Table

All messages (mail, bulletins) encrypted at rest.

```sql
CREATE TABLE messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT UNIQUE NOT NULL,           -- UUID for deduplication
    msg_type        TEXT NOT NULL,                  -- 'mail' | 'bulletin' | 'system'
    board_id        INTEGER REFERENCES boards(id),  -- NULL for mail
    sender_user_id  INTEGER REFERENCES users(id),   -- NULL if from unregistered node
    sender_node_id  INTEGER NOT NULL REFERENCES nodes(id),
    recipient_user_id INTEGER REFERENCES users(id), -- NULL for bulletins
    recipient_node_id INTEGER REFERENCES nodes(id), -- Direct node target
    subject_enc     BLOB,                           -- Encrypted subject
    body_enc        BLOB NOT NULL,                  -- Encrypted body
    created_at_us   INTEGER NOT NULL,               -- Creation timestamp
    delivered_at_us INTEGER,                        -- NULL until delivered
    read_at_us      INTEGER,                        -- NULL until read
    expires_at_us   INTEGER,                        -- Auto-delete timestamp
    origin_bbs      TEXT,                           -- Originating BBS ID (for sync)
    -- Delivery tracking (for mail)
    delivery_attempts INTEGER DEFAULT 0,            -- Number of delivery attempts
    last_attempt_us INTEGER,                        -- Last delivery attempt timestamp
    forwarded_to    TEXT,                           -- Peer BBS that received handoff
    hop_count       INTEGER DEFAULT 0,              -- Prevent infinite forwarding (max 3)
    CONSTRAINT chk_msg_type CHECK (msg_type IN ('mail', 'bulletin', 'system'))
);
CREATE INDEX idx_messages_uuid ON messages(uuid);
CREATE INDEX idx_messages_recipient_user ON messages(recipient_user_id);
CREATE INDEX idx_messages_recipient_node ON messages(recipient_node_id);
CREATE INDEX idx_messages_board ON messages(board_id);
CREATE INDEX idx_messages_created ON messages(created_at_us);
```

### Boards Table

Bulletin boards for public messages.

```sql
CREATE TABLE boards (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,           -- Board name
    description     TEXT,                           -- Board description
    created_at_us   INTEGER NOT NULL,
    is_restricted   INTEGER DEFAULT 0,              -- Admin-only posting
    board_type      TEXT DEFAULT 'public',          -- 'public' | 'restricted'
    board_key_enc   BLOB                            -- Board encryption key (encrypted with master)
);

-- Per-user board access for restricted boards
CREATE TABLE board_access (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    board_id        INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    board_key_enc   BLOB NOT NULL,                  -- Board key encrypted with user's key
    granted_at_us   INTEGER NOT NULL,
    granted_by      INTEGER REFERENCES users(id),   -- Admin who granted access
    UNIQUE(board_id, user_id)
);
```

### BoardStates Table

Per-user reading position in boards.

```sql
CREATE TABLE board_states (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    board_id        INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    last_read_us    INTEGER NOT NULL,               -- Timestamp of last read post
    UNIQUE(user_id, board_id)
);
```

### BBSPeers Table

Known peer BBS nodes for inter-BBS sync.

```sql
CREATE TABLE bbs_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT UNIQUE NOT NULL,           -- Peer BBS node ID
    bbs_name        TEXT,                           -- Peer BBS name
    last_sync_us    INTEGER,                        -- Last successful sync
    sync_enabled    INTEGER DEFAULT 1,              -- Enable/disable sync
    trust_level     INTEGER DEFAULT 0               -- 0=untrusted, 1=trusted, 2=full
);
```

### SyncLog Table

Track message sync status for inter-BBS protocol.

```sql
CREATE TABLE sync_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_uuid    TEXT NOT NULL,
    peer_id         INTEGER NOT NULL REFERENCES bbs_peers(id),
    direction       TEXT NOT NULL,                  -- 'sent' | 'received'
    status          TEXT NOT NULL,                  -- 'pending' | 'acked' | 'failed'
    attempts        INTEGER DEFAULT 0,
    last_attempt_us INTEGER,
    UNIQUE(message_uuid, peer_id, direction)
);
```

---

## Encryption Architecture

### Overview

FQ51BBS implements encryption at three levels:

1. **Transport** - Meshtastic channel encryption (PSK)
2. **User Authentication** - Argon2id password hashing
3. **Message Storage** - ChaCha20-Poly1305 encryption at rest

### Key Derivation

```
User Password
     │
     ▼
┌─────────────────────────────────────┐
│  Argon2id(password, salt)           │
│  - Time cost: 3 iterations          │
│  - Memory: 64MB (configurable)      │
│  - Parallelism: 1 (RPi friendly)    │
│  - Output: 32 bytes                 │
└─────────────────────────────────────┘
     │
     ├──────────────────┐
     ▼                  ▼
Password Hash      Encryption Key
(stored in DB)     (derived, not stored directly)
```

### Memory-Constrained Argon2id Parameters

For RPi Zero 2 W (512MB RAM), we use conservative parameters:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Time cost | 3 | Balance security/speed |
| Memory | 32MB | Leave headroom for system |
| Parallelism | 1 | Single-threaded derivation |
| Hash length | 32 bytes | ChaCha20 key size |
| Salt length | 16 bytes | Unique per user |

### Message Encryption

Messages are encrypted using ChaCha20-Poly1305 (AEAD):

```
Plaintext Message
     │
     ▼
┌─────────────────────────────────────┐
│  ChaCha20-Poly1305                  │
│  - Key: User's derived key          │
│  - Nonce: Random 12 bytes           │
│  - AAD: message_uuid + timestamp    │
└─────────────────────────────────────┘
     │
     ▼
Ciphertext + Auth Tag (stored in DB)
```

### Key Storage Strategy

```
┌─────────────────────────────────────────────────────────┐
│                    Master Key                           │
│  (Derived from BBS admin password at startup)           │
│  (Never written to disk - held in memory only)          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              User Encryption Keys                       │
│  (Encrypted with master key, stored in users table)     │
│  (Decrypted on-demand when user authenticates)          │
└─────────────────────────────────────────────────────────┘
```

### Encryption for Different Message Types

| Message Type | Encryption Key | Access |
|--------------|----------------|--------|
| Private Mail | Recipient's key | Only recipient can decrypt |
| Bulletin | Board key (shared) | All registered users |
| System Message | Master key | Admin only |

### Security Considerations

1. **No plaintext storage** - All message content encrypted
2. **Forward secrecy** - Not implemented (would require DH key exchange)
3. **Key rotation** - Password change regenerates encryption key
4. **Secure deletion** - Overwrite before delete (configurable)

### Key Escrow (Admin Recovery)

**Decision: Admin Recovery Key (Balanced Approach)**

When users forget their password, encrypted messages become permanently unreadable unless a recovery mechanism exists. FQ51BBS implements admin-assisted recovery:

```
User Password → Argon2id → User Key ──────────┐
                              ↓               │
                    Messages encrypted        │
                              ↓               ▼
Admin Master Key → Encrypts copy of User Key
                              ↓
              Stored in users.recovery_key_enc
```

**How Recovery Works:**
1. User contacts admin out-of-band (proves identity)
2. Admin uses `RECOVER <username>` command
3. System generates temporary password, re-encrypts user key
4. Admin provides temporary password to user
5. User logs in, immediately changes password with `PASSWD`

**Database Addition:**
```sql
ALTER TABLE users ADD COLUMN recovery_key_enc BLOB;  -- User key encrypted with master
```

**Privacy Implications:**
- Admin CAN decrypt any user's messages if needed
- This is documented and users accept it on registration
- Users wanting true privacy should run their own BBS node
- Trade-off: Usability over absolute privacy

### Board Encryption (Hybrid Approach)

**Decision: Shared Key for Public Boards, Per-User for Restricted**

```
Board Types:
┌──────────────────────────────────────────────────────────────┐
│ PUBLIC BOARDS                                                │
│   - Shared board_key stored encrypted with Master Key        │
│   - All authenticated users can read                         │
│   - BBS decrypts on behalf of user                          │
│   - Simple, low overhead                                     │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ RESTRICTED BOARDS                                            │
│   - Board key encrypted separately for each authorized user  │
│   - Stored in board_access table                            │
│   - User decrypts with their own key                        │
│   - Granular access control                                 │
└──────────────────────────────────────────────────────────────┘
```

**Public Board Flow:**
```
User requests post → BBS retrieves board_key (decrypt with master)
                  → BBS decrypts post with board_key
                  → BBS sends plaintext to user
```

**Restricted Board Flow:**
```
User requests post → BBS retrieves user's board_key_enc from board_access
                  → User's session key decrypts board_key
                  → Post decrypted with board_key
                  → Plaintext sent to user
```

---

## Message Chunking (150 bytes)

### Design Decision

Messages are chunked to 150 bytes maximum with sequence headers for reassembly.
Longer messages are sent as multiple transmissions with 2-second delays.

### Chunk Format

```
[seq/total] content

Examples:
[1/3] This is the first part of a longer message that needs
[2/3] to be split across multiple transmissions because of
[3/3] LoRa packet size constraints.
```

### Implementation

```python
MAX_CHUNK_SIZE = 150  # bytes
HEADER_RESERVE = 8    # "[xx/xx] " = 8 bytes max
CONTENT_SIZE = MAX_CHUNK_SIZE - HEADER_RESERVE  # 142 bytes

def chunk_message(message: str) -> list[str]:
    """Split message into 150-byte chunks with sequence headers."""
    encoded = message.encode('utf-8')

    chunks = []
    for i in range(0, len(encoded), CONTENT_SIZE):
        chunks.append(encoded[i:i + CONTENT_SIZE])

    total = len(chunks)
    if total == 1:
        return [message]  # No chunking needed

    result = []
    for i, chunk in enumerate(chunks, 1):
        header = f"[{i}/{total}] "
        result.append(header + chunk.decode('utf-8', errors='replace'))

    return result

async def send_chunked(message: str, destination: str, interface):
    """Send message with chunking and inter-chunk delays."""
    chunks = chunk_message(message)

    for i, chunk in enumerate(chunks):
        await interface.sendText(chunk, destination)
        if i < len(chunks) - 1:
            await asyncio.sleep(2)  # 2 second delay between chunks
```

### Reassembly with Hybrid Timeout

**Timeout Strategy:**
- **Per-chunk timeout:** 2 minutes - expect next chunk within this window
- **Total timeout:** 10 minutes - absolute max for any message
- Whichever hits first triggers cleanup

```python
# Track partial messages per sender
pending_chunks: dict[str, dict] = {}

CHUNK_TIMEOUT = 120   # 2 minutes between chunks
TOTAL_TIMEOUT = 600   # 10 minutes absolute max

def reassemble_message(chunk: str, sender: str) -> str | None:
    """Reassemble chunked messages. Returns full message when complete."""
    import re

    match = re.match(r'\[(\d+)/(\d+)\] (.+)', chunk, re.DOTALL)
    if not match:
        return chunk  # Not chunked, return as-is

    seq, total, content = int(match[1]), int(match[2]), match[3]
    key = f"{sender}:{total}"
    now = time.time()

    if key not in pending_chunks:
        pending_chunks[key] = {
            'chunks': [''] * total,
            'received': set(),
            'created': now,           # Total timeout anchor
            'last_chunk': now         # Per-chunk timeout anchor
        }

    # Update last chunk time (sliding window)
    pending_chunks[key]['last_chunk'] = now
    pending_chunks[key]['chunks'][seq - 1] = content
    pending_chunks[key]['received'].add(seq)

    if len(pending_chunks[key]['received']) == total:
        full_message = ''.join(pending_chunks[key]['chunks'])
        del pending_chunks[key]
        return full_message

    return None  # Still waiting for more chunks

def cleanup_expired_chunks():
    """Remove stale pending chunks. Call periodically."""
    now = time.time()
    expired = []

    for key, entry in pending_chunks.items():
        # Expired if no chunk for 2 min OR total time > 10 min
        chunk_stale = (now - entry['last_chunk']) > CHUNK_TIMEOUT
        total_exceeded = (now - entry['created']) > TOTAL_TIMEOUT

        if chunk_stale or total_exceeded:
            expired.append(key)

    for key in expired:
        del pending_chunks[key]
```

**Why Hybrid Timeout?**
| Scenario | Per-Chunk (2min) | Total (10min) | Result |
|----------|------------------|---------------|--------|
| Sender stops mid-message | Triggers | - | Fast cleanup |
| Very slow but steady delivery | Keeps resetting | Eventually triggers | Tolerant |
| Normal delivery | Neither | Neither | Completes normally |
| Lost single chunk | Triggers after 2min | - | Reasonable wait |

---

## Mail Delivery Protocol

### 3 Attempts Then Forward

Private mail delivery uses exponential backoff with forwarding on failure:

```
Message sent to User B (node !xyz)
         │
         ▼
    ┌─────────────────────────────────────┐
    │  Attempt 1: Send DM to !xyz         │
    │  Wait for ACK (30 seconds)          │
    └─────────────────────────────────────┘
         │
         ├─── ACK received → DELIVERED ✓
         │
         ▼ (No ACK)
    ┌─────────────────────────────────────┐
    │  Attempt 2: Retry after 60 seconds  │
    │  Wait for ACK (30 seconds)          │
    └─────────────────────────────────────┘
         │
         ├─── ACK received → DELIVERED ✓
         │
         ▼ (No ACK)
    ┌─────────────────────────────────────┐
    │  Attempt 3: Retry after 120 seconds │
    │  Wait for ACK (30 seconds)          │
    └─────────────────────────────────────┘
         │
         ├─── ACK received → DELIVERED ✓
         │
         ▼ (No ACK after 3 attempts)
    ┌─────────────────────────────────────┐
    │  FORWARD to next BBS peer           │
    │  Mark as "forwarded" in database    │
    │  Increment hop_count                │
    └─────────────────────────────────────┘
         │
         ▼
    Peer BBS receives, tries same process
    (max 3 BBS hops to prevent loops)
```

### Timing Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| ACK timeout | 30 seconds | Wait for mesh acknowledgment |
| Retry 1 delay | 60 seconds | First retry backoff |
| Retry 2 delay | 120 seconds | Second retry backoff |
| Max attempts | 3 | Before forwarding |
| Max BBS hops | 3 | Prevent infinite forwarding |

### Implementation

```python
class MailDeliveryManager:
    async def deliver_mail(self, message_id: int):
        msg = self.db.get_message(message_id)

        for attempt in range(1, 4):
            msg.delivery_attempts = attempt
            msg.last_attempt_us = time.time_ns() // 1000
            self.db.update_message(msg)

            ack = await self.send_with_ack(msg)
            if ack:
                msg.delivered_at_us = time.time_ns() // 1000
                self.db.update_message(msg)
                return True

            if attempt < 3:
                delay = 60 * (2 ** (attempt - 1))  # 60, 120 seconds
                await asyncio.sleep(delay)

        # Failed after 3 attempts - forward to peer
        await self.forward_to_peer(msg)
        return False

    async def forward_to_peer(self, msg):
        if msg.hop_count >= 3:
            # Max hops reached, mark as undeliverable
            return

        peer = self.get_next_peer()
        if peer:
            msg.forwarded_to = peer.node_id
            msg.hop_count += 1
            self.db.update_message(msg)
            await self.sync_message_to_peer(msg, peer)
```

---

## Operating Modes & Togglable Features

### Feature Flags

Each BBS instance can independently enable/disable core features:

```toml
[features]
# Core features - independently togglable
mail_enabled = true              # Private mail system
boards_enabled = true            # Public bulletin boards
sync_enabled = true              # Inter-BBS synchronization
registration_enabled = true      # Allow new user registration
```

### Operating Modes

```toml
[operating_mode]
# BBS operating mode
# Options: "full" | "mail_only" | "boards_only" | "repeater"
mode = "full"
```

| Mode | Mail | Boards | Local Users | Behavior |
|------|------|--------|-------------|----------|
| `full` | ✓ | ✓ | ✓ | Full BBS functionality |
| `mail_only` | ✓ | ✗ | ✓ | Private mail only, no public boards |
| `boards_only` | ✗ | ✓ | ✓ | Public boards only, no private mail |
| `repeater` | forward | forward | ✗ | Forward-only, no local processing |

### Repeater Mode Details

Repeater mode creates a "dumb pipe" that forwards messages without local storage:

```
┌─────────────────────────────────────────────────────────────┐
│                     REPEATER MODE                           │
│                                                             │
│  Receives message → Check if for local user (none exist)    │
│                   → Forward to configured peers             │
│                   → No local storage                        │
│                   → No command processing                   │
│                   → Silent relay                            │
└─────────────────────────────────────────────────────────────┘
```

**Use Cases:**
- Extend BBS network reach without running full BBS
- Bridge between mesh segments
- Low-resource nodes that just relay

```toml
[repeater]
# Repeater-specific settings (only used in repeater mode)
forward_mail = true              # Forward private mail to peers
forward_bulletins = true         # Forward bulletin posts to peers
forward_to_peers = ["!abc123", "!def456"]  # Specific peers
# If empty, forwards to all known peers

# Announcement settings (user configurable)
announce_enabled = true          # Toggle announcements on/off
announce_message = "FQ51BBS Relay active. SM <user> <msg> to send mail."
announce_interval_hours = 12     # How often (0 = once at startup only)
announce_channel = 0             # Which channel to announce on
```

### Repeater Announcements

Repeaters can optionally announce their presence to the mesh. All settings are user-configurable:

**Configuration Options:**
| Setting | Default | Description |
|---------|---------|-------------|
| `announce_enabled` | true | Master toggle for announcements |
| `announce_message` | (see above) | Custom message text |
| `announce_interval_hours` | 12 | Frequency (0 = startup only) |
| `announce_channel` | 0 | Channel index for broadcasts |

**Example Announcement Messages:**
```toml
# Minimal
announce_message = "FQ51BBS Relay online"

# Informative
announce_message = "[FQ51] Mail relay active. SM <user> <msg> to send."

# With node ID
announce_message = "BBS repeater !abc123 - forwarding mail & bulletins"

# Disabled
announce_enabled = false
```

**Implementation:**
```python
class RepeaterAnnouncer:
    def __init__(self, config):
        self.enabled = config.repeater.announce_enabled
        self.message = config.repeater.announce_message
        self.interval = config.repeater.announce_interval_hours * 3600
        self.channel = config.repeater.announce_channel
        self.last_announce = 0

    async def start(self):
        """Initial announcement at startup if enabled."""
        if self.enabled:
            await self.announce()

    async def tick(self):
        """Call periodically to check if announcement needed."""
        if not self.enabled or self.interval == 0:
            return  # Disabled or startup-only mode

        if time.time() - self.last_announce >= self.interval:
            await self.announce()

    async def announce(self):
        await interface.sendText(
            self.message,
            destinationId=BROADCAST_ADDR,
            channelIndex=self.channel
        )
        self.last_announce = time.time()
        log.info(f"Repeater announcement sent on channel {self.channel}")
```

### Sync Timing by Message Type

```toml
[sync]
# Different sync behavior for different message types
bulletin_sync_interval_minutes = 60    # Hourly for boards (scheduled)
mail_delivery_mode = "instant"         # "instant" | "batched"
mail_batch_interval_minutes = 5        # Only if batched mode

# Opt-in participation
participate_in_mail_relay = true       # Help deliver others' mail
participate_in_bulletin_sync = true    # Sync bulletin boards with peers
```

| Message Type | Default Timing | Rationale |
|--------------|----------------|-----------|
| Private Mail | Instant | Time-sensitive, personal |
| Bulletins | Hourly | Not urgent, batch-friendly |
| System Messages | Instant | Admin alerts, important |

### Mode Selection Logic

```python
class FQ51BBS:
    def handle_message(self, msg: str, sender: str):
        # Repeater mode: forward only, no processing
        if self.mode == OperatingMode.REPEATER:
            self.forward_message(msg, sender)
            return None  # Silent

        # Check feature availability
        cmd = msg.split()[0].upper() if msg else ""

        if cmd in MAIL_COMMANDS and not self.features.mail_enabled:
            return "Mail system disabled on this BBS."

        if cmd in BOARD_COMMANDS and not self.features.boards_enabled:
            return "Bulletin boards disabled on this BBS."

        if self.mode == OperatingMode.MAIL_ONLY and cmd in BOARD_COMMANDS:
            return "This BBS only supports private mail."

        if self.mode == OperatingMode.BOARDS_ONLY and cmd in MAIL_COMMANDS:
            return "This BBS only supports bulletin boards."

        # Process normally
        return self.dispatch(msg, sender)
```

---

## Admin BBS Channel

### Purpose

Ban list synchronization requires a dedicated admin channel to prevent unintended propagation to unrelated BBS networks. Only explicitly trusted peers can exchange admin commands.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BBS NETWORK TOPOLOGY                     │
│                                                             │
│   Public Channel (0)          Admin Channel (7)             │
│   ┌─────────────────┐         ┌─────────────────┐           │
│   │ User messages   │         │ BAN_SYNC        │           │
│   │ Commands        │         │ UNBAN_SYNC      │           │
│   │ Bulletins       │         │ PEER_STATUS     │           │
│   │ Announcements   │         │ ADMIN_PING      │           │
│   └─────────────────┘         └─────────────────┘           │
│          ▲                           ▲                      │
│          │                           │                      │
│      All nodes                  Trusted BBS admins only     │
│                              (requires shared admin PSK)    │
└─────────────────────────────────────────────────────────────┘
```

### Configuration

```toml
[admin_channel]
enabled = true                       # Enable admin channel features
channel_index = 7                    # Dedicated channel (must match Meshtastic config)
# Note: PSK for this channel configured in Meshtastic, not here

# What to sync over admin channel
sync_bans = true                     # Sync ban/unban across peers
sync_peer_status = true              # Share peer health/status

# Trust settings
trusted_peers = ["!abc123", "!def456"]  # Only accept admin sync from these
require_mutual_trust = true          # Both sides must list each other
```

### Trust Levels

```
┌─────────────────────────────────────────────────────────────┐
│                     TRUST HIERARCHY                         │
│                                                             │
│  Level 0: Unknown                                           │
│    - No sync at all                                         │
│                                                             │
│  Level 1: Known Peer (in sync.peers)                        │
│    - Mail/bulletin sync allowed                             │
│    - NO admin sync                                          │
│                                                             │
│  Level 2: Trusted Admin (in admin_channel.trusted_peers)    │
│    - All Level 1 features                                   │
│    - Ban/unban sync (if sync_bans = true)                   │
│    - Peer status exchange                                   │
│                                                             │
│  Level 3: Mutual Trust (both list each other)               │
│    - All Level 2 features                                   │
│    - Full admin command acceptance                          │
└─────────────────────────────────────────────────────────────┘
```

### Admin Protocol Messages

```
FQ51|1|ADMIN|BAN|<username>|<reason>|<banned_by>|<timestamp>
FQ51|1|ADMIN|UNBAN|<username>|<unbanned_by>|<timestamp>
FQ51|1|ADMIN|PEER_STATUS|<node_id>|<status>|<user_count>|<msg_count>
FQ51|1|ADMIN|PING|<timestamp>
FQ51|1|ADMIN|PONG|<timestamp>|<latency_ms>
```

### Implementation

```python
class AdminChannelHandler:
    def __init__(self, config, db):
        self.enabled = config.admin_channel.enabled
        self.channel = config.admin_channel.channel_index
        self.trusted_peers = set(config.admin_channel.trusted_peers)
        self.require_mutual = config.admin_channel.require_mutual_trust
        self.sync_bans = config.admin_channel.sync_bans
        self.db = db

    def is_trusted(self, sender: str) -> bool:
        """Check if sender is in trusted peers list."""
        return sender in self.trusted_peers

    def handle_admin_message(self, msg: str, sender: str, channel: int):
        # Only process on admin channel
        if channel != self.channel:
            return

        # Only process from trusted peers
        if not self.is_trusted(sender):
            log.warning(f"Admin msg from untrusted {sender}, ignoring")
            return

        parts = msg.split("|")
        if len(parts) < 4 or parts[0] != "FQ51" or parts[2] != "ADMIN":
            return

        action = parts[3]

        if action == "BAN" and self.sync_bans:
            self.process_ban(parts, sender)
        elif action == "UNBAN" and self.sync_bans:
            self.process_unban(parts, sender)
        elif action == "PEER_STATUS":
            self.process_peer_status(parts, sender)

    def process_ban(self, parts: list, sender: str):
        if len(parts) < 8:
            return

        username = parts[4]
        reason = parts[5]
        banned_by = parts[6]
        timestamp = int(parts[7])

        # Don't re-apply if already banned
        user = self.db.get_user(username)
        if user and user.is_banned:
            return

        self.db.ban_user(
            username=username,
            reason=reason,
            banned_by=banned_by,
            ban_origin=sender  # Track where ban came from
        )
        log.info(f"Ban synced: {username} (from {sender})")

    def broadcast_ban(self, username: str, reason: str):
        """Broadcast ban to trusted peers."""
        if not self.enabled or not self.sync_bans:
            return

        msg = f"FQ51|1|ADMIN|BAN|{username}|{reason}|{self.node_id}|{int(time.time())}"

        for peer in self.trusted_peers:
            interface.sendText(msg, peer, channelIndex=self.channel)
```

### Database Updates for Ban Tracking

```sql
-- Extended user ban fields
ALTER TABLE users ADD COLUMN banned_by TEXT;        -- Who issued ban
ALTER TABLE users ADD COLUMN ban_reason TEXT;       -- Why banned
ALTER TABLE users ADD COLUMN ban_origin TEXT;       -- 'local' or peer node_id
ALTER TABLE users ADD COLUMN banned_at_us INTEGER;  -- When banned
```

### Security Considerations

1. **Channel Encryption** - Admin channel should use a strong, unique PSK in Meshtastic config
2. **Trusted Peers Only** - Never accept admin commands from unknown nodes
3. **Audit Trail** - All synced bans tracked with origin for accountability
4. **No Cascade** - Received bans are not re-broadcast (prevents amplification)
5. **Local Override** - Admin can always unban locally regardless of sync

---

## Inter-BBS Sync System

### Design Philosophy

FQ51BBS acts as a **polyglot BBS** - it speaks each external system's native protocol when syncing with them, while using its own optimized DM-based protocol for FQ51-to-FQ51 communication.

**We do NOT try to change how other BBS systems work.** We participate as a peer in their existing networks.

### Sync Compatibility Matrix

| BBS System | Has Sync Protocol? | FQ51BBS Approach |
|------------|-------------------|------------------|
| **TC2-BBS-mesh** | Yes | Use TC2's exact pipe-delimited protocol |
| **meshing-around** | Yes | Use their exact bbslink/bbsack protocol |
| **frozenbbs** | **No** | Cannot sync (no protocol exists) |
| **FQ51BBS** | Yes | Native DM-based protocol |

### Peer Configuration

```toml
[sync]
enabled = true

# Peers with their protocol type
[[sync.peers]]
node_id = "!abc123"
name = "TC2-BBS-West"
protocol = "tc2"           # Use TC2-BBS protocol

[[sync.peers]]
node_id = "!def456"
name = "MeshAround-Central"
protocol = "meshing-around" # Use meshing-around protocol

[[sync.peers]]
node_id = "!ghi789"
name = "FQ51BBS-East"
protocol = "fq51"          # Use native FQ51 DM protocol
```

---

### Protocol 1: TC2-BBS-mesh Compatibility

**Reference:** https://github.com/TheCommsChannel/TC2-BBS-mesh

TC2-BBS uses pipe-delimited messages for sync. We implement their exact format.

#### TC2 Message Formats

```
# Bulletin sync
BULLETIN|<board>|<sender_short_name>|<subject>|<content>|<unique_id>

# Mail sync
MAIL|<sender>|<recipient>|<subject>|<content>|<unique_id>

# Delete bulletin
DELETE_BULLETIN|<unique_id>

# Delete mail
DELETE_MAIL|<unique_id>

# Channel directory
CHANNEL|<name>|<url>
```

#### TC2 Sync Behavior

TC2-BBS syncs by:
1. Detecting peer BBS nodes listed in `bbs_nodes` config
2. Sending messages directly to those node IDs
3. Using UUIDs for deduplication

#### FQ51BBS TC2 Implementation

```python
class TC2Compatibility:
    """Sync with TC2-BBS-mesh peers using their native protocol."""

    def send_bulletin_to_tc2(self, msg: dict, peer_id: str):
        """Send bulletin in TC2 format."""
        tc2_msg = f"BULLETIN|{msg['board']}|{msg['sender_short']}|{msg['subject']}|{msg['body']}|{msg['uuid']}"
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def send_mail_to_tc2(self, msg: dict, peer_id: str):
        """Send mail in TC2 format."""
        tc2_msg = f"MAIL|{msg['sender']}|{msg['recipient']}|{msg['subject']}|{msg['body']}|{msg['uuid']}"
        self.interface.sendText(tc2_msg, destinationId=peer_id)

    def parse_tc2_message(self, raw: str) -> dict | None:
        """Parse incoming TC2 format message."""
        parts = raw.split("|")
        if len(parts) < 2:
            return None

        msg_type = parts[0]

        if msg_type == "BULLETIN" and len(parts) >= 6:
            return {
                'type': 'bulletin',
                'board': parts[1],
                'sender_short': parts[2],
                'subject': parts[3],
                'body': parts[4],
                'uuid': parts[5]
            }
        elif msg_type == "MAIL" and len(parts) >= 6:
            return {
                'type': 'mail',
                'sender': parts[1],
                'recipient': parts[2],
                'subject': parts[3],
                'body': parts[4],
                'uuid': parts[5]
            }
        elif msg_type == "DELETE_BULLETIN" and len(parts) >= 2:
            return {'type': 'delete_bulletin', 'uuid': parts[1]}
        elif msg_type == "DELETE_MAIL" and len(parts) >= 2:
            return {'type': 'delete_mail', 'uuid': parts[1]}

        return None
```

---

### Protocol 2: meshing-around Compatibility

**Reference:** https://github.com/SpudGunMan/meshing-around

meshing-around uses `bbslink` and `bbsack` commands for sync.

#### meshing-around Sync Behavior

1. **bbslink** - Initiates sync, sends messages
2. **bbsack** - Acknowledges received messages
3. Sync typically happens on a configured channel
4. Can be triggered manually or via scheduler
5. Uses pickle serialization for message data
6. Supports whitelist filtering (`bbs_link_whitelist`)

#### meshing-around Message Format

```
# Sync initiation
bbslink <serialized_message_data>

# Acknowledgment
bbsack <message_id>
```

#### FQ51BBS meshing-around Implementation

```python
class MeshingAroundCompatibility:
    """Sync with meshing-around peers using their native protocol."""

    def __init__(self, config):
        self.sync_channel = config.get('meshing_around_channel', 0)

    def send_bbslink(self, msg: dict, peer_id: str):
        """Send message using bbslink format."""
        # meshing-around expects specific format
        # [messageID, subject, message, fromNode, timestamp, threadID, replytoID]
        payload = [
            msg['id'],
            msg['subject'],
            msg['body'],
            msg['sender_node'],
            msg['timestamp'],
            msg.get('thread_id', 0),
            msg.get('reply_to', 0)
        ]

        # Serialize and send
        import pickle
        import base64
        serialized = base64.b64encode(pickle.dumps(payload)).decode()
        bbslink_msg = f"bbslink {serialized}"

        self.interface.sendText(bbslink_msg, destinationId=peer_id)

    def send_bbsack(self, message_id: str, peer_id: str):
        """Send acknowledgment."""
        self.interface.sendText(f"bbsack {message_id}", destinationId=peer_id)

    def parse_bbslink(self, raw: str) -> dict | None:
        """Parse incoming bbslink message."""
        if not raw.startswith("bbslink "):
            return None

        try:
            import pickle
            import base64
            serialized = raw[8:]  # Strip "bbslink "
            payload = pickle.loads(base64.b64decode(serialized))

            return {
                'type': 'bbslink',
                'id': payload[0],
                'subject': payload[1],
                'body': payload[2],
                'sender_node': payload[3],
                'timestamp': payload[4],
                'thread_id': payload[5] if len(payload) > 5 else 0,
                'reply_to': payload[6] if len(payload) > 6 else 0
            }
        except Exception as e:
            log.error(f"Failed to parse bbslink: {e}")
            return None

    def is_bbsack(self, raw: str) -> str | None:
        """Check if message is bbsack, return message_id if so."""
        if raw.startswith("bbsack "):
            return raw[7:]
        return None
```

---

### Protocol 3: FQ51BBS Native (DM-Based)

For FQ51BBS-to-FQ51BBS sync, we use our own optimized DM-based protocol.

#### Why DM-Based for FQ51?

| Aspect | Channel Broadcast | Targeted DM |
|--------|-------------------|-------------|
| Control | Anyone can see | Explicit peer only |
| Privacy | Public | Private |
| Reliability | Best-effort | ACK-confirmed |
| Bandwidth | Floods mesh | Point-to-point |

#### FQ51 Protocol Messages

All messages sent via DM to specific peer:

```
FQ51|<version>|<msg_type>|<payload>
```

| Type | Purpose | Payload |
|------|---------|---------|
| `HELLO` | Handshake | `bbs_name\|capabilities` |
| `SYNC_REQ` | Request sync | `since_timestamp\|types` |
| `SYNC_MSG` | Sync message | `uuid\|type\|sender\|recipient\|subject\|body\|timestamp` |
| `SYNC_ACK` | Acknowledge | `uuid\|status` |
| `SYNC_DONE` | Sync complete | `count` |
| `DELETE` | Delete message | `uuid` |

#### FQ51 Sync Flow (All Via DM)

```
FQ51BBS-A                                FQ51BBS-B
    │                                        │
    │─── DM: FQ51|1|HELLO|BBS-A|mail,bbs ───▶│
    │◀── DM: FQ51|1|HELLO|BBS-B|mail,bbs ────│
    │                                        │
    │─── DM: FQ51|1|SYNC_REQ|timestamp|all ─▶│
    │                                        │
    │◀── DM: FQ51|1|SYNC_MSG|uuid1|... ──────│
    │─── DM: FQ51|1|SYNC_ACK|uuid1|ok ──────▶│
    │                                        │
    │◀── DM: FQ51|1|SYNC_MSG|uuid2|... ──────│
    │─── DM: FQ51|1|SYNC_ACK|uuid2|ok ──────▶│
    │                                        │
    │◀── DM: FQ51|1|SYNC_DONE|2 ─────────────│
    │                                        │
```

#### FQ51 Native Implementation

```python
class FQ51NativeSync:
    """Native FQ51BBS-to-FQ51BBS sync via DM."""

    def __init__(self, config, db, interface):
        self.db = db
        self.interface = interface
        self.my_name = config.bbs.name

    async def sync_with_peer(self, peer_id: str):
        """Initiate sync with FQ51BBS peer via DM."""
        # Handshake
        hello = f"FQ51|1|HELLO|{self.my_name}|mail,bulletin"
        await self.send_dm(peer_id, hello)

        # Request sync
        last_sync = self.db.get_last_sync_time(peer_id)
        sync_req = f"FQ51|1|SYNC_REQ|{last_sync}|mail,bulletin"
        await self.send_dm(peer_id, sync_req)

    async def send_dm(self, peer_id: str, message: str):
        """Send direct message to peer."""
        await self.interface.sendText(
            message,
            destinationId=peer_id,
            wantAck=True
        )

    def handle_fq51_message(self, raw: str, sender: str):
        """Process incoming FQ51 protocol message."""
        parts = raw.split("|")
        if len(parts) < 3 or parts[0] != "FQ51":
            return

        version = parts[1]
        msg_type = parts[2]

        if msg_type == "HELLO":
            self.handle_hello(parts, sender)
        elif msg_type == "SYNC_REQ":
            self.handle_sync_request(parts, sender)
        elif msg_type == "SYNC_MSG":
            self.handle_sync_message(parts, sender)
        elif msg_type == "SYNC_ACK":
            self.handle_sync_ack(parts, sender)
        elif msg_type == "SYNC_DONE":
            self.handle_sync_done(parts, sender)

    async def handle_sync_request(self, parts: list, sender: str):
        """Respond to sync request with our messages."""
        since = int(parts[3])
        types = parts[4].split(",")

        messages = self.db.get_messages_since(since, types)

        for msg in messages:
            sync_msg = f"FQ51|1|SYNC_MSG|{msg['uuid']}|{msg['type']}|{msg['sender']}|{msg['recipient']}|{msg['subject']}|{msg['body']}|{msg['timestamp']}"
            await self.send_dm(sender, sync_msg)
            await asyncio.sleep(3)  # Rate limit

        await self.send_dm(sender, f"FQ51|1|SYNC_DONE|{len(messages)}")
```

---

### Unified Sync Manager

Routes to appropriate protocol based on peer type:

```python
class SyncManager:
    """Manages sync with all peer types."""

    def __init__(self, config, db, interface):
        self.peers = {p['node_id']: p for p in config.sync.peers}
        self.tc2 = TC2Compatibility(interface)
        self.meshing = MeshingAroundCompatibility(config, interface)
        self.fq51 = FQ51NativeSync(config, db, interface)
        self.db = db

    async def sync_with_peer(self, peer_id: str):
        """Sync with peer using their native protocol."""
        if peer_id not in self.peers:
            log.warning(f"Unknown peer {peer_id}")
            return

        peer = self.peers[peer_id]
        protocol = peer['protocol']

        if protocol == "tc2":
            await self.sync_tc2(peer_id)
        elif protocol == "meshing-around":
            await self.sync_meshing_around(peer_id)
        elif protocol == "fq51":
            await self.fq51.sync_with_peer(peer_id)

    def handle_incoming(self, raw: str, sender: str):
        """Route incoming sync message to appropriate handler."""
        # Check if from known peer
        if sender not in self.peers:
            return

        peer = self.peers[sender]
        protocol = peer['protocol']

        # Detect message type and route
        if raw.startswith("FQ51|"):
            self.fq51.handle_fq51_message(raw, sender)
        elif raw.startswith("bbslink ") or raw.startswith("bbsack "):
            self.handle_meshing_around(raw, sender)
        elif "|" in raw and raw.split("|")[0] in ["BULLETIN", "MAIL", "DELETE_BULLETIN", "DELETE_MAIL", "CHANNEL"]:
            self.handle_tc2(raw, sender)
```

---

### frozenbbs Note

**frozenbbs has no inter-BBS sync protocol.** From their documentation:

> "No federation or inter-BBS communication is currently documented."

Until frozenbbs implements sync, we cannot interoperate with it. This is noted for future reference if they add the capability.

---

### Rate Limiting (All Protocols)

| Operation | Limit | Rationale |
|-----------|-------|-----------|
| Sync messages | 1 per 3 seconds | Prevent flooding |
| Sync requests | 1 per 5 minutes per peer | Avoid hammering |
| Retries | Max 3 | Don't waste bandwidth |
| Retry backoff | Exponential (30s, 60s, 120s) | Progressive cooldown |

---

## Web Reader Interface

### Purpose

Optional read-only web interface allowing users to check boards and mail when a BBS node is online, without requiring a Meshtastic device.

**Key Constraint: Read-only.** No mesh writes, no sending messages. This keeps it lightweight and safe.

### Why This Is Lightweight

| Operation | Mesh Impact | Web Impact |
|-----------|-------------|------------|
| Read bulletin | None (already in DB) | SQLite query |
| Read mail | None (already in DB) | SQLite query |
| Login | None | Argon2 verify |
| Send message | Heavy (mesh TX) | **Not allowed** |

### Resource Impact (RPi Zero 2 W)

| Component | Memory | CPU |
|-----------|--------|-----|
| Flask/Bottle | ~15-25MB | Negligible |
| SQLite reads | Shared with BBS | Minimal |
| **Total added** | **~20MB** | **<5%** |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      RPi Zero 2 W                           │
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │    FQ51BBS      │         │   Web Reader    │           │
│  │  (main process) │         │  (Flask/Bottle) │           │
│  │                 │         │                 │           │
│  │  - Mesh I/O     │         │  - HTTP only    │           │
│  │  - Commands     │         │  - Read-only    │           │
│  │  - Sync         │         │  - SQLite reads │           │
│  └────────┬────────┘         └────────┬────────┘           │
│           │                           │                     │
│           └───────────┬───────────────┘                     │
│                       │                                     │
│              ┌────────▼────────┐                           │
│              │    SQLite DB    │                           │
│              │  (WAL mode)     │                           │
│              └─────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │  Reverse Proxy  │
              │  (TLS optional) │
              └─────────────────┘
```

### Configuration

```toml
[web_reader]
enabled = false                      # Toggle web reader on/off
host = "127.0.0.1"                   # Bind address (localhost only by default)
port = 8080                          # HTTP port
# For external access, use reverse proxy with TLS

# Authentication
use_bbs_auth = true                  # Use BBS user credentials for login
session_timeout_minutes = 30         # Auto-logout after inactivity
max_failed_logins = 5                # Lockout after N failures
lockout_minutes = 15                 # Lockout duration

# Rate limiting
requests_per_minute = 60             # Per-IP rate limit
login_attempts_per_minute = 5        # Prevent brute force

# Features (all read-only)
allow_board_browsing = true          # View bulletin boards
allow_mail_reading = true            # View personal mail (requires login)
allow_user_list = false              # Show online/registered users
show_node_status = true              # Show BBS node status/stats

# Appearance
terminal_style = true                # Green-on-black terminal aesthetic
motd_on_login = true                 # Show BBS MOTD after login
```

### Security Model

1. **Read-only by design** - No endpoints that write to mesh or DB
2. **Localhost by default** - External access requires explicit reverse proxy
3. **BBS credentials** - Reuses existing user auth (no separate accounts)
4. **Rate limiting** - Prevents brute force and DoS
5. **Session management** - Timeout and secure cookies
6. **SQLite read-only** - Web process opens DB in read-only mode

```python
# Web reader DB connection (read-only)
conn = sqlite3.connect('file:fq51bbs.db?mode=ro', uri=True)
```

### Endpoints

| Endpoint | Auth Required | Description |
|----------|---------------|-------------|
| `GET /` | No | Landing page, BBS info |
| `GET /login` | No | Login form |
| `POST /login` | No | Authenticate |
| `GET /logout` | Yes | End session |
| `GET /boards` | No* | List bulletin boards |
| `GET /boards/<id>` | No* | View board posts |
| `GET /boards/<id>/<post>` | No* | Read single post |
| `GET /mail` | Yes | List user's mail |
| `GET /mail/<id>` | Yes | Read single message |
| `GET /status` | No | BBS node status |

*Board access may require login depending on board type (public vs restricted)

### Implementation Sketch

```python
from flask import Flask, render_template, session, redirect, request
import sqlite3

app = Flask(__name__)
app.secret_key = config.web_reader.secret_key

def get_db():
    """Read-only database connection."""
    return sqlite3.connect(f'file:{config.database.path}?mode=ro', uri=True)

@app.route('/')
def index():
    return render_template('index.html',
                          bbs_name=config.bbs.name,
                          motd=config.bbs.motd)

@app.route('/boards')
def boards():
    db = get_db()
    boards = db.execute('SELECT * FROM boards').fetchall()
    return render_template('boards.html', boards=boards)

@app.route('/boards/<int:board_id>')
def board(board_id):
    db = get_db()
    posts = db.execute('''
        SELECT m.*, u.username
        FROM messages m
        LEFT JOIN users u ON m.sender_user_id = u.id
        WHERE m.board_id = ? AND m.msg_type = 'bulletin'
        ORDER BY m.created_at_us DESC
        LIMIT 50
    ''', (board_id,)).fetchall()
    return render_template('board.html', posts=posts)

@app.route('/mail')
def mail():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    messages = db.execute('''
        SELECT * FROM messages
        WHERE recipient_user_id = ? AND msg_type = 'mail'
        ORDER BY created_at_us DESC
    ''', (session['user_id'],)).fetchall()
    return render_template('mail.html', messages=messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verify against BBS user database
        user = verify_bbs_credentials(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/mail')

        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

if __name__ == '__main__':
    if config.web_reader.enabled:
        app.run(
            host=config.web_reader.host,
            port=config.web_reader.port
        )
```

### Terminal-Style CSS

```css
/* Terminal aesthetic */
body {
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.4;
}

.container {
    max-width: 80ch;  /* Terminal width */
    margin: 0 auto;
    padding: 1rem;
}

a {
    color: #00ffff;
}

.prompt::before {
    content: "> ";
    color: #ffff00;
}

.header {
    border-bottom: 1px solid #00ff00;
    margin-bottom: 1rem;
}

.message {
    border: 1px solid #333;
    padding: 0.5rem;
    margin: 0.5rem 0;
}

.unread {
    border-color: #00ff00;
}
```

### Reverse Proxy Example (Caddy)

```caddyfile
bbs.example.com {
    reverse_proxy localhost:8080

    # Optional: Basic rate limiting at proxy level
    rate_limit {
        zone bbs_zone {
            key {remote_host}
            events 100
            window 1m
        }
    }
}
```

### Dependencies

```
# Additional requirements for web reader
flask>=3.0.0           # Or bottle>=0.12 as alternative
```

### Process Management

Web reader can run as:

1. **Subprocess of BBS** - Started/stopped with main BBS process
2. **Separate systemd service** - Independent lifecycle
3. **Integrated** - Same process, threaded (not recommended for Z2W)

**Recommended:** Separate systemd service for isolation:

```ini
# /etc/systemd/system/fq51bbs-web.service
[Unit]
Description=FQ51BBS Web Reader
After=fq51bbs.service

[Service]
Type=simple
User=fq51bbs
ExecStart=/usr/bin/python3 -m fq51bbs.web
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Module Structure

### Directory Layout

```
fq51bbs/
├── fq51bbs/
│   ├── __init__.py
│   ├── __main__.py              # CLI entry point
│   ├── config.py                # Configuration loading
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── config_menu.py       # Interactive config interface
│   │   ├── setup_wizard.py      # Initial setup wizard
│   │   ├── user_admin.py        # User management screens
│   │   ├── sync_admin.py        # Sync/peer management
│   │   └── utils.py             # Terminal utilities (colors, boxes)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── bbs.py               # Main BBS class
│   │   ├── crypto.py            # Encryption utilities
│   │   └── rate_limiter.py      # Rate limiting
│   ├── db/
│   │   ├── __init__.py
│   │   ├── connection.py        # SQLite connection management
│   │   ├── models.py            # Data classes
│   │   ├── users.py             # User CRUD operations
│   │   ├── messages.py          # Message CRUD operations
│   │   ├── nodes.py             # Node tracking
│   │   └── migrations/          # Schema migrations
│   │       └── 001_initial.sql
│   ├── mesh/
│   │   ├── __init__.py
│   │   ├── interface.py         # Meshtastic connection
│   │   ├── packets.py           # Packet handling
│   │   └── radio.py             # Radio abstraction
│   ├── commands/
│   │   ├── __init__.py
│   │   ├── dispatcher.py        # Command routing
│   │   ├── auth.py              # REG, LOGIN, LOGOUT, PASSWD
│   │   ├── mail.py              # SM, CM, RM, DM (send/check/read/delete mail)
│   │   ├── boards.py            # BBS bulletin operations
│   │   ├── admin.py             # Admin commands
│   │   ├── help.py              # Help system
│   │   └── config_cmd.py        # User config commands
│   ├── sync/
│   │   ├── __init__.py
│   │   ├── manager.py           # Unified sync manager
│   │   ├── peers.py             # Peer management
│   │   └── compat/
│   │       ├── __init__.py
│   │       ├── meshing_around.py # bbslink/bbsack protocol
│   │       ├── tc2_bbs.py       # Pipe-delimited protocol
│   │       └── fq51_native.py   # Native DM-based protocol
│   ├── web/
│   │   ├── __init__.py
│   │   ├── __main__.py          # Web reader entry point
│   │   ├── app.py               # Flask/Bottle application
│   │   ├── auth.py              # Web authentication
│   │   ├── routes.py            # HTTP endpoints
│   │   ├── templates/           # Jinja2 templates
│   │   │   ├── base.html
│   │   │   ├── index.html
│   │   │   ├── login.html
│   │   │   ├── boards.html
│   │   │   ├── board.html
│   │   │   ├── mail.html
│   │   │   ├── message.html
│   │   │   └── status.html
│   │   └── static/
│   │       └── terminal.css     # Terminal-style CSS
│   └── utils/
│       ├── __init__.py
│       ├── pagination.py        # Message chunking
│       └── formatting.py        # Output formatting
├── config.example.toml          # Configuration template
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
└── tests/
    ├── __init__.py
    ├── test_crypto.py
    ├── test_commands.py
    ├── test_sync.py
    └── test_web.py
```

### Core Components

#### BBS Class (`core/bbs.py`)

Central orchestrator that:
- Initializes database and crypto
- Manages Meshtastic interface
- Routes incoming messages to command dispatcher
- Handles graceful shutdown

#### Crypto Module (`core/crypto.py`)

- `derive_key(password, salt)` - Argon2id key derivation
- `encrypt_message(plaintext, key)` - ChaCha20-Poly1305 encryption
- `decrypt_message(ciphertext, key)` - Decryption with auth verification
- `generate_salt()` - Cryptographically secure salt generation

#### Command Dispatcher (`commands/dispatcher.py`)

```python
COMMANDS = {
    "H": ("help", cmd_help, "always"),
    "?": ("help", cmd_help, "always"),
    "REG": ("register", cmd_register, "always"),
    "LOGIN": ("login", cmd_login, "always"),
    "SM": ("send_mail", cmd_send_mail, "authenticated"),
    "CM": ("check_mail", cmd_check_mail, "authenticated"),
    # ...
}

def dispatch(message, sender_node, user_session):
    cmd = message.split()[0].upper()
    if cmd in COMMANDS:
        name, handler, access = COMMANDS[cmd]
        if check_access(access, user_session):
            return handler(message, sender_node, user_session)
    return "Unknown command. Send H for help."
```

### Dependency Graph

```
__main__.py
    │
    ▼
core/bbs.py ◄─────────────────────────┐
    │                                 │
    ├──▶ config.py                    │
    │                                 │
    ├──▶ db/connection.py             │
    │       │                         │
    │       ├──▶ db/users.py          │
    │       ├──▶ db/messages.py       │
    │       └──▶ db/nodes.py          │
    │                                 │
    ├──▶ mesh/interface.py            │
    │       │                         │
    │       └──▶ mesh/packets.py      │
    │                                 │
    ├──▶ commands/dispatcher.py       │
    │       │                         │
    │       ├──▶ commands/auth.py     │
    │       ├──▶ commands/mail.py     │
    │       └──▶ commands/boards.py   │
    │                                 │
    └──▶ sync/protocol.py ────────────┘
            │
            └──▶ sync/peers.py
```

---

## Command Reference

### Authentication Commands

| Command | Format | Description | Access |
|---------|--------|-------------|--------|
| `REG` | `REG <username> <password>` | Register new user | Always |
| `LOGIN` | `LOGIN <username> <password>` | Authenticate | Always |
| `LOGOUT` | `LOGOUT` | End session | Authenticated |
| `PASSWD` | `PASSWD <old> <new>` | Change password | Authenticated |
| `ADDNODE` | `ADDNODE` | Associate current node | Authenticated |
| `RMNODE` | `RMNODE <node_id>` | Remove node association | Authenticated |
| `NODES` | `NODES` | List associated nodes | Authenticated |

### Mail Commands

| Command | Format | Description | Access |
|---------|--------|-------------|--------|
| `SM` | `SM <user_or_node> <subject> <body>` | Send mail | Authenticated |
| `CM` | `CM` | Check mail (count) | Authenticated |
| `RM` | `RM [n]` | Read mail (n=message#) | Authenticated |
| `DM` | `DM <n>` | Delete mail | Authenticated |
| `PURGE` | `PURGE` | Delete all mail | Authenticated |

### Bulletin Commands

| Command | Format | Description | Access |
|---------|--------|-------------|--------|
| `B` | `B` | List boards | Always |
| `B` | `B <board>` | Enter board | Always |
| `L` | `L [n]` | List posts (n=count) | In board |
| `R` | `R <n>` | Read post | In board |
| `P` | `P <subject> <body>` | Post to board | Authenticated + In board |
| `Q` | `Q` | Quit board | In board |

### Utility Commands

| Command | Format | Description | Access |
|---------|--------|-------------|--------|
| `H` or `?` | `H` | Show help | Always |
| `W` | `W` | Who's online | Always |
| `I` | `I` | BBS info | Always |
| `DESTRUCT` | `DESTRUCT CONFIRM` | Delete all user data | Authenticated |

### Admin Commands

| Command | Format | Description | Access |
|---------|--------|-------------|--------|
| `BAN` | `BAN <user>` | Ban user | Admin |
| `UNBAN` | `UNBAN <user>` | Unban user | Admin |
| `SYNC` | `SYNC [peer]` | Force sync | Admin |
| `PEERS` | `PEERS` | List BBS peers | Admin |
| `ANNOUNCE` | `ANNOUNCE <msg>` | Broadcast announcement | Admin |

---

## Configuration

### config.toml

```toml
[bbs]
name = "FQ51BBS"
callsign = "FQ51"                    # Short identifier
admin_password = "changeme"          # Required at startup
motd = "Welcome to FQ51BBS!"
max_message_age_days = 30            # Auto-expire messages
announcement_interval_hours = 12     # 0 to disable

[database]
path = "/var/lib/fq51bbs/fq51bbs.db"
backup_path = "/var/lib/fq51bbs/backups"
backup_interval_hours = 24

[meshtastic]
connection_type = "serial"           # serial | tcp | ble
serial_port = "/dev/ttyUSB0"         # For serial
tcp_host = "localhost"               # For tcp
tcp_port = 4403                      # For tcp
channel_index = 0                    # Primary channel
public_channel = 0                   # For broadcasts

[crypto]
argon2_time_cost = 3
argon2_memory_kb = 32768             # 32MB
argon2_parallelism = 1

# === FEATURE FLAGS ===
[features]
mail_enabled = true                  # Private mail system
boards_enabled = true                # Public bulletin boards
sync_enabled = true                  # Inter-BBS synchronization
registration_enabled = true          # Allow new user registration

# === OPERATING MODE ===
[operating_mode]
# Options: "full" | "mail_only" | "boards_only" | "repeater"
mode = "full"

[repeater]
# Only used in repeater mode
forward_mail = true
forward_bulletins = true
forward_to_peers = []                # Empty = forward to all known peers

# === SYNC SETTINGS ===
[sync]
enabled = true
auto_sync_interval_minutes = 60      # Scheduled sync with all peers

# Peers with protocol type (polyglot support)
[[sync.peers]]
node_id = "!abc123"
name = "TC2-BBS-West"
protocol = "tc2"                     # TC2-BBS-mesh protocol

[[sync.peers]]
node_id = "!def456"
name = "MeshAround-Central"
protocol = "meshing-around"          # meshing-around bbslink protocol

[[sync.peers]]
node_id = "!ghi789"
name = "FQ51BBS-East"
protocol = "fq51"                    # Native FQ51 DM-based protocol

# Bulletin sync (scheduled)
bulletin_sync_interval_minutes = 60  # Hourly

# Mail delivery
mail_delivery_mode = "instant"       # "instant" | "batched"
mail_batch_interval_minutes = 5      # Only if batched

# Delivery retry policy
mail_retry_attempts = 3              # Attempts before forwarding
mail_ack_timeout_seconds = 30        # Wait for ACK
mail_retry_backoff_base = 60         # First retry delay (doubles each time)
mail_max_hops = 3                    # Max BBS forwarding hops

# Participation flags
participate_in_mail_relay = true     # Help deliver others' mail
participate_in_bulletin_sync = true  # Sync boards with peers

# === ADMIN CHANNEL ===
[admin_channel]
enabled = true                       # Enable admin channel features
channel_index = 7                    # Dedicated channel for admin sync
# Note: Configure matching PSK in Meshtastic for this channel

# What to sync
sync_bans = true                     # Sync ban/unban across trusted peers
sync_peer_status = true              # Share peer health info

# Trust settings
trusted_peers = ["!abc123", "!def456"]  # Only accept admin sync from these
require_mutual_trust = true          # Both sides must list each other

[rate_limits]
messages_per_minute = 10
sync_messages_per_minute = 20
commands_per_minute = 30

# === WEB READER ===
[web_reader]
enabled = false                      # Toggle web reader on/off
host = "127.0.0.1"                   # Bind address (localhost by default)
port = 8080                          # HTTP port

# Authentication
use_bbs_auth = true                  # Use BBS credentials
session_timeout_minutes = 30         # Auto-logout
max_failed_logins = 5                # Lockout threshold
lockout_minutes = 15                 # Lockout duration

# Rate limiting
requests_per_minute = 60             # Per-IP limit
login_attempts_per_minute = 5        # Brute force protection

# Features (all read-only)
allow_board_browsing = true          # View bulletin boards
allow_mail_reading = true            # View personal mail
allow_user_list = false              # Show user list
show_node_status = true              # Show BBS status

# Appearance
terminal_style = true                # Green-on-black aesthetic
motd_on_login = true                 # Show MOTD after login

# === CLI CONFIGURATION INTERFACE ===
[cli_config]
enabled = true                       # Enable config CLI
require_admin = true                 # Require admin auth to access
auto_apply = false                   # Apply changes immediately (vs restart)
backup_on_change = true              # Auto-backup config before changes
color_output = true                  # Enable terminal colors
menu_timeout_minutes = 30            # Auto-exit after inactivity (0 = disabled)

[logging]
level = "INFO"                       # DEBUG | INFO | WARNING | ERROR
file = "/var/log/fq51bbs.log"
max_size_mb = 10
backup_count = 3
```

---

## Dependencies

### requirements.txt

```
# Core
meshtastic>=2.3.0          # Meshtastic Python API
pubsub>=4.0.3              # Pub/sub for async messaging

# Database
# (SQLite is built into Python)

# Cryptography
argon2-cffi>=23.1.0        # Argon2id password hashing
cryptography>=41.0.0       # ChaCha20-Poly1305

# Utilities
tomli>=2.0.0               # TOML config parsing (Python <3.11)

# Web Reader (optional, only if web_reader.enabled = true)
flask>=3.0.0               # Lightweight web framework

# Optional (development)
pytest>=7.0.0              # Testing
pytest-asyncio>=0.21.0     # Async test support
```

### System Requirements

- Python 3.9+ (3.11+ recommended)
- SQLite 3.35+ (for RETURNING clause)
- ~50MB disk space for typical deployment

---

## Performance Considerations

### Memory Budget (512MB Total)

| Component | Allocation | Notes |
|-----------|------------|-------|
| OS + System | ~200MB | Raspberry Pi OS Lite |
| Python Runtime | ~30MB | Base interpreter |
| FQ51BBS Process | ~50MB | Target max |
| Argon2 Operations | ~32MB | During key derivation only |
| SQLite Cache | ~10MB | Page cache |
| Headroom | ~190MB | For system operations |

### CPU Considerations

1. **Argon2id** - Expensive but infrequent (registration, login)
2. **ChaCha20** - Fast, suitable for every message
3. **SQLite** - Lightweight, no indexing overhead on small tables
4. **Async I/O** - Non-blocking radio operations

### Optimization Strategies

1. **Lazy loading** - Only decrypt messages when read
2. **Connection pooling** - Single SQLite connection per thread
3. **Message pagination** - Never load full message history
4. **Rate limiting** - Prevents CPU spikes from spam

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Password brute force | Argon2id with high memory cost |
| Message interception | ChaCha20-Poly1305 encryption |
| Replay attacks | UUID + timestamp in AAD |
| Node impersonation | User-node binding verification |
| Admin compromise | Master key in memory only |
| Database theft | All content encrypted at rest |

### Trust Levels

1. **Anonymous** - Can read help, BBS info only
2. **Observed** - Known node, not registered
3. **Registered** - Can send/receive mail, post to boards
4. **Admin** - Full system access

### Limitations

1. **No forward secrecy** - Compromised key decrypts all messages
2. **Trust-on-first-use** - No certificate authority
3. **Metadata visible** - Timestamps, sender/recipient IDs not encrypted
4. **Single point of failure** - Master key holder is trusted

---

## CLI Configuration Interface

### Design Inspiration

Based on [Meshtasticd-Configuration-Tool](https://github.com/chrismyers2000/Meshtasticd-Configuration-Tool), FQ51BBS includes an interactive CLI configuration system for setup and administration.

### Features

1. **Interactive Text Menus** - Step-by-step guided configuration
2. **SSH-Friendly** - Pure text-based, no GUI dependencies
3. **Progressive Setup** - Initial setup wizard + ongoing administration
4. **Live Configuration** - Changes apply immediately or on restart (configurable)
5. **Config Validation** - Validates settings before applying

### Menu Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    FQ51BBS Configuration                     │
│                      Version 1.0.0                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   [1] Initial Setup Wizard                                  │
│   [2] BBS Settings                                          │
│   [3] Meshtastic Connection                                 │
│   [4] User Management                                       │
│   [5] Sync & Peer Configuration                             │
│   [6] Security Settings                                     │
│   [7] Web Reader Settings                                   │
│   [8] View Current Configuration                            │
│   [9] Backup & Restore                                      │
│   [0] Exit                                                  │
│                                                             │
│   Select option [0-9]:                                      │
└─────────────────────────────────────────────────────────────┘
```

### Submenu Examples

#### Initial Setup Wizard
```
┌─────────────────────────────────────────────────────────────┐
│                   FQ51BBS Initial Setup                      │
│                      Step 1 of 6                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   BBS Name                                                  │
│   ────────                                                  │
│   Enter a name for your BBS (e.g., "Mountain View BBS"):    │
│                                                             │
│   > FQ51BBS_                                                │
│                                                             │
│   [Enter] Continue  [Esc] Cancel  [?] Help                  │
└─────────────────────────────────────────────────────────────┘
```

#### BBS Settings Menu
```
┌─────────────────────────────────────────────────────────────┐
│                      BBS Settings                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   [1] BBS Name ................... FQ51BBS                  │
│   [2] Callsign ................... FQ51                     │
│   [3] Admin Password ............. ********                 │
│   [4] MOTD ....................... Welcome to FQ51BBS!      │
│   [5] Message Expiration ......... 30 days                  │
│   [6] Announcement Interval ...... 12 hours                 │
│   [7] Operating Mode ............. full                     │
│                                                             │
│   [B] Back  [S] Save  [R] Reset to Defaults                 │
│                                                             │
│   Select option:                                            │
└─────────────────────────────────────────────────────────────┘
```

#### Meshtastic Connection
```
┌─────────────────────────────────────────────────────────────┐
│                  Meshtastic Connection                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Connection Type                                           │
│   ───────────────                                           │
│   [1] Serial  (USB connection)        ← Current             │
│   [2] TCP     (Network/IP)                                  │
│   [3] BLE     (Bluetooth)                                   │
│                                                             │
│   Current Settings:                                         │
│   Serial Port: /dev/ttyUSB0                                 │
│   Channel Index: 0                                          │
│   Status: Connected ✓                                       │
│                                                             │
│   [T] Test Connection  [B] Back  [S] Save                   │
└─────────────────────────────────────────────────────────────┘
```

#### User Management
```
┌─────────────────────────────────────────────────────────────┐
│                    User Management                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Users: 15 registered, 2 banned                            │
│                                                             │
│   [1] List All Users                                        │
│   [2] Search User                                           │
│   [3] View User Details                                     │
│   [4] Ban/Unban User                                        │
│   [5] Reset User Password                                   │
│   [6] Delete User                                           │
│   [7] Promote/Demote Admin                                  │
│   [8] Registration Settings                                 │
│                                                             │
│   [B] Back                                                  │
└─────────────────────────────────────────────────────────────┘
```

#### Sync & Peer Configuration
```
┌─────────────────────────────────────────────────────────────┐
│                 Sync & Peer Configuration                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Sync Status: Enabled                                      │
│   Last Sync: 2025-12-10 14:32:15                           │
│   Peers: 3 configured, 2 online                             │
│                                                             │
│   [1] View Peer List                                        │
│   [2] Add New Peer                                          │
│   [3] Edit Peer                                             │
│   [4] Remove Peer                                           │
│   [5] Force Sync Now                                        │
│   [6] Sync Settings                                         │
│   [7] Admin Channel Settings                                │
│                                                             │
│   [B] Back                                                  │
└─────────────────────────────────────────────────────────────┘
```

### Configuration

```toml
[cli_config]
enabled = true                       # Enable config CLI
require_admin = true                 # Require admin auth to access
auto_apply = false                   # Apply changes immediately (vs restart)
backup_on_change = true              # Auto-backup config before changes
color_output = true                  # Enable terminal colors
menu_timeout_minutes = 30            # Auto-exit after inactivity (0 = disabled)
```

### Entry Points

```bash
# Start configuration interface
python3 -m fq51bbs config

# Start setup wizard directly
python3 -m fq51bbs config --wizard

# Start specific submenu
python3 -m fq51bbs config --menu users
python3 -m fq51bbs config --menu sync
python3 -m fq51bbs config --menu meshtastic

# Non-interactive config operations
python3 -m fq51bbs config --show           # Dump current config
python3 -m fq51bbs config --validate       # Validate config file
python3 -m fq51bbs config --set bbs.name "New Name"
python3 -m fq51bbs config --backup
python3 -m fq51bbs config --restore backup_20251210.toml
```

### Implementation

```python
# fq51bbs/cli/config_menu.py

import sys
import os
from typing import Callable, Optional

class ConfigMenu:
    """Interactive configuration menu system."""

    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.running = True
        self.modified = False

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_box(self, title: str, content: list[str], width: int = 61):
        """Print a bordered menu box."""
        border_h = "─" * (width - 2)
        print(f"┌{border_h}┐")
        print(f"│{title.center(width - 2)}│")
        print(f"├{border_h}┤")
        for line in content:
            print(f"│ {line.ljust(width - 4)} │")
        print(f"└{border_h}┘")

    def prompt(self, message: str, default: str = "") -> str:
        """Get user input with optional default."""
        if default:
            result = input(f"{message} [{default}]: ").strip()
            return result if result else default
        return input(f"{message}: ").strip()

    def confirm(self, message: str) -> bool:
        """Get yes/no confirmation."""
        result = input(f"{message} [y/N]: ").strip().lower()
        return result in ('y', 'yes')

    def main_menu(self):
        """Display main configuration menu."""
        while self.running:
            self.clear_screen()

            content = [
                "",
                "  [1] Initial Setup Wizard",
                "  [2] BBS Settings",
                "  [3] Meshtastic Connection",
                "  [4] User Management",
                "  [5] Sync & Peer Configuration",
                "  [6] Security Settings",
                "  [7] Web Reader Settings",
                "  [8] View Current Configuration",
                "  [9] Backup & Restore",
                "  [0] Exit",
                "",
                f"  {'* Unsaved changes' if self.modified else ''}",
            ]

            self.print_box(
                f"FQ51BBS Configuration v{self.config.version}",
                content
            )

            choice = self.prompt("Select option [0-9]")

            handlers = {
                '1': self.setup_wizard,
                '2': self.bbs_settings,
                '3': self.meshtastic_settings,
                '4': self.user_management,
                '5': self.sync_settings,
                '6': self.security_settings,
                '7': self.web_reader_settings,
                '8': self.view_config,
                '9': self.backup_restore,
                '0': self.exit_menu,
            }

            if choice in handlers:
                handlers[choice]()

    def setup_wizard(self):
        """Run initial setup wizard."""
        steps = [
            ("BBS Name", self._wizard_bbs_name),
            ("Admin Password", self._wizard_admin_password),
            ("Meshtastic Connection", self._wizard_meshtastic),
            ("Operating Mode", self._wizard_operating_mode),
            ("Sync Settings", self._wizard_sync),
            ("Confirm & Save", self._wizard_confirm),
        ]

        for i, (name, handler) in enumerate(steps, 1):
            self.clear_screen()
            content = [
                "",
                f"  {name}",
                "  " + "─" * len(name),
                "",
            ]
            self.print_box(f"FQ51BBS Initial Setup - Step {i} of {len(steps)}", content)

            if not handler():
                if self.confirm("Cancel setup wizard?"):
                    return

    def bbs_settings(self):
        """BBS settings submenu."""
        while True:
            self.clear_screen()

            content = [
                "",
                f"  [1] BBS Name ................... {self.config.bbs.name}",
                f"  [2] Callsign ................... {self.config.bbs.callsign}",
                f"  [3] Admin Password ............. {'*' * 8}",
                f"  [4] MOTD ....................... {self.config.bbs.motd[:20]}...",
                f"  [5] Message Expiration ......... {self.config.bbs.max_message_age_days} days",
                f"  [6] Announcement Interval ...... {self.config.bbs.announcement_interval_hours} hours",
                f"  [7] Operating Mode ............. {self.config.operating_mode.mode}",
                "",
                "  [B] Back  [S] Save  [R] Reset to Defaults",
                "",
            ]

            self.print_box("BBS Settings", content)

            choice = self.prompt("Select option").upper()

            if choice == 'B':
                return
            elif choice == 'S':
                self.save_config()
            elif choice == 'R':
                if self.confirm("Reset BBS settings to defaults?"):
                    self.reset_bbs_defaults()
            elif choice == '1':
                self.config.bbs.name = self.prompt("BBS Name", self.config.bbs.name)
                self.modified = True
            # ... more options

    def user_management(self):
        """User management submenu."""
        while True:
            self.clear_screen()

            total_users = self.db.count_users()
            banned_users = self.db.count_banned_users()

            content = [
                "",
                f"  Users: {total_users} registered, {banned_users} banned",
                "",
                "  [1] List All Users",
                "  [2] Search User",
                "  [3] View User Details",
                "  [4] Ban/Unban User",
                "  [5] Reset User Password",
                "  [6] Delete User",
                "  [7] Promote/Demote Admin",
                "  [8] Registration Settings",
                "",
                "  [B] Back",
                "",
            ]

            self.print_box("User Management", content)

            choice = self.prompt("Select option").upper()

            if choice == 'B':
                return
            elif choice == '1':
                self.list_users()
            elif choice == '4':
                self.ban_user_menu()
            # ... more options

    def save_config(self):
        """Save configuration to file."""
        if self.config.cli_config.backup_on_change:
            self.backup_config()

        self.config.save()
        self.modified = False
        print("\n  Configuration saved successfully!")
        input("  Press Enter to continue...")

    def exit_menu(self):
        """Exit with unsaved changes check."""
        if self.modified:
            if self.confirm("You have unsaved changes. Save before exit?"):
                self.save_config()
        self.running = False


def main():
    """Entry point for config CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="FQ51BBS Configuration")
    parser.add_argument('--wizard', action='store_true', help="Start setup wizard")
    parser.add_argument('--menu', choices=['users', 'sync', 'meshtastic', 'security', 'web'],
                       help="Jump to specific menu")
    parser.add_argument('--show', action='store_true', help="Show current config")
    parser.add_argument('--validate', action='store_true', help="Validate config file")
    parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help="Set config value")
    parser.add_argument('--backup', action='store_true', help="Backup config")
    parser.add_argument('--restore', metavar='FILE', help="Restore config from backup")

    args = parser.parse_args()

    config = load_config()
    db = Database(config.database.path)

    if args.show:
        print(config.to_toml())
        return

    if args.validate:
        errors = config.validate()
        if errors:
            print("Configuration errors:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(1)
        print("Configuration is valid.")
        return

    if args.set:
        key, value = args.set
        config.set(key, value)
        config.save()
        print(f"Set {key} = {value}")
        return

    # Interactive menu
    menu = ConfigMenu(config, db)

    if args.wizard:
        menu.setup_wizard()
    elif args.menu:
        menu_map = {
            'users': menu.user_management,
            'sync': menu.sync_settings,
            'meshtastic': menu.meshtastic_settings,
            'security': menu.security_settings,
            'web': menu.web_reader_settings,
        }
        menu_map[args.menu]()
    else:
        menu.main_menu()


if __name__ == '__main__':
    main()
```

### Module Structure Addition

```
fq51bbs/
├── fq51bbs/
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── config_menu.py          # Main config interface
│   │   ├── setup_wizard.py         # Initial setup wizard
│   │   ├── user_admin.py           # User management screens
│   │   ├── sync_admin.py           # Sync/peer management
│   │   └── utils.py                # Terminal utilities (colors, boxes)
│   ...
```

### Terminal Utilities

```python
# fq51bbs/cli/utils.py

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Standard colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')


def draw_box(title: str, lines: list[str], width: int = 60) -> str:
    """Draw a Unicode box around content."""
    result = []
    border_h = "─" * (width - 2)

    result.append(f"┌{border_h}┐")
    if title:
        result.append(f"│{title.center(width - 2)}│")
        result.append(f"├{border_h}┤")

    for line in lines:
        padded = line.ljust(width - 4)[:width - 4]
        result.append(f"│ {padded} │")

    result.append(f"└{border_h}┘")
    return '\n'.join(result)


def progress_bar(current: int, total: int, width: int = 40) -> str:
    """Draw a simple progress bar."""
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    percent = int(100 * current / total)
    return f"[{bar}] {percent}%"


def table(headers: list[str], rows: list[list[str]], max_col_width: int = 20) -> str:
    """Format data as an ASCII table."""
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(str(cell))), max_col_width)

    # Build table
    result = []

    # Header
    header_line = " │ ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    result.append(header_line)
    result.append("─┼─".join("─" * w for w in widths))

    # Rows
    for row in rows:
        row_line = " │ ".join(str(cell).ljust(widths[i])[:widths[i]]
                              for i, cell in enumerate(row))
        result.append(row_line)

    return '\n'.join(result)
```

### Status Display (Real-time)

```python
# Live status view accessible from config menu

def status_display(bbs):
    """Real-time status display."""
    import time

    while True:
        os.system('clear')

        content = [
            "",
            f"  BBS Name: {bbs.config.bbs.name}",
            f"  Uptime: {format_uptime(bbs.start_time)}",
            "",
            f"  Meshtastic: {'Connected ✓' if bbs.mesh.connected else 'Disconnected ✗'}",
            f"  Node ID: {bbs.mesh.node_id or 'N/A'}",
            "",
            f"  Users Online: {bbs.session_count}",
            f"  Total Users: {bbs.db.count_users()}",
            f"  Messages Today: {bbs.stats.messages_today}",
            "",
            f"  Sync Peers: {bbs.sync.online_peer_count}/{bbs.sync.total_peer_count}",
            f"  Last Sync: {format_time(bbs.sync.last_sync_time)}",
            "",
            "  [Q] Quit status view",
        ]

        print(draw_box("FQ51BBS Status", content))

        # Check for quit
        if sys.stdin in select.select([sys.stdin], [], [], 1)[0]:
            if sys.stdin.read(1).lower() == 'q':
                break
```

---

## Implementation Phases

### Phase 1: Core Foundation
- [ ] Project scaffolding and configuration
- [ ] Database schema and migrations
- [ ] Crypto module (Argon2id, ChaCha20)
- [ ] Basic Meshtastic interface

### Phase 2: User System
- [ ] Registration and authentication
- [ ] Multi-node user binding
- [ ] Session management
- [ ] Password change/reset

### Phase 3: Messaging
- [ ] Private mail (send/receive/delete)
- [ ] Bulletin boards
- [ ] Message encryption/decryption
- [ ] Pagination and chunking

### Phase 4: Commands
- [ ] Command dispatcher
- [ ] Help system
- [ ] Admin commands
- [ ] User configuration

### Phase 5: Inter-BBS Sync
- [ ] FQ51 protocol implementation
- [ ] Peer discovery and management
- [ ] Message synchronization
- [ ] Compatibility adapters

### Phase 6: CLI Configuration Interface
- [ ] Interactive menu system
- [ ] Setup wizard
- [ ] User management screens
- [ ] Sync/peer configuration screens
- [ ] Terminal utilities (colors, boxes, tables)
- [ ] Non-interactive CLI commands

### Phase 7: Polish
- [ ] Auto-announcements
- [ ] Message expiration
- [ ] Backup/restore
- [ ] Monitoring/logging

---

## Docker Deployment

### Container Architecture

FQ51BBS is designed to run in Docker containers for easy deployment and isolation.

```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Host                             │
│  (RPi Zero 2 W / x86_64 / ARM64)                            │
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │   fq51bbs       │         │  fq51bbs-web    │           │
│  │   (main BBS)    │         │  (web reader)   │           │
│  │                 │         │  [optional]     │           │
│  │  - Mesh I/O     │         │  - Flask        │           │
│  │  - Commands     │         │  - Read-only    │           │
│  │  - Sync         │         │  - Port 8080    │           │
│  └────────┬────────┘         └────────┬────────┘           │
│           │                           │                     │
│           └───────────┬───────────────┘                     │
│                       │                                     │
│              ┌────────▼────────┐                           │
│              │  fq51bbs_data   │                           │
│              │    (volume)     │                           │
│              │  - SQLite DB    │                           │
│              │  - Backups      │                           │
│              └─────────────────┘                           │
│                       │                                     │
│              ┌────────▼────────┐                           │
│              │  /dev/ttyUSB0   │                           │
│              │  (Meshtastic)   │                           │
│              └─────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

### Dockerfile Strategy

Two Dockerfiles are provided:

| File | Target | Base Image | Optimization |
|------|--------|------------|--------------|
| `Dockerfile` | General x86_64/ARM64 | python:3.11-slim | Standard |
| `Dockerfile.rpi` | Raspberry Pi | python:3.11-slim | Memory, SD card |

### Docker Compose Files

| File | Purpose | Use Case |
|------|---------|----------|
| `docker-compose.yml` | Standard deployment | Desktop, server |
| `docker-compose.rpi.yml` | RPi optimized | Raspberry Pi Zero 2 W |

### Quick Start (Docker)

```bash
# Clone repository
git clone https://forge.echo6.co/fq51bbs/fq51bbs.git
cd fq51bbs

# Create configuration
cp config.example.toml config.toml
# Edit config.toml - CHANGE admin_password!

# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# With web reader
docker-compose --profile web up -d
```

### Quick Start (Raspberry Pi)

```bash
# On RPi Zero 2 W
git clone https://forge.echo6.co/fq51bbs/fq51bbs.git
cd fq51bbs

cp config.example.toml config.toml
vim config.toml  # Set admin_password, serial_port

# Build RPi-optimized image
docker-compose -f docker-compose.rpi.yml build

# Run
docker-compose -f docker-compose.rpi.yml up -d
```

### Volume Mounts

| Volume | Container Path | Purpose |
|--------|---------------|---------|
| `fq51bbs_data` | `/data` | SQLite database, backups |
| `fq51bbs_logs` | `/var/log` | Application logs |
| `config.toml` | `/app/config.toml` | Configuration (read-only) |

### Device Access

For serial connection to Meshtastic device:

```yaml
services:
  fq51bbs:
    devices:
      - /dev/ttyUSB0:/dev/ttyUSB0
      # or
      - /dev/ttyACM0:/dev/ttyACM0
      # or for GPIO UART
      - /dev/serial0:/dev/serial0
```

### Resource Limits

**Standard deployment:**
```yaml
deploy:
  resources:
    limits:
      memory: 256M
    reservations:
      memory: 64M
```

**Raspberry Pi:**
```yaml
deploy:
  resources:
    limits:
      cpus: "2"
      memory: 100M
    reservations:
      memory: 50M
```

### Health Checks

The container includes health checks:

```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import sqlite3; sqlite3.connect('/data/fq51bbs.db').execute('SELECT 1')"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FQ51BBS_CONFIG` | `/app/config.toml` | Config file path |
| `MESHTASTIC_HOST` | - | TCP host (if using TCP) |
| `MESHTASTIC_PORT` | `4403` | TCP port (if using TCP) |

### Cross-Platform Building

Build for multiple architectures:

```bash
# Enable buildx
docker buildx create --use

# Build for ARM64 (RPi)
docker buildx build --platform linux/arm64 -t fq51bbs:arm64 .

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 \
  -t fq51bbs:latest --push .
```

---

## Resolved Design Decisions

| Question | Decision | Rationale |
|----------|----------|-----------|
| Key escrow | **Admin Recovery Key** | Usability over absolute privacy; users can run own BBS for full privacy |
| Offline nodes | **3 attempts, then forward** | 30s ACK timeout, 60s/120s backoff, max 3 BBS hops |
| Board encryption | **Hybrid** | Shared key for public boards, per-user keys for restricted boards |
| Message size | **150 bytes per chunk** | Multi-message transmission with `[seq/total]` headers |
| Sync frequency | **Mail instant, boards hourly** | Time-sensitive vs batch-friendly |
| Feature toggles | **Full configurability** | mail_enabled, boards_enabled, operating modes (full/mail_only/boards_only/repeater) |
| Chunk timeout | **Hybrid: 2min per-chunk + 10min total** | Fast cleanup for stalled sends, tolerance for slow delivery |
| Max total message | **No limit** | Chunking handles arbitrary length (within reason) |
| Repeater announcements | **User configurable** | Toggle, message, frequency all settable in config |
| Ban list sync | **Admin channel required** | Dedicated channel with trusted peer list prevents unintended propagation |
| CLI config interface | **Meshtasticd-style menus** | Interactive text menus, setup wizard, SSH-friendly, like Meshtasticd-Configuration-Tool |

---

## All Design Questions Resolved

All architectural decisions have been finalized. The document is ready for implementation approval.

---

## Approval Required

This architecture document requires user approval before implementation begins.

**To approve:** Reply with "approved" or provide feedback for revisions.

---

## References

- [Meshtastic Python API](https://meshtastic.org/docs/development/python/library/)
- [meshing-around](https://github.com/SpudGunMan/meshing-around)
- [TC2-BBS-mesh](https://github.com/TheCommsChannel/TC2-BBS-mesh)
- [frozenbbs](https://github.com/kstrauser/frozenbbs)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RPi Zero 2 W Specifications](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/)
