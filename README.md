# FQ51BBS

> **Note**: This is a vibe-coded project built with AI assistance (Claude). While functional, it may contain bugs, unconventional patterns, or rough edges. Contributions and feedback welcome!

Lightweight BBS for Meshtastic Mesh Networks

## Features

- **Encryption-first**: All messages encrypted at rest using password-derived keys (Argon2id + ChaCha20-Poly1305)
- **Multi-node identity**: Users can associate multiple Meshtastic nodes with their account
- **Node-based 2FA**: Login requires both password and a registered node
- **Inter-BBS federation**: Send mail to users on other BBS nodes (`SEND user@remotebbs message`)
- **Multi-hop routing**: Messages can relay through intermediate BBS nodes to reach destination
- **Lightweight**: Designed to run on Raspberry Pi Zero 2 W (~100MB RAM)
- **Operating modes**: Full, mail-only, boards-only, or repeater mode
- **Docker ready**: Includes Dockerfile and docker-compose for easy deployment

## Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://forge.echo6.co/matt/fq51bbs.git
cd fq51bbs

# Start BBS
docker compose up -d

# View logs
docker compose logs -f
```

### Configuration

Open **http://localhost:7681** in your browser for the web-based config interface (dialog TUI).

Config is stored in the Docker volume and persists across restarts.

### Raspberry Pi

```bash
# On RPi Zero 2 W (build may take 10-15 min)
docker compose up -d
```

For faster deployment, build on a more powerful machine and push to a registry.

### Manual Installation

```bash
pip install -r requirements.txt
cp config.example.toml config.toml
# Edit config.toml
python -m fq51bbs
```

## Commands

### General
| Command | Description |
|---------|-------------|
| `?` / `HELP` | Show help (4 pages) |
| `? admin` | Admin command help |
| `INFO` | BBS information |

### Authentication
| Command | Description |
|---------|-------------|
| `REGISTER <user> <pass>` | Create account (auto-registers current node) |
| `LOGIN <user> <pass>` | Login (requires registered node) |
| `LOGOUT` | Log out |
| `PASSWD <old> <new>` | Change password |

### Node Management
| Command | Description |
|---------|-------------|
| `NODES` | List your registered nodes |
| `ADDNODE <node_id>` | Add a new node (run from existing device) |
| `NODES rm <node_id>` | Remove a node (can't remove last or current) |

### Mail
| Command | Description |
|---------|-------------|
| `SEND <user> <msg>` | Send local mail |
| `SEND <user@bbs> <msg>` | Send mail to remote BBS |
| `MAIL` | Check inbox summary |
| `READ` | List mail |
| `READ <n>` | Read message #n |
| `REPLY [n] <msg>` | Reply to message (n or last read) |
| `FORWARD [n] <user[@bbs]>` | Forward message |
| `DELETE <n>` | Delete message #n |

### Boards
| Command | Description |
|---------|-------------|
| `BOARD` | List boards |
| `BOARD <name>` | Enter board |
| `LIST` | List posts |
| `READ <n>` | Read post #n |
| `POST <subj> <body>` | Create post |
| `QUIT` | Exit board |

### Federation
| Command | Description |
|---------|-------------|
| `PEERS` | List connected BBS peers |

### Admin
| Command | Description |
|---------|-------------|
| `BAN <user> [reason]` | Ban user |
| `UNBAN <user>` | Unban user |
| `MKBOARD <name> [desc]` | Create board |
| `RMBOARD <name>` | Delete board |
| `ANNOUNCE <msg>` | Broadcast message |

### Account
| Command | Description |
|---------|-------------|
| `DESTRUCT CONFIRM` | Delete all your data |

## Remote Mail Federation

FQ51BBS supports sending mail between BBS nodes using `user@bbs` addressing:

```
SEND alice@REMOTE1 Hello from another BBS!
```

### How it works

1. **Pre-flight check**: Message limited to 450 chars for remote delivery
2. **Route discovery**: Your BBS finds a path to the destination
3. **Chunked delivery**: Message split into 150-char chunks (max 3)
4. **Multi-hop relay**: If your BBS can't reach the destination directly, it can relay through intermediate nodes

### Protocol Messages

| Message | Purpose |
|---------|---------|
| `MAILREQ` | Request to send mail (includes route info) |
| `MAILACK` | Destination accepts, ready for chunks |
| `MAILNAK` | Delivery rejected (user not found, loop, etc) |
| `MAILDAT` | Message chunk |
| `MAILDLV` | Delivery confirmation |

## Configuration

See `config.example.toml` for all options.

Key settings:
- `bbs.admin_password` - **CHANGE THIS!**
- `meshtastic.connection_type` - serial, tcp, or ble
- `meshtastic.serial_port` - e.g., /dev/ttyUSB0
- `operating_mode.mode` - full, mail_only, boards_only, repeater

### Peer Configuration (Federation)

Federation traffic is **whitelisted by peer** - only nodes configured as peers can send/receive BBS protocol messages. This prevents unauthorized nodes from injecting messages or abusing the relay system.

```toml
[[sync.peers]]
name = "REMOTE1"
node_id = "!abcd1234"
enabled = true

[[sync.peers]]
name = "REMOTE2"
node_id = "!efgh5678"
enabled = true
```

To federate with another BBS:
1. Exchange node IDs with the other BBS operator
2. Both sides add each other as peers in their config
3. Set `enabled = true` to activate the peering

## Security

- **Encryption at rest**: All messages encrypted with user-derived keys (Argon2id + ChaCha20-Poly1305)
- **Node-based 2FA**: Login requires both password AND a pre-registered Meshtastic node
- **Peer whitelisting**: BBS protocol messages only accepted from configured peers
- **Loop prevention**: Remote mail includes route tracking to prevent infinite relay loops
- **Hop limiting**: Maximum 5 hops for relayed messages

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design documentation.

## License

MIT License
