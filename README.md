# FQ51BBS

Lightweight BBS for Meshtastic Mesh Networks

## Features

- **Encryption-first**: All messages encrypted at rest using password-derived keys (Argon2id + ChaCha20-Poly1305)
- **Multi-node identity**: Users can associate multiple Meshtastic nodes with their account
- **Inter-BBS sync**: Compatible with TC2-BBS-mesh, meshing-around, and other FQ51BBS nodes
- **Lightweight**: Designed to run on Raspberry Pi Zero 2 W (~100MB RAM)
- **Operating modes**: Full, mail-only, boards-only, or repeater mode
- **Docker ready**: Includes Dockerfile and docker-compose for easy deployment

## Quick Start

### Docker (Recommended)

```bash
# Clone repository
git clone https://forge.echo6.co/fq51bbs/fq51bbs.git
cd fq51bbs

# IMPORTANT: Create config.toml BEFORE starting Docker
cp config.example.toml config.toml
# Edit config.toml - CHANGE admin_password!

# Build and run
docker-compose up -d

# View logs
docker-compose logs -f
```

> **Note**: You MUST create `config.toml` before running `docker-compose up`.
> If Docker starts without the file, it will create a directory instead,
> causing errors. The container will show helpful instructions if this happens.

### Raspberry Pi

```bash
# On RPi Zero 2 W
docker-compose -f docker-compose.rpi.yml up -d
```

### Manual Installation

```bash
pip install -r requirements.txt
cp config.example.toml config.toml
# Edit config.toml
python -m fq51bbs
```

## Commands

| Command | Description |
|---------|-------------|
| `H` / `?` | Help |
| `REG <user> <pass>` | Register |
| `LOGIN <user> <pass>` | Login |
| `SM <to> <msg>` | Send mail |
| `CM` | Check mail |
| `B` | List boards |
| `I` | BBS info |

## Configuration

See `config.example.toml` for all options.

Key settings:
- `bbs.admin_password` - **CHANGE THIS!**
- `meshtastic.connection_type` - serial, tcp, or ble
- `meshtastic.serial_port` - e.g., /dev/ttyUSB0
- `operating_mode.mode` - full, mail_only, boards_only, repeater

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design documentation.

## License

MIT License
