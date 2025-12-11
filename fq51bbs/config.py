"""
FQ51BBS Configuration Module

Handles loading, validation, and management of configuration settings.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Use tomllib for Python 3.11+, tomli for earlier versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        raise ImportError("Please install tomli: pip install tomli")


@dataclass
class BBSConfig:
    """BBS general settings."""
    name: str = "FQ51BBS"
    callsign: str = "FQ51"
    admin_password: str = "changeme"
    motd: str = "Welcome to FQ51BBS!"
    max_message_age_days: int = 30
    announcement_interval_hours: int = 12


@dataclass
class DatabaseConfig:
    """Database settings."""
    path: str = "/var/lib/fq51bbs/fq51bbs.db"
    backup_path: str = "/var/lib/fq51bbs/backups"
    backup_interval_hours: int = 24


@dataclass
class MeshtasticConfig:
    """Meshtastic connection settings."""
    connection_type: str = "serial"  # serial | tcp | ble
    serial_port: str = "/dev/ttyUSB0"
    tcp_host: str = "localhost"
    tcp_port: int = 4403
    channel_index: int = 0
    public_channel: int = 0


@dataclass
class CryptoConfig:
    """Cryptography settings."""
    argon2_time_cost: int = 3
    argon2_memory_kb: int = 32768  # 32MB - RPi friendly
    argon2_parallelism: int = 1


@dataclass
class FeaturesConfig:
    """Feature toggles."""
    mail_enabled: bool = True
    boards_enabled: bool = True
    sync_enabled: bool = True
    registration_enabled: bool = True


@dataclass
class OperatingModeConfig:
    """Operating mode settings."""
    mode: str = "full"  # full | mail_only | boards_only | repeater


@dataclass
class RepeaterConfig:
    """Repeater mode settings."""
    forward_mail: bool = True
    forward_bulletins: bool = True
    forward_to_peers: list[str] = field(default_factory=list)
    announce_enabled: bool = True
    announce_message: str = "FQ51BBS Relay active. SM <user> <msg> to send mail."
    announce_interval_hours: int = 12
    announce_channel: int = 0


@dataclass
class SyncPeer:
    """Single sync peer configuration."""
    node_id: str
    name: str
    protocol: str  # tc2 | meshing-around | fq51


@dataclass
class SyncConfig:
    """Sync settings."""
    enabled: bool = True
    auto_sync_interval_minutes: int = 60
    bulletin_sync_interval_minutes: int = 60
    mail_delivery_mode: str = "instant"  # instant | batched
    mail_batch_interval_minutes: int = 5
    mail_retry_attempts: int = 3
    mail_ack_timeout_seconds: int = 30
    mail_retry_backoff_base: int = 60
    mail_max_hops: int = 3
    participate_in_mail_relay: bool = True
    participate_in_bulletin_sync: bool = True
    peers: list[SyncPeer] = field(default_factory=list)


@dataclass
class AdminChannelConfig:
    """Admin channel settings."""
    enabled: bool = True
    channel_index: int = 7
    sync_bans: bool = True
    sync_peer_status: bool = True
    trusted_peers: list[str] = field(default_factory=list)
    require_mutual_trust: bool = True


@dataclass
class RateLimitsConfig:
    """Rate limiting settings."""
    messages_per_minute: int = 10
    sync_messages_per_minute: int = 20
    commands_per_minute: int = 30


@dataclass
class WebReaderConfig:
    """Web reader interface settings."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080
    use_bbs_auth: bool = True
    session_timeout_minutes: int = 30
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    requests_per_minute: int = 60
    login_attempts_per_minute: int = 5
    allow_board_browsing: bool = True
    allow_mail_reading: bool = True
    allow_user_list: bool = False
    show_node_status: bool = True
    terminal_style: bool = True
    motd_on_login: bool = True


@dataclass
class CLIConfigSettings:
    """CLI configuration interface settings."""
    enabled: bool = True
    require_admin: bool = True
    auto_apply: bool = False
    backup_on_change: bool = True
    color_output: bool = True
    menu_timeout_minutes: int = 30


@dataclass
class LoggingConfig:
    """Logging settings."""
    level: str = "INFO"
    file: str = "/var/log/fq51bbs.log"
    max_size_mb: int = 10
    backup_count: int = 3


@dataclass
class Config:
    """Main configuration container."""
    bbs: BBSConfig = field(default_factory=BBSConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    meshtastic: MeshtasticConfig = field(default_factory=MeshtasticConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    features: FeaturesConfig = field(default_factory=FeaturesConfig)
    operating_mode: OperatingModeConfig = field(default_factory=OperatingModeConfig)
    repeater: RepeaterConfig = field(default_factory=RepeaterConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)
    admin_channel: AdminChannelConfig = field(default_factory=AdminChannelConfig)
    rate_limits: RateLimitsConfig = field(default_factory=RateLimitsConfig)
    web_reader: WebReaderConfig = field(default_factory=WebReaderConfig)
    cli_config: CLIConfigSettings = field(default_factory=CLIConfigSettings)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # BBS validation
        if not self.bbs.name:
            errors.append("bbs.name cannot be empty")
        if self.bbs.admin_password == "changeme":
            errors.append("bbs.admin_password must be changed from default")

        # Operating mode validation
        valid_modes = ["full", "mail_only", "boards_only", "repeater"]
        if self.operating_mode.mode not in valid_modes:
            errors.append(f"operating_mode.mode must be one of: {valid_modes}")

        # Meshtastic validation
        valid_connections = ["serial", "tcp", "ble"]
        if self.meshtastic.connection_type not in valid_connections:
            errors.append(f"meshtastic.connection_type must be one of: {valid_connections}")

        # Crypto validation (RPi constraints)
        if self.crypto.argon2_memory_kb > 65536:  # 64MB max for RPi
            errors.append("crypto.argon2_memory_kb should not exceed 65536 (64MB) for RPi compatibility")

        # Sync peer validation
        for peer in self.sync.peers:
            if peer.protocol not in ["tc2", "meshing-around", "fq51"]:
                errors.append(f"Invalid protocol '{peer.protocol}' for peer {peer.name}")

        return errors

    def save(self, path: Path):
        """Save configuration to TOML file."""
        import toml  # For writing

        # Convert dataclasses to dict
        data = self._to_dict()

        with open(path, "w") as f:
            toml.dump(data, f)

    def _to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary for serialization."""
        from dataclasses import asdict
        return asdict(self)


def load_config(path: Path) -> Config:
    """Load configuration from TOML file."""
    config = Config()

    if not path.exists():
        return config

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Map TOML sections to config dataclasses
    if "bbs" in data:
        config.bbs = BBSConfig(**data["bbs"])

    if "database" in data:
        config.database = DatabaseConfig(**data["database"])

    if "meshtastic" in data:
        config.meshtastic = MeshtasticConfig(**data["meshtastic"])

    if "crypto" in data:
        config.crypto = CryptoConfig(**data["crypto"])

    if "features" in data:
        config.features = FeaturesConfig(**data["features"])

    if "operating_mode" in data:
        config.operating_mode = OperatingModeConfig(**data["operating_mode"])

    if "repeater" in data:
        config.repeater = RepeaterConfig(**data["repeater"])

    if "sync" in data:
        sync_data = data["sync"].copy()
        peers = []
        for peer_data in sync_data.pop("peers", []):
            peers.append(SyncPeer(**peer_data))
        config.sync = SyncConfig(**sync_data, peers=peers)

    if "admin_channel" in data:
        config.admin_channel = AdminChannelConfig(**data["admin_channel"])

    if "rate_limits" in data:
        config.rate_limits = RateLimitsConfig(**data["rate_limits"])

    if "web_reader" in data:
        config.web_reader = WebReaderConfig(**data["web_reader"])

    if "cli_config" in data:
        config.cli_config = CLIConfigSettings(**data["cli_config"])

    if "logging" in data:
        config.logging = LoggingConfig(**data["logging"])

    return config


def create_default_config(path: Path):
    """Create a default configuration file."""
    config = Config()
    config.save(path)
