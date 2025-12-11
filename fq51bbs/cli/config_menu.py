"""
FQ51BBS Configuration Menu

Interactive CLI configuration interface.
"""

import os
import sys
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run_config(args) -> int:
    """
    Run configuration interface.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    from ..config import load_config, Config

    config_path = getattr(args, 'config', Path('config.toml'))

    # Handle non-interactive commands first
    if getattr(args, 'show', False):
        config = load_config(config_path)
        print(config_to_toml(config))
        return 0

    if getattr(args, 'validate', False):
        config = load_config(config_path)
        errors = config.validate()
        if errors:
            print("Configuration errors:")
            for err in errors:
                print(f"  - {err}")
            return 1
        print("Configuration is valid.")
        return 0

    if getattr(args, 'backup', False):
        return backup_config(config_path)

    if getattr(args, 'restore', None):
        return restore_config(Path(args.restore), config_path)

    if getattr(args, 'set', None):
        key, value = args.set
        return set_config_value(config_path, key, value)

    # Interactive mode
    config = load_config(config_path)
    menu = ConfigMenu(config, config_path)

    if getattr(args, 'wizard', False):
        menu.setup_wizard()
    elif getattr(args, 'menu', None):
        menu_map = {
            'users': menu.user_management,
            'sync': menu.sync_settings,
            'meshtastic': menu.meshtastic_settings,
            'security': menu.security_settings,
            'web': menu.web_reader_settings,
        }
        if args.menu in menu_map:
            menu_map[args.menu]()
    else:
        menu.main_menu()

    return 0


class ConfigMenu:
    """Interactive configuration menu system."""

    def __init__(self, config, config_path: Path):
        self.config = config
        self.config_path = config_path
        self.running = True
        self.modified = False

    def clear_screen(self):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_box(self, title: str, content: list[str], width: int = 61):
        """Print a bordered menu box."""
        border_h = "─" * (width - 2)
        print(f"┌{border_h}┐")
        print(f"│{title.center(width - 2)}│")
        print(f"├{border_h}┤")
        for line in content:
            padded = line.ljust(width - 4)[:width - 4]
            print(f"│ {padded} │")
        print(f"└{border_h}┘")

    def prompt(self, message: str, default: str = "") -> str:
        """Get user input with optional default."""
        import sys
        if default:
            sys.stdout.write(f"{message} [{default}]: ")
            sys.stdout.flush()
            result = sys.stdin.readline().strip()
            return result if result else default
        sys.stdout.write(f"{message}: ")
        sys.stdout.flush()
        return sys.stdin.readline().strip()

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

            from .. import __version__
            self.print_box(f"FQ51BBS Configuration v{__version__}", content)

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
        """Run initial setup wizard for first-time configuration."""
        self.clear_screen()

        print("┌───────────────────────────────────────────────────────────┐")
        print("│            FQ51BBS Initial Setup Wizard                   │")
        print("└───────────────────────────────────────────────────────────┘")
        print()
        print("Welcome! This wizard will help you configure your BBS.")
        print("Press Enter to accept defaults shown in [brackets].")
        print()

        # Step 1: BBS Identity
        print("─── Step 1: BBS Identity ───")
        self.config.bbs.name = self.prompt("BBS Name", self.config.bbs.name)
        self.config.bbs.callsign = self.prompt("Callsign (short identifier)", self.config.bbs.callsign)
        self.config.bbs.motd = self.prompt("Welcome message (MOTD)", self.config.bbs.motd)
        print()

        # Step 2: Admin Password
        print("─── Step 2: Admin Password ───")
        print("Set a secure admin password for BBS management.")
        while True:
            password = self.prompt("Admin password")
            if not password:
                print("  Password cannot be empty.")
                continue
            if password in ("changeme", "CHANGE_ME", "admin", "password"):
                print("  Please choose a more secure password.")
                continue
            confirm = self.prompt("Confirm password")
            if password != confirm:
                print("  Passwords don't match. Try again.")
                continue
            self.config.bbs.admin_password = password
            break
        print()

        # Step 3: Meshtastic Connection
        print("─── Step 3: Meshtastic Connection ───")
        print("How is your Meshtastic device connected?")
        print("  [1] USB Serial (e.g., /dev/ttyUSB0)")
        print("  [2] TCP Network (e.g., meshtastic.local:4403)")
        print("  [3] Skip for now (configure later)")

        conn_choice = self.prompt("Connection type [1-3]", "1")

        if conn_choice == "1":
            self.config.meshtastic.connection_type = "serial"
            self.config.meshtastic.serial_port = self.prompt(
                "Serial port", self.config.meshtastic.serial_port
            )
        elif conn_choice == "2":
            self.config.meshtastic.connection_type = "tcp"
            self.config.meshtastic.tcp_host = self.prompt(
                "TCP host", self.config.meshtastic.tcp_host
            )
            port_str = self.prompt("TCP port", str(self.config.meshtastic.tcp_port))
            try:
                self.config.meshtastic.tcp_port = int(port_str)
            except ValueError:
                print("  Invalid port, using default 4403")
                self.config.meshtastic.tcp_port = 4403
        print()

        # Step 4: Operating Mode
        print("─── Step 4: Operating Mode ───")
        print("Select how this BBS should operate:")
        print("  [1] Full - Mail and bulletin boards (default)")
        print("  [2] Mail Only - Private messages only")
        print("  [3] Boards Only - Public bulletins only")
        print("  [4] Repeater - Relay messages between nodes")

        mode_choice = self.prompt("Operating mode [1-4]", "1")
        mode_map = {"1": "full", "2": "mail_only", "3": "boards_only", "4": "repeater"}
        self.config.operating_mode.mode = mode_map.get(mode_choice, "full")
        print()

        # Step 5: Features
        print("─── Step 5: Features ───")
        reg_input = input("Allow new user registration? [Y/n]: ").strip().lower()
        self.config.features.registration_enabled = reg_input not in ('n', 'no')
        self.config.features.sync_enabled = self.confirm("Enable inter-BBS sync?")
        print()

        # Summary and Save
        print("─── Configuration Summary ───")
        print(f"  BBS Name:     {self.config.bbs.name}")
        print(f"  Callsign:     {self.config.bbs.callsign}")
        print(f"  Connection:   {self.config.meshtastic.connection_type}")
        if self.config.meshtastic.connection_type == "serial":
            print(f"  Serial Port:  {self.config.meshtastic.serial_port}")
        else:
            print(f"  TCP Host:     {self.config.meshtastic.tcp_host}:{self.config.meshtastic.tcp_port}")
        print(f"  Mode:         {self.config.operating_mode.mode}")
        print(f"  Sync:         {'enabled' if self.config.features.sync_enabled else 'disabled'}")
        print()

        if self.confirm("Save this configuration?"):
            self.save_config()
            print()
            print("Setup complete! Your BBS is ready to run.")
            print("Run 'docker-compose up -d' to start in background.")
        else:
            print("Configuration not saved. Run the wizard again to reconfigure.")

        print()
        input("Press Enter to continue...")

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
                "  [B] Back  [S] Save",
                "",
            ]

            self.print_box("BBS Settings", content)

            choice = self.prompt("Select option").upper()

            if choice == 'B':
                return
            elif choice == 'S':
                self.save_config()
            elif choice == '1':
                self.config.bbs.name = self.prompt("BBS Name", self.config.bbs.name)
                self.modified = True
            elif choice == '2':
                self.config.bbs.callsign = self.prompt("Callsign", self.config.bbs.callsign)
                self.modified = True

    def meshtastic_settings(self):
        """Meshtastic connection settings."""
        self.clear_screen()
        print("Meshtastic settings not yet fully implemented.")
        input("Press Enter to continue...")

    def user_management(self):
        """User management submenu."""
        self.clear_screen()
        print("User management not yet implemented.")
        input("Press Enter to continue...")

    def sync_settings(self):
        """Sync settings submenu."""
        self.clear_screen()
        print("Sync settings not yet implemented.")
        input("Press Enter to continue...")

    def security_settings(self):
        """Security settings submenu."""
        self.clear_screen()
        print("Security settings not yet implemented.")
        input("Press Enter to continue...")

    def web_reader_settings(self):
        """Web reader settings submenu."""
        self.clear_screen()
        print("Web reader settings not yet implemented.")
        input("Press Enter to continue...")

    def view_config(self):
        """View current configuration."""
        self.clear_screen()
        print(config_to_toml(self.config))
        input("\nPress Enter to continue...")

    def backup_restore(self):
        """Backup and restore submenu."""
        self.clear_screen()
        print("Backup/restore not yet implemented.")
        input("Press Enter to continue...")

    def save_config(self):
        """Save configuration to file."""
        try:
            self.config.save(self.config_path)
            self.modified = False
            print("\n  Configuration saved successfully!")
        except Exception as e:
            print(f"\n  Error saving config: {e}")
        input("  Press Enter to continue...")

    def exit_menu(self):
        """Exit with unsaved changes check."""
        if self.modified:
            if self.confirm("You have unsaved changes. Save before exit?"):
                self.save_config()
        self.running = False


def config_to_toml(config) -> str:
    """Convert config to TOML string representation."""
    # Simple representation for now
    lines = ["# FQ51BBS Configuration", ""]

    lines.append("[bbs]")
    lines.append(f'name = "{config.bbs.name}"')
    lines.append(f'callsign = "{config.bbs.callsign}"')
    lines.append(f'motd = "{config.bbs.motd}"')
    lines.append(f"max_message_age_days = {config.bbs.max_message_age_days}")
    lines.append("")

    lines.append("[meshtastic]")
    lines.append(f'connection_type = "{config.meshtastic.connection_type}"')
    lines.append(f'serial_port = "{config.meshtastic.serial_port}"')
    lines.append(f"channel_index = {config.meshtastic.channel_index}")
    lines.append("")

    lines.append("[operating_mode]")
    lines.append(f'mode = "{config.operating_mode.mode}"')
    lines.append("")

    lines.append("[features]")
    lines.append(f"mail_enabled = {str(config.features.mail_enabled).lower()}")
    lines.append(f"boards_enabled = {str(config.features.boards_enabled).lower()}")
    lines.append(f"sync_enabled = {str(config.features.sync_enabled).lower()}")
    lines.append(f"registration_enabled = {str(config.features.registration_enabled).lower()}")

    return "\n".join(lines)


def backup_config(config_path: Path) -> int:
    """Backup configuration file."""
    import shutil
    from datetime import datetime

    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        return 1

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f".{timestamp}.bak")

    shutil.copy(config_path, backup_path)
    print(f"Backed up to: {backup_path}")
    return 0


def restore_config(backup_path: Path, config_path: Path) -> int:
    """Restore configuration from backup."""
    import shutil

    if not backup_path.exists():
        print(f"Backup file not found: {backup_path}")
        return 1

    shutil.copy(backup_path, config_path)
    print(f"Restored from: {backup_path}")
    return 0


def set_config_value(config_path: Path, key: str, value: str) -> int:
    """Set a specific configuration value."""
    from ..config import load_config

    config = load_config(config_path)

    # Parse dotted key (e.g., "bbs.name")
    parts = key.split(".")
    obj = config

    for part in parts[:-1]:
        if hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            print(f"Invalid config key: {key}")
            return 1

    final_key = parts[-1]
    if not hasattr(obj, final_key):
        print(f"Invalid config key: {key}")
        return 1

    # Convert value to appropriate type
    current = getattr(obj, final_key)
    if isinstance(current, bool):
        value = value.lower() in ('true', '1', 'yes')
    elif isinstance(current, int):
        value = int(value)
    elif isinstance(current, float):
        value = float(value)

    setattr(obj, final_key, value)
    config.save(config_path)

    print(f"Set {key} = {value}")
    return 0
