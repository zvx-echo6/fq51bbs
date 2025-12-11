"""
FQ51BBS Command Dispatcher

Routes incoming messages to appropriate command handlers.
"""

import logging
import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.bbs import FQ51BBS

logger = logging.getLogger(__name__)


class CommandDispatcher:
    """
    Dispatches commands to appropriate handlers.

    Commands are case-insensitive and can have arguments.
    """

    def __init__(self, bbs: "FQ51BBS"):
        """
        Initialize dispatcher with BBS instance.

        Args:
            bbs: Parent BBS instance for accessing services
        """
        self.bbs = bbs

        # Command registry: command -> (handler_func, access_level, help_text)
        # Access levels: "always", "authenticated", "admin"
        self._commands = {}

        # Register built-in commands
        self._register_builtins()

    def _register_builtins(self):
        """Register built-in commands."""
        # Help commands
        self.register("H", self.cmd_help, "always", "Show help")
        self.register("?", self.cmd_help, "always", "Show help")
        self.register("HELP", self.cmd_help, "always", "Show help")

        # Info commands
        self.register("I", self.cmd_info, "always", "BBS information")
        self.register("INFO", self.cmd_info, "always", "BBS information")
        self.register("W", self.cmd_who, "always", "Who's online")
        self.register("WHO", self.cmd_who, "always", "Who's online")

        # Authentication commands
        self.register("REG", self.cmd_register, "always", "Register: REG <user> <pass>")
        self.register("LOGIN", self.cmd_login, "always", "Login: LOGIN <user> <pass>")
        self.register("LOGOUT", self.cmd_logout, "authenticated", "Log out")
        self.register("PASSWD", self.cmd_passwd, "authenticated", "Change password")

        # Node management
        self.register("ADDNODE", self.cmd_addnode, "authenticated", "Add current node")
        self.register("RMNODE", self.cmd_rmnode, "authenticated", "Remove node")
        self.register("NODES", self.cmd_nodes, "authenticated", "List your nodes")

        # Mail commands
        self.register("SM", self.cmd_send_mail, "authenticated", "Send mail: SM <to> <msg>")
        self.register("CM", self.cmd_check_mail, "authenticated", "Check mail count")
        self.register("RM", self.cmd_read_mail, "authenticated", "Read mail: RM [n]")
        self.register("DM", self.cmd_delete_mail, "authenticated", "Delete mail: DM <n>")

        # Board commands
        self.register("B", self.cmd_boards, "always", "List boards or enter: B [name]")
        self.register("L", self.cmd_list, "always", "List posts: L [n]")
        self.register("R", self.cmd_read, "always", "Read post: R <n>")
        self.register("P", self.cmd_post, "authenticated", "Post: P <subj> <body>")
        self.register("Q", self.cmd_quit_board, "always", "Quit board")

        # Admin commands
        self.register("BAN", self.cmd_ban, "admin", "Ban user: BAN <user> [reason]")
        self.register("UNBAN", self.cmd_unban, "admin", "Unban user: UNBAN <user>")
        self.register("SYNC", self.cmd_sync, "admin", "Force sync: SYNC [peer]")
        self.register("ANNOUNCE", self.cmd_announce, "admin", "Broadcast: ANNOUNCE <msg>")

        # Self-destruct
        self.register("DESTRUCT", self.cmd_destruct, "authenticated", "Delete all your data")

    def register(
        self,
        command: str,
        handler,
        access: str,
        help_text: str
    ):
        """Register a command handler."""
        self._commands[command.upper()] = (handler, access, help_text)

    def dispatch(
        self,
        message: str,
        sender: str,
        channel: int
    ) -> Optional[str]:
        """
        Dispatch a message to the appropriate command handler.

        Args:
            message: Raw message text
            sender: Sender node ID
            channel: Channel the message arrived on

        Returns:
            Response string or None if no response
        """
        if not message or not message.strip():
            return None

        # Parse command and arguments
        parts = message.strip().split(maxsplit=1)
        cmd = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        # Look up command
        if cmd not in self._commands:
            return "Unknown command. Send H for help."

        handler, access, _ = self._commands[cmd]

        # Check access
        session = self._get_session(sender)

        if access == "authenticated" and not session.get("user_id"):
            return "Please login first. REG <user> <pass> or LOGIN <user> <pass>"

        if access == "admin" and not session.get("is_admin"):
            return "Admin access required."

        # Check feature availability
        if not self._check_feature(cmd):
            return "This feature is disabled on this BBS."

        # Execute command
        try:
            self.bbs.stats.commands_processed += 1
            return handler(sender, args, session, channel)
        except Exception as e:
            logger.error(f"Error executing {cmd}: {e}")
            self.bbs.stats.errors += 1
            return "Error processing command."

    def _get_session(self, sender: str) -> dict:
        """Get or create session for sender."""
        if sender not in self.bbs._sessions:
            self.bbs._sessions[sender] = {
                "user_id": None,
                "username": None,
                "is_admin": False,
                "current_board": None,
                "last_activity": 0,
            }
        return self.bbs._sessions[sender]

    def _check_feature(self, cmd: str) -> bool:
        """Check if the feature for this command is enabled."""
        mail_commands = {"SM", "CM", "RM", "DM"}
        board_commands = {"B", "L", "R", "P", "Q"}

        if cmd in mail_commands and not self.bbs.config.features.mail_enabled:
            return False

        if cmd in board_commands and not self.bbs.config.features.boards_enabled:
            return False

        return True

    # === Command Handlers ===

    def cmd_help(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Show help information."""
        lines = [
            f"=== {self.bbs.config.bbs.name} Help ===",
            "",
            "Commands:",
        ]

        # Group commands by access level
        for cmd, (_, access, help_text) in sorted(self._commands.items()):
            if access == "admin" and not session.get("is_admin"):
                continue
            if len(cmd) <= 2:  # Only show short commands
                lines.append(f"  {cmd}: {help_text}")

        lines.append("")
        lines.append("Send ? <cmd> for detailed help")

        return "\n".join(lines)

    def cmd_info(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Show BBS information."""
        uptime_secs = int(self.bbs.uptime)
        uptime_str = f"{uptime_secs // 3600}h {(uptime_secs % 3600) // 60}m"

        return (
            f"=== {self.bbs.config.bbs.name} ===\n"
            f"Callsign: {self.bbs.config.bbs.callsign}\n"
            f"Mode: {self.bbs.config.operating_mode.mode}\n"
            f"Uptime: {uptime_str}\n"
            f"Users: {self.bbs.db.count_users()}\n"
            f"Messages: {self.bbs.db.count_messages()}"
        )

    def cmd_who(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Show online users."""
        active = []
        for node_id, sess in self.bbs._sessions.items():
            if sess.get("username"):
                active.append(sess["username"])

        if not active:
            return "No users currently logged in."

        return f"Online: {', '.join(active)}"

    def cmd_register(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Register new user."""
        if not self.bbs.config.features.registration_enabled:
            return "Registration is currently disabled."

        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: REG <username> <password>"

        username, password = parts

        # Validate username
        if len(username) < 3 or len(username) > 16:
            return "Username must be 3-16 characters."

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return "Username can only contain letters, numbers, underscore."

        # Validate password
        if len(password) < 6:
            return "Password must be at least 6 characters."

        # Check if username exists
        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)

        if user_repo.get_user_by_username(username):
            return "Username already taken."

        # Create user
        try:
            salt = self.bbs.crypto.generate_salt()
            password_hash = self.bbs.crypto.hash_password(password).encode()
            encryption_key = self.bbs.crypto.derive_key(password, salt)

            # Encrypt user key with master key for recovery
            recovery_key = self.bbs.master_key.encrypt_user_key(encryption_key)

            user = user_repo.create_user(
                username=username,
                password_hash=password_hash,
                salt=salt,
                encryption_key=self.bbs.master_key.encrypt_user_key(encryption_key),
                recovery_key_enc=recovery_key
            )

            # Auto-login
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin

            # Associate current node
            from ..db.users import NodeRepository, UserNodeRepository
            node_repo = NodeRepository(self.bbs.db)
            user_node_repo = UserNodeRepository(self.bbs.db)

            node = node_repo.get_or_create_node(sender)
            user_node_repo.associate_node(user.id, node.id, is_primary=True)

            self.bbs.stats.users_registered += 1

            return f"Welcome {username}! You are now registered and logged in."

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return "Registration failed. Please try again."

    def cmd_login(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Login user."""
        if session.get("user_id"):
            return f"Already logged in as {session['username']}. LOGOUT first."

        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: LOGIN <username> <password>"

        username, password = parts

        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)

        user = user_repo.get_user_by_username(username)
        if not user:
            return "Invalid username or password."

        if user.is_banned:
            return f"Account banned: {user.ban_reason or 'No reason given'}"

        # Verify password
        try:
            if not self.bbs.crypto.verify_password(password, user.password_hash.decode()):
                return "Invalid username or password."
        except Exception:
            return "Invalid username or password."

        # Update session
        session["user_id"] = user.id
        session["username"] = user.username
        session["is_admin"] = user.is_admin

        # Update last seen
        user_repo.update_last_seen(user.id)

        # Check for mail
        from ..db.messages import MessageRepository
        msg_repo = MessageRepository(self.bbs.db)
        unread = msg_repo.count_unread_mail(user.id)

        mail_notice = f" You have {unread} unread message(s)." if unread else ""

        return f"Welcome back, {username}!{mail_notice}"

    def cmd_logout(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Logout user."""
        username = session.get("username", "user")
        session["user_id"] = None
        session["username"] = None
        session["is_admin"] = False
        session["current_board"] = None

        return f"Goodbye, {username}!"

    def cmd_passwd(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Change password."""
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: PASSWD <old_password> <new_password>"

        old_pass, new_pass = parts

        if len(new_pass) < 6:
            return "New password must be at least 6 characters."

        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)

        user = user_repo.get_user_by_id(session["user_id"])
        if not user:
            return "Error: User not found."

        # Verify old password
        if not self.bbs.crypto.verify_password(old_pass, user.password_hash.decode()):
            return "Current password is incorrect."

        # Generate new credentials
        salt = self.bbs.crypto.generate_salt()
        password_hash = self.bbs.crypto.hash_password(new_pass).encode()
        encryption_key = self.bbs.crypto.derive_key(new_pass, salt)

        user_repo.update_password(
            user.id,
            password_hash,
            salt,
            self.bbs.master_key.encrypt_user_key(encryption_key)
        )

        return "Password changed successfully."

    def cmd_addnode(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Add current node to user's account."""
        from ..db.users import NodeRepository, UserNodeRepository

        node_repo = NodeRepository(self.bbs.db)
        user_node_repo = UserNodeRepository(self.bbs.db)

        node = node_repo.get_or_create_node(sender)
        user_node_repo.associate_node(session["user_id"], node.id)

        return f"Node {sender} added to your account."

    def cmd_rmnode(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Remove a node from user's account."""
        if not args:
            return "Usage: RMNODE <node_id>"

        from ..db.users import UserNodeRepository
        user_node_repo = UserNodeRepository(self.bbs.db)

        if user_node_repo.remove_node(session["user_id"], args):
            return f"Node {args} removed from your account."
        return "Node not found or not associated with your account."

    def cmd_nodes(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List user's associated nodes."""
        from ..db.users import UserNodeRepository
        user_node_repo = UserNodeRepository(self.bbs.db)

        nodes = user_node_repo.get_user_nodes(session["user_id"])
        if not nodes:
            return "No nodes associated with your account."

        return "Your nodes: " + ", ".join(nodes)

    # Stub implementations for remaining commands
    def cmd_send_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Send mail."""
        # TODO: Implement
        return "Mail system not yet implemented."

    def cmd_check_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Check mail count."""
        from ..db.messages import MessageRepository
        msg_repo = MessageRepository(self.bbs.db)
        unread = msg_repo.count_unread_mail(session["user_id"])
        return f"You have {unread} unread message(s)."

    def cmd_read_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Read mail."""
        # TODO: Implement
        return "Mail system not yet implemented."

    def cmd_delete_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Delete mail."""
        # TODO: Implement
        return "Mail system not yet implemented."

    def cmd_boards(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List or enter boards."""
        # TODO: Implement
        return "Board system not yet implemented."

    def cmd_list(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List posts."""
        # TODO: Implement
        return "Board system not yet implemented."

    def cmd_read(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Read post."""
        # TODO: Implement
        return "Board system not yet implemented."

    def cmd_post(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Post to board."""
        # TODO: Implement
        return "Board system not yet implemented."

    def cmd_quit_board(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Quit current board."""
        session["current_board"] = None
        return "Exited board."

    def cmd_ban(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Ban user (admin only)."""
        parts = args.split(maxsplit=1)
        if not parts:
            return "Usage: BAN <username> [reason]"

        username = parts[0]
        reason = parts[1] if len(parts) > 1 else "No reason given"

        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)

        if user_repo.ban_user(username, reason, session["username"]):
            return f"User {username} has been banned."
        return "User not found."

    def cmd_unban(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Unban user (admin only)."""
        if not args:
            return "Usage: UNBAN <username>"

        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)

        if user_repo.unban_user(args):
            return f"User {args} has been unbanned."
        return "User not found."

    def cmd_sync(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Force sync (admin only)."""
        # TODO: Implement
        return "Sync not yet implemented."

    def cmd_announce(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Broadcast announcement (admin only)."""
        if not args:
            return "Usage: ANNOUNCE <message>"
        # TODO: Implement
        return "Announcement system not yet implemented."

    def cmd_destruct(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Delete all user data."""
        if args != "CONFIRM":
            return "WARNING: This will delete ALL your data. Type DESTRUCT CONFIRM to proceed."

        from ..db.users import UserRepository
        from ..db.messages import MessageRepository

        user_repo = UserRepository(self.bbs.db)
        msg_repo = MessageRepository(self.bbs.db)

        user_id = session["user_id"]

        # Delete all messages
        deleted = msg_repo.delete_user_messages(user_id)

        # Delete user
        user_repo.delete_user(user_id)

        # Clear session
        session["user_id"] = None
        session["username"] = None
        session["is_admin"] = False

        return f"All your data has been deleted ({deleted} messages removed)."
