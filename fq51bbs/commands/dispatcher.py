"""
FQ51BBS Command Dispatcher

Routes incoming messages to appropriate command handlers.
"""

import logging
import re
import time
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
        # Help
        self.register("?", self.cmd_help, "always", "Show help")
        self.register("HELP", self.cmd_help, "always", "Show help")

        # Info
        self.register("INFO", self.cmd_info, "always", "BBS information")

        # Authentication
        self.register("REGISTER", self.cmd_register, "always", "Register: REGISTER <user> <pass>")
        self.register("LOGIN", self.cmd_login, "always", "Login: LOGIN <user> <pass>")
        self.register("LOGOUT", self.cmd_logout, "authenticated", "Log out")
        self.register("PASSWD", self.cmd_passwd, "authenticated", "Change password: PASSWD <old> <new>")

        # Node management
        self.register("ADDNODE", self.cmd_addnode, "authenticated", "Add node: ADDNODE <node_id>")
        self.register("RMVNODE", self.cmd_rmvnode, "authenticated", "Remove node: RMVNODE <node_id>")
        self.register("NODES", self.cmd_nodes, "authenticated", "List your nodes")

        # Mail commands
        self.register("SEND", self.cmd_send_mail, "authenticated", "Send mail: SEND <to[@bbs]> <msg>")
        self.register("MAIL", self.cmd_check_mail, "authenticated", "Check mail count")
        self.register("READ", self.cmd_read_mail, "authenticated", "Read mail: READ [n]")
        self.register("DELETE", self.cmd_delete_mail, "authenticated", "Delete mail: DELETE <n>")
        self.register("REPLY", self.cmd_reply, "authenticated", "Reply to mail: REPLY <n> <msg>")
        self.register("FORWARD", self.cmd_forward, "authenticated", "Forward mail: FORWARD <n> <to[@bbs]>")

        # Board commands
        self.register("BOARD", self.cmd_boards, "always", "List/enter board: BOARD [name]")
        self.register("LIST", self.cmd_list, "always", "List posts: LIST [count]")
        self.register("POST", self.cmd_post, "authenticated", "Post: POST <subj> <body>")
        self.register("QUIT", self.cmd_quit_board, "always", "Quit board")

        # Peer/federation commands
        self.register("PEERS", self.cmd_peers, "always", "List connected BBS peers")

        # Admin commands
        self.register("BAN", self.cmd_ban, "admin", "Ban user: BAN <user> [reason]")
        self.register("UNBAN", self.cmd_unban, "admin", "Unban user: UNBAN <user>")
        self.register("MKBOARD", self.cmd_mkboard, "admin", "Create board: MKBOARD <name> [desc]")
        self.register("RMBOARD", self.cmd_rmboard, "admin", "Delete board: RMBOARD <name>")
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
            return "Unknown cmd. Send ? for help."

        handler, access, _ = self._commands[cmd]

        # Check access
        session = self._get_session(sender)

        if access == "authenticated" and not session.get("user_id"):
            return "Please login first. REGISTER <user> <pass> or LOGIN <user> <pass>"

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
        """Get or create session for sender, checking for timeout."""
        now = time.time()
        timeout_secs = self.bbs.config.bbs.session_timeout_minutes * 60

        if sender not in self.bbs._sessions:
            self.bbs._sessions[sender] = {
                "user_id": None,
                "username": None,
                "is_admin": False,
                "current_board": None,
                "last_activity": now,
            }
        else:
            session = self.bbs._sessions[sender]
            # Check for session timeout
            if session.get("user_id") and timeout_secs > 0:
                if now - session.get("last_activity", 0) > timeout_secs:
                    # Session expired - log out user
                    logger.info(f"Session timeout for {session.get('username')}")
                    session["user_id"] = None
                    session["username"] = None
                    session["is_admin"] = False
                    session["current_board"] = None

            # Update last activity
            session["last_activity"] = now

        return self.bbs._sessions[sender]

    def _check_feature(self, cmd: str) -> bool:
        """Check if the feature for this command is enabled."""
        mail_commands = {"SEND", "MAIL", "READ", "DELETE", "REPLY", "FORWARD"}
        board_commands = {"BOARD", "LIST", "POST", "QUIT"}

        if cmd in mail_commands and not self.bbs.config.features.mail_enabled:
            return False

        if cmd in board_commands and not self.bbs.config.features.boards_enabled:
            return False

        return True

    # === Command Handlers ===

    def cmd_help(self, sender: str, args: str, session: dict, channel: int):
        """Show help information - sends all help in multiple messages (<150 chars each)."""
        callsign = self.bbs.config.bbs.callsign

        # Check for admin help
        if args.strip().lower() == "admin":
            if not session.get("is_admin"):
                return "Admin access required."
            return (
                f"[{callsign}] Admin Commands\n"
                "BAN user [reason] - Ban user\n"
                "UNBAN user - Unban user\n"
                "MKBOARD name [desc] - Create board\n"
                "RMBOARD name - Delete board\n"
                "ANNOUNCE msg - Broadcast"
            )

        # Build help messages - each under 150 chars
        help_msgs = [
            (
                f"[{callsign}] Commands 1/4\n"
                "REGISTER user pass - New account\n"
                "LOGIN user pass - Login\n"
                "LOGOUT - Log out\n"
                "INFO - BBS info"
            ),
            (
                f"[{callsign}] Mail 2/4\n"
                "SEND user[@bbs] msg - Send mail\n"
                "MAIL - Inbox, READ [n] - Read\n"
                "REPLY [n] msg - Reply\n"
                "FORWARD [n] user - Fwd"
            ),
            (
                f"[{callsign}] Boards 3/4\n"
                "BOARD - List boards\n"
                "BOARD name - Enter board\n"
                "LIST - Posts, READ n - Read\n"
                "POST subj msg - New post"
            ),
            (
                f"[{callsign}] Other 4/4\n"
                "PEERS - BBS network\n"
                "ADDNODE id - Add device\n"
                "RMVNODE id - Remove device\n"
                "DESTRUCT - Delete account"
            ),
        ]

        # Return all messages as a list
        return help_msgs

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

        # Verify node association (2FA - must login from registered node)
        from ..db.users import NodeRepository, UserNodeRepository
        node_repo = NodeRepository(self.bbs.db)
        user_node_repo = UserNodeRepository(self.bbs.db)

        # Get node DB record for sender
        node = node_repo.get_node_by_id(sender)
        if node:
            # Check if this node is associated with the user
            if not user_node_repo.is_node_associated(user.id, node.id):
                return "Node not authorized for this account. Contact admin."
        else:
            # Node not in database at all - definitely not associated
            return "Node not authorized for this account. Contact admin."

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
        """Add a node to user's account: ADDNODE <node_id>"""
        if not args:
            return "Usage: ADDNODE <node_id> (e.g., ADDNODE !abcd1234)"

        node_id = args.strip()

        # Validate node ID format (should start with !)
        if not node_id.startswith("!"):
            return "Invalid node ID. Should start with ! (e.g., !abcd1234)"

        from ..db.users import NodeRepository, UserNodeRepository

        node_repo = NodeRepository(self.bbs.db)
        user_node_repo = UserNodeRepository(self.bbs.db)

        # Check if already associated
        existing_nodes = user_node_repo.get_user_nodes(session["user_id"])
        if node_id in existing_nodes:
            return f"Node {node_id} is already associated with your account."

        node = node_repo.get_or_create_node(node_id)
        user_node_repo.associate_node(session["user_id"], node.id)

        return f"Node {node_id} added. You can now login from that device."

    def cmd_rmvnode(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Remove a node from user's account: RMVNODE <node_id>"""
        if not args:
            return "Usage: RMVNODE <node_id>"

        node_to_remove = args.strip()

        from ..db.users import UserNodeRepository
        user_node_repo = UserNodeRepository(self.bbs.db)

        # Get current nodes
        nodes = user_node_repo.get_user_nodes(session["user_id"])

        # Don't allow removing last node
        if len(nodes) <= 1:
            return "Cannot remove your only node. Add another first."

        # Don't allow removing current node (would lock self out)
        if node_to_remove == sender:
            return "Cannot remove the node you're currently using."

        if user_node_repo.remove_node(session["user_id"], node_to_remove):
            return f"Node {node_to_remove} removed."
        return "Node not found or not associated with your account."

    def cmd_nodes(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List user's associated nodes."""
        from ..db.users import UserNodeRepository
        user_node_repo = UserNodeRepository(self.bbs.db)

        nodes = user_node_repo.get_user_nodes(session["user_id"])
        if not nodes:
            return "No nodes associated with your account."

        # Mark current node
        node_list = []
        for n in nodes:
            if n == sender:
                node_list.append(f"{n} (current)")
            else:
                node_list.append(n)

        return "Your nodes:\n" + "\n".join(node_list)

    # === Mail Commands ===

    def cmd_send_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Send mail: SEND <to[@bbs]> <message>"""
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: SEND <user[@bbs]> <message>"

        recipient, body = parts

        if len(body) > 1000:
            return "Message too long (max 1000 chars)."

        # Check for remote addressing (user@bbs)
        if "@" in recipient:
            username, remote_bbs = recipient.split("@", 1)
            return self._send_remote_mail(session, sender, username, remote_bbs, body)

        # Local mail
        message, error = self.bbs.mail_service.compose_mail(
            sender_user_id=session["user_id"],
            sender_node_id=sender,
            recipient_username=recipient,
            body=body
        )

        if error:
            return error

        return f"Mail sent to {recipient}."

    def _send_remote_mail(self, session: dict, sender_node: str, recipient: str, remote_bbs: str, body: str) -> str:
        """Send mail to a user on a remote BBS."""
        # Find the peer BBS
        if not self.bbs.sync_manager:
            return "Remote mail not available (sync disabled)."

        # Pre-flight check: max 450 chars for remote mail
        if len(body) > 450:
            return f"Message too long for remote delivery (max 450 chars, yours: {len(body)})"

        # Check if we know the destination or can relay
        peer = self.bbs.sync_manager.get_peer_by_name(remote_bbs)
        if not peer and not self.bbs.sync_manager.list_peers():
            return f"No route to {remote_bbs}. No peers configured."

        # Get sender username
        from ..db.users import UserRepository
        user_repo = UserRepository(self.bbs.db)
        sender_user = user_repo.get_user_by_id(session["user_id"])
        if not sender_user:
            return "Error: sender not found."

        # Queue remote mail for sync
        from ..db.messages import MessageRepository
        msg_repo = MessageRepository(self.bbs.db)

        message = msg_repo.create_remote_mail(
            sender_username=sender_user.username,
            sender_bbs=self.bbs.config.bbs.callsign,
            recipient_username=recipient,
            recipient_bbs=remote_bbs.upper(),
            body=body,
            origin_bbs=self.bbs.config.bbs.callsign
        )

        if message:
            # Trigger immediate send via sync manager
            import asyncio
            asyncio.create_task(
                self.bbs.sync_manager.send_remote_mail(
                    sender_username=sender_user.username,
                    sender_bbs=self.bbs.config.bbs.callsign,
                    recipient_username=recipient,
                    recipient_bbs=remote_bbs.upper(),
                    body=body,
                    mail_uuid=message.uuid
                )
            )
            return f"Mail queued for {recipient}@{remote_bbs}."
        return "Failed to queue remote mail."

    def cmd_check_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Check mail count and list recent."""
        summary = self.bbs.mail_service.get_inbox_summary(session["user_id"])
        messages = self.bbs.mail_service.list_mail(session["user_id"], limit=5)

        if summary["total"] == 0:
            return "Your inbox is empty."

        lines = [f"Mail: {summary['unread']} unread / {summary['total']} total"]

        if messages:
            lines.append("")
            for msg in messages:
                marker = "*" if msg["new"] else " "
                lines.append(f"{marker}{msg['id']:3d}. {msg['date']} {msg['from'][:12]}")

        lines.append("")
        lines.append("Use READ <n> to read, DELETE <n> to delete")

        return "\n".join(lines)

    def cmd_read_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Read mail: READ <n> or READ to list"""
        if not args:
            # List mail
            messages = self.bbs.mail_service.list_mail(session["user_id"], limit=10)

            if not messages:
                return "Your inbox is empty."

            lines = ["=== Inbox ===", ""]
            for msg in messages:
                marker = "*" if msg["new"] else " "
                lines.append(f"{marker}{msg['id']:3d}. {msg['date']} {msg['from'][:12]}")

            return "\n".join(lines)

        try:
            message_id = int(args)
        except ValueError:
            return "Usage: READ <message_id>"

        mail, error = self.bbs.mail_service.read_mail(session["user_id"], message_id)
        if error:
            return error

        # Store last read message for REPLY
        session["last_mail_id"] = mail["id"]
        session["last_mail_from"] = mail["from"]
        session["last_mail_from_bbs"] = mail.get("from_bbs")  # For remote mail

        lines = [
            f"=== Mail #{mail['id']} ===",
            f"From: {mail['from']}",
            f"Date: {mail['date']}",
            f"Subject: {mail['subject']}",
            "",
            mail['body'],
            "",
            "REPLY <msg> to reply | FORWARD <user[@bbs]> to forward"
        ]

        return "\n".join(lines)

    def cmd_reply(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Reply to mail: REPLY [n] <message> or REPLY <message> for last read"""
        if not args:
            return "Usage: REPLY [msg_id] <message>"

        # Check if first arg is a message ID
        parts = args.split(maxsplit=1)
        message_id = None
        reply_body = args

        if len(parts) >= 2:
            try:
                message_id = int(parts[0])
                reply_body = parts[1]
            except ValueError:
                # First part isn't a number, use last read message
                pass

        # Get original message
        if message_id:
            mail, error = self.bbs.mail_service.read_mail(session["user_id"], message_id)
            if error:
                return error
            reply_to = mail["from"]
            reply_to_bbs = mail.get("from_bbs")
        elif session.get("last_mail_from"):
            reply_to = session["last_mail_from"]
            reply_to_bbs = session.get("last_mail_from_bbs")
        else:
            return "No message to reply to. Use READ <n> first or REPLY <n> <msg>"

        # Build recipient address
        if reply_to_bbs and reply_to_bbs != self.bbs.config.bbs.callsign:
            recipient = f"{reply_to}@{reply_to_bbs}"
        else:
            recipient = reply_to

        # Send reply
        return self.cmd_send_mail(sender, f"{recipient} {reply_body}", session, channel)

    def cmd_forward(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Forward mail: FORWARD <n> <to[@bbs]> or FORWARD <to[@bbs]> for last read"""
        if not args:
            return "Usage: FORWARD [msg_id] <user[@bbs]>"

        parts = args.split(maxsplit=1)
        message_id = None
        forward_to = args

        # Check if first arg is a message ID
        if len(parts) >= 2:
            try:
                message_id = int(parts[0])
                forward_to = parts[1]
            except ValueError:
                pass

        # Get original message
        if message_id:
            mail, error = self.bbs.mail_service.read_mail(session["user_id"], message_id)
            if error:
                return error
        elif session.get("last_mail_id"):
            mail, error = self.bbs.mail_service.read_mail(session["user_id"], session["last_mail_id"])
            if error:
                return error
        else:
            return "No message to forward. Use READ <n> first or FORWARD <n> <user>"

        # Build forwarded message body
        fwd_body = f"[FWD from {mail['from']}]\n{mail['body']}"

        # Send forwarded message
        return self.cmd_send_mail(sender, f"{forward_to} {fwd_body}", session, channel)

    def cmd_delete_mail(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Delete mail: DELETE <n>"""
        if not args:
            return "Usage: DELETE <message_id>"

        try:
            message_id = int(args)
        except ValueError:
            return "Usage: DELETE <message_id>"

        success, error = self.bbs.mail_service.delete_mail(session["user_id"], message_id)
        if error:
            return error

        return f"Message #{message_id} deleted."

    # === Peer/Federation Commands ===

    def cmd_peers(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List connected BBS peers for remote mail."""
        if not self.bbs.sync_manager:
            return "Sync/federation not enabled."

        peers = self.bbs.sync_manager.list_peers()
        if not peers:
            return "No BBS peers configured."

        lines = ["=== BBS Peers ===", ""]
        for peer in peers:
            status = "online" if peer.get("online") else "offline"
            lines.append(f"  {peer['name']:<12} [{status}]")

        lines.append("")
        lines.append("Send mail: SEND user@PEERNAME message")

        return "\n".join(lines)

    # === Board Commands ===

    def cmd_boards(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List boards or enter: B [name]"""
        if not args:
            # List boards
            boards = self.bbs.board_service.list_boards(session.get("user_id"))

            if not boards:
                return "No boards available."

            lines = ["=== Boards ===", ""]
            for board in boards:
                unread_marker = f"({board['unread']} new)" if board['unread'] > 0 else ""
                restricted = "[R]" if board['restricted'] else ""
                lines.append(f"  {board['name']:<12} {board['posts']:3d} posts {unread_marker} {restricted}")

            lines.append("")
            lines.append("Use B <name> to enter a board")

            return "\n".join(lines)

        # Enter board
        board, error = self.bbs.board_service.enter_board(args, session.get("user_id"))
        if error:
            return error

        session["current_board"] = board.id

        # Get post count
        from ..db.messages import MessageRepository
        msg_repo = MessageRepository(self.bbs.db)
        post_count = msg_repo.count_board_messages(board.id)

        lines = [
            f"=== {board.name.upper()} ===",
            board.description or "",
            f"{post_count} posts",
            "",
            "L - list posts, R <n> - read, P <subj> <body> - post, Q - quit"
        ]

        return "\n".join(lines)

    def cmd_list(self, sender: str, args: str, session: dict, channel: int) -> str:
        """List posts: L [count]"""
        if not session.get("current_board"):
            return "Enter a board first with B <name>"

        limit = 10
        if args:
            try:
                limit = min(int(args), 50)
            except ValueError:
                pass

        posts = self.bbs.board_service.list_posts(
            session["current_board"],
            session.get("user_id"),
            limit=limit
        )

        if not posts:
            return "No posts on this board."

        lines = ["#    Date   Author       Subject", "-" * 40]
        for post in posts:
            lines.append(f"{post.number:3d}. {post.date} {post.author[:12]:<12} {post.subject}")

        return "\n".join(lines)

    def cmd_read(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Read post: R <n>"""
        if not session.get("current_board"):
            return "Enter a board first with B <name>"

        if not args:
            return "Usage: R <post_number>"

        try:
            post_number = int(args)
        except ValueError:
            return "Usage: R <post_number>"

        post, error = self.bbs.board_service.read_post(
            session["current_board"],
            post_number,
            session.get("user_id")
        )

        if error:
            return error

        lines = [
            f"=== {post.board}#{post.number} ===",
            f"Subject: {post.subject}",
            f"From: {post.author}",
            f"Date: {post.date}",
            "",
            post.body
        ]

        return "\n".join(lines)

    def cmd_post(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Post to board: P <subject> <body>"""
        if not session.get("current_board"):
            return "Enter a board first with B <name>"

        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: P <subject> <body>"

        subject, body = parts

        message, error = self.bbs.board_service.create_post(
            board_id=session["current_board"],
            user_id=session["user_id"],
            sender_node_id=sender,
            subject=subject,
            body=body
        )

        if error:
            return error

        return "Post created successfully."

    def cmd_quit_board(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Quit current board."""
        if not session.get("current_board"):
            return "Not currently in a board."

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

    def cmd_mkboard(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Create a new board (admin only)."""
        parts = args.split(maxsplit=1)
        if not parts:
            return "Usage: MKBOARD <name> [description]"

        name = parts[0].lower()
        description = parts[1] if len(parts) > 1 else ""

        # Validate name
        if len(name) < 2 or len(name) > 16:
            return "Board name must be 2-16 characters."

        if not re.match(r'^[a-z0-9_]+$', name):
            return "Board name: lowercase letters, numbers, underscore only."

        board, error = self.bbs.board_service.create_board(
            name=name,
            description=description,
            creator_id=session["user_id"]
        )

        if error:
            return error

        return f"Board '{name}' created."

    def cmd_rmboard(self, sender: str, args: str, session: dict, channel: int) -> str:
        """Delete a board (admin only)."""
        if not args:
            return "Usage: RMBOARD <name>"

        name = args.strip().lower()

        success, error = self.bbs.board_service.delete_board(name)
        if error:
            return error

        return f"Board '{name}' deleted."

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
