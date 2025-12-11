#!/bin/bash
# FQ51BBS Docker Entrypoint
# Handles first-run config setup and starts the BBS

set -e

CONFIG_FILE="/app/config.toml"
EXAMPLE_CONFIG="/app/config.example.toml"

# Check if config.toml exists and is a regular file
if [ ! -f "$CONFIG_FILE" ]; then
    # Check if it's a directory (Docker created it due to missing bind mount source)
    if [ -d "$CONFIG_FILE" ]; then
        echo "ERROR: $CONFIG_FILE is a directory, not a file."
        echo "This happens when the config file doesn't exist before starting Docker."
        echo ""
        echo "To fix this:"
        echo "  1. Stop the container: docker-compose down"
        echo "  2. Remove the directory: rm -rf ./config.toml"
        echo "  3. Create the config file: cp config.example.toml config.toml"
        echo "  4. Edit config.toml with your settings (especially admin_password!)"
        echo "  5. Restart: docker-compose up -d"
        exit 1
    fi

    # Config doesn't exist - provide helpful error
    echo "ERROR: Configuration file not found at $CONFIG_FILE"
    echo ""
    echo "To set up FQ51BBS:"
    echo "  1. Copy the example config: cp config.example.toml config.toml"
    echo "  2. Edit config.toml with your settings:"
    echo "     - Change admin_password (REQUIRED)"
    echo "     - Configure meshtastic connection (serial/tcp)"
    echo "     - Set your BBS name and callsign"
    echo "  3. Restart the container: docker-compose up -d"
    exit 1
fi

# Check if admin password is still the default
if grep -q 'admin_password = "CHANGE_ME"' "$CONFIG_FILE" 2>/dev/null; then
    echo "WARNING: admin_password is still set to 'CHANGE_ME'"
    echo "Please edit config.toml and set a secure admin password!"
    echo ""
fi

# Execute the main application
exec python -m fq51bbs "$@"
