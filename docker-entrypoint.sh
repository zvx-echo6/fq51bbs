#!/bin/bash
# FQ51BBS Docker Entrypoint
# Handles first-run setup and starts the BBS

set -e

CONFIG_FILE="/data/config.toml"

# First run - no config exists yet
if [ ! -f "$CONFIG_FILE" ]; then
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│              FQ51BBS - First Time Setup                 │"
    echo "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo "No configuration found. Starting setup wizard..."
    echo ""

    # Run the config wizard to create initial config
    exec python -m fq51bbs --config "$CONFIG_FILE" config --wizard
fi

# Config exists - start the BBS
exec python -m fq51bbs --config "$CONFIG_FILE" "$@"
