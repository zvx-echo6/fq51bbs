#!/bin/bash
# FQ51BBS Docker Entrypoint
# Handles first-run setup and starts the BBS

set -e

export FQ51BBS_CONFIG="/data/config.toml"

# First run - no config exists yet
if [ ! -f "$FQ51BBS_CONFIG" ]; then
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│              FQ51BBS - First Time Setup                 │"
    echo "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo "No configuration found. Starting setup wizard..."
    echo ""

    # Run the dialog-based config wizard
    exec fq51-config --wizard
fi

# Config exists - start the BBS
exec python -m fq51bbs --config "$FQ51BBS_CONFIG" "$@"
