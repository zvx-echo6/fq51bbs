#!/bin/bash
# FQ51BBS Docker Entrypoint
# Runs ttyd for web config access and the BBS

set -e

export FQ51BBS_CONFIG="/data/config.toml"
export TERM="${TERM:-xterm-256color}"

# First run - no config exists, create defaults
if [ ! -f "$FQ51BBS_CONFIG" ]; then
    echo "Creating default configuration..."
    fq51-config --wizard < /dev/null || true

    # If still no config (wizard was skipped), create minimal defaults
    if [ ! -f "$FQ51BBS_CONFIG" ]; then
        mkdir -p /data
        cat > "$FQ51BBS_CONFIG" << 'EOF'
[bbs]
name = "FQ51BBS"
callsign = "FQ51"
admin_password = "changeme"
motd = "Welcome to FQ51BBS!"

[database]
path = "/data/fq51bbs.db"
backup_path = "/data/backups"

[meshtastic]
connection_type = "tcp"
tcp_host = "localhost"
tcp_port = 4403

[features]
mail_enabled = true
boards_enabled = true
sync_enabled = true
registration_enabled = true

[operating_mode]
mode = "full"

[logging]
level = "INFO"
EOF
        echo "Default config created. Access web config at http://localhost:7681"
    fi
fi

# Start ttyd in background for web-based config access
echo "Starting web config interface on port 7681..."
ttyd -p 7681 -W fq51-config &

# Start the BBS
echo "Starting FQ51BBS..."
exec python -m fq51bbs --config "$FQ51BBS_CONFIG" "$@"
