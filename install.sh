#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/BitsLabSec/nanobot-security-guide.git"
SKILL_DIR_NAME="nanobot-security-guard"

echo "========================================================="
echo "🛡️  Nanobot Security Guard - One-Click Installer 🛡️"
echo "========================================================="

# Discover the correct skills directory
if [ -d "nanobot/skills" ]; then
    TARGET_SKILLS_DIR="$(pwd)/nanobot/skills"
    echo "[*] Found local nanobot workspace: $TARGET_SKILLS_DIR"
elif [ -d "$HOME/.nanobot/skills" ]; then
    TARGET_SKILLS_DIR="$HOME/.nanobot/skills"
    echo "[*] Found global nanobot config directory: $TARGET_SKILLS_DIR"
else
    # Create the directory if neither exists
    TARGET_SKILLS_DIR="$HOME/.nanobot/skills"
    mkdir -p "$TARGET_SKILLS_DIR"
    echo "[*] Creating default skills directory at: $TARGET_SKILLS_DIR"
fi

DEST_DIR="$TARGET_SKILLS_DIR/$SKILL_DIR_NAME"

echo "[*] Fetching Security Guard from GitHub repository..."
if [ -d "$DEST_DIR/.git" ]; then
    echo "[*] Existing installation found. Updating from repository..."
    cd "$DEST_DIR"
    git pull origin main --quiet
    cd - > /dev/null
else
    # Remove if it exists as an empty/non-git folder to avoid clone failure
    rm -rf "$DEST_DIR"
    git clone --quiet "$REPO_URL" "$DEST_DIR"
fi

echo "[*] Setting execution permissions for audit scripts..."
chmod +x "$DEST_DIR/scripts/"*.sh 2>/dev/null || true
chmod +x "$DEST_DIR/scripts/"*.py 2>/dev/null || true

echo "========================================================="
echo "✅ Installation Complete! The 'nanobot-security-guard' skill is now active."
echo "========================================================="
echo "To manually trigger a security audit right now, run:"
echo "  python3 $DEST_DIR/scripts/audit_system.py"
echo ""
echo "Or send a message to your Nanobot:"
echo "  \"Please read your newly installed security guard SKILL.md and run a host inspection.\""
echo "========================================================="
