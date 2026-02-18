#!/bin/bash
# Install PacketPoet Wireshark plugin

echo "[*] PacketPoet Wireshark Plugin Installer"
echo ""

# Find Wireshark plugin directory
PLUGIN_DIR=""

# Try common locations
if [ -d "$HOME/.local/lib/wireshark/plugins" ]; then
    PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
elif [ -d "$HOME/.config/wireshark/plugins" ]; then
    PLUGIN_DIR="$HOME/.config/wireshark/plugins"
elif [ -d "/usr/lib/wireshark/plugins" ]; then
    PLUGIN_DIR="/usr/lib/wireshark/plugins"
elif [ -d "/usr/local/lib/wireshark/plugins" ]; then
    PLUGIN_DIR="/usr/local/lib/wireshark/plugins"
else
    # Create user plugin directory
    PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    mkdir -p "$PLUGIN_DIR"
fi

echo "[*] Found plugin directory: $PLUGIN_DIR"

# Copy plugin
cp packetpoet.lua "$PLUGIN_DIR/"
echo "[+] Plugin installed to $PLUGIN_DIR/packetpoet.lua"

# Set permissions
chmod 644 "$PLUGIN_DIR/packetpoet.lua"

# Check if PacketPoet exists
if [ ! -f "$HOME/packetpoet/main.py" ]; then
    echo "[!] Warning: PacketPoet not found at ~/packetpoet/main.py"
    echo "[*] Set PACKETPOET_PATH environment variable if different"
fi

echo ""
echo "[*] Installation complete!"
echo "[*] Restart Wireshark to see 'Tools → PacketPoet' menu"
echo ""
echo "Usage:"
echo "  1. Open Wireshark"
echo "  2. Capture or open a PCAP file"
echo "  3. Select packets (or use all)"
echo "  4. Tools → PacketPoet → Choose style"
