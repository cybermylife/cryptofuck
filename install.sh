#!/bin/bash

set -e

echo "Installing Cryptofuck on Arch Linux..."

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="cryptofuck"
TEMP_DIR="/tmp/cryptofuck_install"

echo "Downloading cryptofuck..."

mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

curl -sSL https://raw.githubusercontent.com/CyberMyLife/cryptofuck/main/cryptofuck.py -o cryptofuck.py

echo "Installing cryptofuck to $INSTALL_DIR..."

cp cryptofuck.py "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

rm -rf "$TEMP_DIR"

echo "Cryptofuck installed successfully!"
echo "You can now use 'cryptofuck' from anywhere in your system"
echo ""
echo "Usage examples:"
echo "  cryptofuck 'hello world' -t bin"
echo "  cryptofuck 'cryptanalys' -t b64"
echo "  cryptofuck -l"
echo ""
echo "Installation complete! "
