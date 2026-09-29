#!/data/data/com.termux/files/usr/bin/sh
# Ramin VPN - one-line installer for Termux.
# Re-running it updates the program; your settings (Jason/ folder) are kept.
set -e

REPO="raminsepehr96/Ramin_VPN"     # <-- change this
BRANCH="main"
DIR="$HOME/Ramin_VPN"

echo "[1/3] Installing required packages..."
pkg update -y >/dev/null 2>&1 || true
pkg install -y python curl tar >/dev/null

echo "[2/3] Downloading Ramin VPN..."
mkdir -p "$DIR"
curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
  | tar xz --strip-components=1 -C "$DIR"

echo "[3/3] Creating the 'Ramin' command..."
for NAME in Ramin ramin; do
cat > "$PREFIX/bin/$NAME" <<LAUNCH
#!$PREFIX/bin/sh
# RAMIN_VPN_LAUNCHER
SCRIPT="$DIR/Ramin_VPN.py"
cd "\$(dirname "\$SCRIPT")" || exit 1
exec python "\$SCRIPT" "\$@"
LAUNCH
chmod +x "$PREFIX/bin/$NAME"
done

echo
echo "Done. Type:  Ramin"
echo "(the first run installs sing-box 1.14.2 automatically)"