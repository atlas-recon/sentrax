#!/usr/bin/env bash
# SentraX Desktop — Linux installer (Athena OS / Kali / Parrot / Arch / Debian / Fedora …)
# Installs the SentraX penetration-testing GUI as a native desktop app.
# Usage:  chmod +x install-sentrax.sh && ./install-sentrax.sh
set -euo pipefail

ELECTRON_VERSION="33.2.1"
APP_URL="${SENTRAX_URL:-https://sentrax.lovable.app/}"
PREFIX="$HOME/.local/share/sentrax"
BIN="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"

cyan()  { printf "\033[36m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
die()   { printf "\033[31mERROR: %s\033[0m\n" "$1" >&2; exit 1; }

cyan "== SentraX Desktop installer =="

# ---- Linux-only guard -------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "SentraX Desktop installs on Linux only (Athena OS and other distros)."

DISTRO="unknown"
if [ -r /etc/os-release ]; then . /etc/os-release; DISTRO="${PRETTY_NAME:-$ID}"; fi
green "Detected distribution: $DISTRO"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) EARCH="x64" ;;
  aarch64|arm64) EARCH="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

for c in curl unzip; do command -v "$c" >/dev/null || die "'$c' is required. Install it and re-run."; done

# ---- Fetch Electron runtime -------------------------------------------------
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/electron-v${ELECTRON_VERSION}-linux-${EARCH}.zip"
cyan "Downloading runtime (~90 MB)…"
curl -fL --progress-bar "$URL" -o "$TMP/electron.zip" || die "Download failed."

rm -rf "$PREFIX"; mkdir -p "$PREFIX/runtime" "$PREFIX/app" "$BIN" "$DESKTOP_DIR"
unzip -q "$TMP/electron.zip" -d "$PREFIX/runtime"
chmod +x "$PREFIX/runtime/electron"
[ -f "$PREFIX/runtime/chrome-sandbox" ] && chmod 4755 "$PREFIX/runtime/chrome-sandbox" 2>/dev/null || true

# ---- App bundle -------------------------------------------------------------
cat > "$PREFIX/app/package.json" <<'JSON'
{ "name": "sentrax-desktop", "version": "1.0.0", "main": "main.cjs" }
JSON

cat > "$PREFIX/app/main.cjs" <<EOF
const { app, BrowserWindow, shell, Menu } = require("electron");
const APP_URL = process.env.SENTRAX_URL || "${APP_URL}";
const UA_SUFFIX = " SentraX-Desktop/1.0 (Linux; pentest-gui)";
let win = null;
function createWindow() {
  win = new BrowserWindow({
    width: 1440, height: 900, minWidth: 1024, minHeight: 640,
    backgroundColor: "#0a0f16", autoHideMenuBar: true,
    title: "SentraX — Security Assessment Console",
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  const ua = win.webContents.getUserAgent() + UA_SUFFIX;
  win.webContents.setUserAgent(ua);
  win.loadURL(APP_URL, { userAgent: ua });
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  win.on("closed", () => { win = null; });
}
Menu.setApplicationMenu(Menu.buildFromTemplate([{ label: "SentraX", submenu: [
  { label: "Reload", accelerator: "CmdOrCtrl+R", click: () => win && win.reload() },
  { label: "Toggle DevTools", accelerator: "CmdOrCtrl+Shift+I", click: () => win && win.webContents.toggleDevTools() },
  { type: "separator" }, { role: "quit" },
]}]));
app.whenReady().then(() => { createWindow(); app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); }); });
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
EOF

curl -fsL "${APP_URL%/}/sentrax-logo.png" -o "$PREFIX/app/icon.png" || true

# ---- Launcher + desktop entry ----------------------------------------------
cat > "$BIN/sentrax" <<EOF
#!/usr/bin/env bash
exec "$PREFIX/runtime/electron" "$PREFIX/app" "\$@"
EOF
chmod +x "$BIN/sentrax"

cat > "$DESKTOP_DIR/sentrax.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SentraX
GenericName=Security Assessment Console
Comment=AI-powered penetration testing and vulnerability assessment GUI
Exec=$BIN/sentrax
Icon=$PREFIX/app/icon.png
Terminal=false
Categories=Security;Network;Development;
Keywords=security;pentest;owasp;vulnerability;scanner;
EOF

command -v update-desktop-database >/dev/null && update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true

green "SentraX Desktop installed."
echo "  Launch:      sentrax        (or find 'SentraX' in your app menu)"
echo "  Location:    $PREFIX"
echo "  Uninstall:   rm -rf '$PREFIX' '$BIN/sentrax' '$DESKTOP_DIR/sentrax.desktop'"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "  NOTE: add $BIN to your PATH";; esac
