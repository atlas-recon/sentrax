const { app, BrowserWindow, shell, Menu } = require("electron");
const path = require("path");

// SentraX Desktop — Linux penetration-testing GUI.
// Loads the SentraX app with a desktop user-agent so the web app unlocks
// all tools and hides every payment / upgrade surface.
const APP_URL = process.env.SENTRAX_URL || "https://sentrax.lovable.app/";
const UA_SUFFIX = " SentraX-Desktop/1.0 (Linux; pentest-gui)";

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 640,
    backgroundColor: "#0a0f16",
    autoHideMenuBar: true,
    icon: path.join(__dirname, "icon.png"),
    title: "SentraX — Security Assessment Console",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const ua = win.webContents.getUserAgent() + UA_SUFFIX;
  win.webContents.setUserAgent(ua);
  win.loadURL(APP_URL, { userAgent: ua });

  // Open external links in the system browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  win.on("closed", () => {
    win = null;
  });
}

Menu.setApplicationMenu(
  Menu.buildFromTemplate([
    {
      label: "SentraX",
      submenu: [
        { label: "Reload", accelerator: "CmdOrCtrl+R", click: () => win && win.reload() },
        { label: "Toggle DevTools", accelerator: "CmdOrCtrl+Shift+I", click: () => win && win.webContents.toggleDevTools() },
        { type: "separator" },
        { role: "quit" },
      ],
    },
  ]),
);

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
