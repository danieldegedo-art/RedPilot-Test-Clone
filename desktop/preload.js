const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("redpilot", {
  startBackend: () => ipcRenderer.invoke("start-backend"),
  hasSession: () => ipcRenderer.invoke("has-session"),
  clearSession: () => ipcRenderer.invoke("clear-session"),
  openLoginBrowser: (url) => ipcRenderer.invoke("open-login-browser", url),
  confirmLogin: () => ipcRenderer.send("confirm-login"),
  runScan: (url) => ipcRenderer.invoke("run-scan", url),
  openProofBrowser: (url) => ipcRenderer.invoke("open-proof-browser", url),
  onScanProgress: (cb) => ipcRenderer.on("scan-progress", (_, data) => cb(data)),
  onScanDone: (cb) => ipcRenderer.on("scan-done", (_, data) => cb(data)),
  onScanProof: (cb) => ipcRenderer.on("scan-proof", (_, data) => cb(data)),
});
