const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");
const https = require("https");
const fs = require("fs");

const BACKEND_DIR = path.join(__dirname, "..", "backend");
const API_BASE = "http://127.0.0.1:8420";
const STATE_DIR = path.join(app.getPath("userData"), "redpilot");
const SESSION_STATE_PATH = path.join(STATE_DIR, "session_state.json");

let mainWindow = null;
let backendProcess = null;
let loginBrowser = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1050,
    height: 720,
    minWidth: 800,
    minHeight: 500,
    backgroundColor: "#0a0a0f",
    titleBarStyle: "hiddenInset",
    trafficLightPosition: { x: 12, y: 12 },
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile("index.html");
}

// --- Backend server management ---

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 3000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
  });
}

function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: parsed.hostname, port: parsed.port, path: parsed.pathname,
      method: "POST", timeout: 30000,
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
    }, (res) => {
      let buf = "";
      res.on("data", (chunk) => (buf += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: buf }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.write(data);
    req.end();
  });
}

async function isBackendRunning() {
  try {
    const r = await httpGet(`${API_BASE}/health`);
    return r.status === 200;
  } catch { return false; }
}

async function startBackend() {
  if (await isBackendRunning()) return { success: true, message: "Backend already running" };

  const python = process.platform === "win32" ? "python" : "python3";
  const env = { ...process.env, PYTHONPATH: BACKEND_DIR };

  return new Promise((resolve) => {
    backendProcess = spawn(python, ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8420"], {
      cwd: BACKEND_DIR, env, stdio: ["ignore", "pipe", "pipe"],
    });
    backendProcess.on("error", (err) => resolve({ success: false, message: err.message }));
    backendProcess.stderr.on("data", () => {});
    backendProcess.stdout.on("data", () => {});

    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      if (await isBackendRunning()) {
        clearInterval(poll);
        resolve({ success: true, message: "Backend started" });
      } else if (attempts > 40) {
        clearInterval(poll);
        resolve({ success: false, message: "Backend failed to start after 40s" });
      }
    }, 1000);
  });
}

function stopBackend() {
  if (backendProcess) {
    backendProcess.kill("SIGTERM");
    setTimeout(() => { if (backendProcess) backendProcess.kill("SIGKILL"); }, 5000);
    backendProcess = null;
  }
}

// --- Session state ---

function ensureStateDir() {
  if (!fs.existsSync(STATE_DIR)) fs.mkdirSync(STATE_DIR, { recursive: true });
}

function hasSession() {
  return fs.existsSync(SESSION_STATE_PATH);
}

function loadSessionCookies() {
  if (!hasSession()) return null;
  const state = JSON.parse(fs.readFileSync(SESSION_STATE_PATH, "utf-8"));
  return (state.cookies || []).map((c) => `${c.name}=${c.value}`).join("; ");
}

// --- Playwright: login flow ---

async function openLoginBrowser(url) {
  const { chromium } = require("playwright");
  const browser = await chromium.launch({ headless: false, args: ["--no-sandbox"] });
  loginBrowser = browser;
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });

  return new Promise((resolve) => {
    let resolved = false;

    const finish = async () => {
      if (resolved) return;
      resolved = true;
      try {
        await page.waitForTimeout(1500);
        const state = await context.storageState();
        ensureStateDir();
        fs.writeFileSync(SESSION_STATE_PATH, JSON.stringify(state, null, 2));
        await browser.close();
        loginBrowser = null;
        resolve({ success: true });
      } catch (err) {
        resolve({ success: false, error: err.message });
      }
    };

    ipcMain.once("confirm-login", finish);

    page.on("close", () => {
      if (!resolved) {
        resolved = true;
        resolve({ success: false, error: "Browser was closed before login was confirmed" });
      }
    });

    browser.on("disconnected", () => {
      if (!resolved) {
        resolved = true;
        resolve({ success: false, error: "Browser disconnected" });
      }
    });
  });
}

// --- Playwright: proof-of-bypass ---

async function openProofBrowser(url) {
  if (!hasSession()) return { success: false, error: "No session state" };
  const state = JSON.parse(fs.readFileSync(SESSION_STATE_PATH, "utf-8"));
  const { chromium } = require("playwright");
  const browser = await chromium.launch({ headless: false, args: ["--no-sandbox"] });
  const context = await browser.newContext({ storageState: state });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });

  return new Promise((resolve) => {
    browser.on("disconnected", () => resolve({ success: true }));
    page.on("close", async () => {
      try { await browser.close(); } catch {}
      resolve({ success: true });
    });
  });
}

// --- Scan: run engine via backend API ---

async function runScan(url, event) {
  const cookies = loadSessionCookies();
  const body = { url };
  if (cookies) body.session_cookies = cookies;

  const send = (channel, data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, data);
    }
  };

  try {
    send("scan-progress", { type: "status", text: "Sending scan request..." });
    const startResp = await httpPost(`${API_BASE}/api/v1/runs/scan`, body);
    if (startResp.status !== 202) {
      send("scan-progress", { type: "error", text: `Server returned ${startResp.status}: ${startResp.body}` });
      send("scan-done", { error: true });
      return;
    }

    const startData = JSON.parse(startResp.body);
    const runId = startData.run_id;
    send("scan-progress", { type: "chrome", text: `Engine started — Run ID: ${runId}` });

    const phases = [
      "Initializing recon pipeline...",
      "Mapping application surface...",
      "Probing authentication workflows...",
      "Analyzing payment flow endpoints...",
      "Testing entitlement boundaries...",
      "Running differential oracle probes...",
      "Fuzzing parameter surfaces...",
      "Scanning for hidden endpoints...",
      "Checking privilege escalation paths...",
      "Executing attack chain composition...",
      "Running cognitive analysis engine...",
    ];
    let phaseIdx = 0;
    let prevResultCount = 0;

    const poll = async () => {
      while (true) {
        await new Promise((r) => setTimeout(r, 2000));
        try {
          const resp = await httpGet(`${API_BASE}/api/v1/runs/${runId}`);
          const run = JSON.parse(resp.body);
          const status = run.status;
          const results = run.results || [];

          if (results.length > prevResultCount) {
            const newResults = results.slice(prevResultCount);
            for (const r of newResults) {
              const isFail = r.status === "FAIL";
              const isWarn = r.status === "WARNING";
              if (isFail) {
                send("scan-progress", { type: "chrome", text: `[CRITICAL] ${r.name}` });
                send("scan-progress", { type: "chrome", text: `  → ${(r.actual || "").slice(0, 300)}` });
                if (r.recommendation) send("scan-progress", { type: "detail", text: `  Fix: ${r.recommendation.slice(0, 300)}` });
              } else if (isWarn) {
                send("scan-progress", { type: "chrome", text: `[WARNING] ${r.name}` });
                send("scan-progress", { type: "detail", text: `  → ${(r.actual || "").slice(0, 200)}` });
              } else {
                send("scan-progress", { type: "pass", text: `[PASS] ${r.name}` });
              }
            }
            prevResultCount = results.length;
          } else if (phaseIdx < phases.length) {
            send("scan-progress", { type: "chrome", text: phases[phaseIdx] });
            phaseIdx++;
          }

          if (status === "completed" || status === "failed" || status === "cancelled") {
            const fails = results.filter((r) => r.status === "FAIL");
            const warns = results.filter((r) => r.status === "WARNING");
            const passes = results.filter((r) => r.status === "PASS");

            send("scan-progress", { type: "divider" });
            send("scan-progress", { type: "chrome", text: `Scan ${status.toUpperCase()} — ${results.length} total | ${fails.length} FAIL | ${warns.length} WARNING | ${passes.length} PASS` });

            // Only trigger proof-of-bypass for CONFIRMED_P0 from the payment integrity engine (PI-* test IDs).
            // Generic functional/integration test failures (FUNC-*, INTEG-*) are NOT access-without-payment flaws —
            // they just mean guessed API endpoints returned errors (e.g. 403 from a WAF).
            const accessFlaws = fails.filter((f) =>
              f.test_case_id && f.test_case_id.startsWith("PI-")
            );

            if (accessFlaws.length > 0) {
              send("scan-progress", { type: "chrome", text: "" });
              send("scan-progress", { type: "chrome", text: "ACCESS-WITHOUT-PAYMENT FLAW CONFIRMED" });
              for (const flaw of accessFlaws) {
                send("scan-progress", { type: "chrome", text: `  Exploit: ${flaw.name}` });
                send("scan-progress", { type: "chrome", text: `  ${(flaw.actual || "").slice(0, 400)}` });
              }
              send("scan-proof", { url, flaws: accessFlaws });
            }

            if (run.error_message) {
              send("scan-progress", { type: "error", text: `Error: ${run.error_message}` });
            }

            send("scan-done", { error: status === "failed" });
            return;
          }
        } catch (err) {
          send("scan-progress", { type: "detail", text: `Poll error: ${err.message}` });
        }
      }
    };

    await poll();
  } catch (err) {
    send("scan-progress", { type: "error", text: `Scan failed: ${err.message}` });
    send("scan-done", { error: true });
  }
}

// --- IPC handlers ---

ipcMain.handle("start-backend", startBackend);
ipcMain.handle("has-session", () => hasSession());
ipcMain.handle("clear-session", async () => {
  if (fs.existsSync(SESSION_STATE_PATH)) fs.unlinkSync(SESSION_STATE_PATH);
  // Also clear Electron partition cookies so a fresh login starts clean
  try { await session.fromPartition(LOGIN_PARTITION).clearStorageData(); } catch {}
  try { await session.fromPartition("persist:redpilot-proof").clearStorageData(); } catch {}
  return true;
});
ipcMain.handle("open-login-browser", (_, url) => openLoginBrowser(url));
ipcMain.handle("run-scan", (event, url) => runScan(url, event));
ipcMain.handle("open-proof-browser", (_, url) => openProofBrowser(url));

// --- App lifecycle ---

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  stopBackend();
  if (loginBrowser) { try { loginBrowser.close(); } catch {} }
  app.quit();
});

app.on("before-quit", stopBackend);
