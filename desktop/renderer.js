/* RedPilot Terminal — renderer process */

const output = document.getElementById("output");
const cmdInput = document.getElementById("cmd");
const banner = document.getElementById("banner");

// ─── ASCII Art Banner ────────────────────────────────────────────

const CROSSHAIR = [
  "              ░              ",
  "         ═════╬═════         ",
  "         ║    │    ║         ",
  "      ═══╬════●════╬═══     ",
  "         ║    │    ║         ",
  "         ═════╬═════         ",
  "              ░              ",
].join("\n");

const LOGO_TEXT = [
  " ██████  ███████ ██████  ██████  ██ ██       ██████  ████████",
  " ██   ██ ██      ██   ██ ██   ██ ██ ██      ██    ██    ██   ",
  " ██████  █████   ██   ██ ██████  ██ ██      ██    ██    ██   ",
  " ██   ██ ██      ██   ██ ██      ██ ██      ██    ██    ██   ",
  " ██   ██ ███████ ██████  ██      ██ ███████  ██████     ██   ",
].join("\n");

const SUBTITLE = "Payment Security QA — Zero Trust Engine";
const VERSION = "v9.0 — 36 engines | 34 AWP patterns | 11 PBB probes | 37 tests";

function renderBanner() {
  banner.innerHTML = "";

  const crosshairEl = document.createElement("div");
  crosshairEl.className = "chrome-banner";
  crosshairEl.textContent = CROSSHAIR;
  banner.appendChild(crosshairEl);

  const spacer1 = document.createElement("div");
  spacer1.textContent = "";
  banner.appendChild(spacer1);

  const logoEl = document.createElement("div");
  logoEl.className = "chrome-banner";
  logoEl.textContent = LOGO_TEXT;
  banner.appendChild(logoEl);

  const spacer2 = document.createElement("div");
  spacer2.style.height = "6px";
  banner.appendChild(spacer2);

  const subEl = document.createElement("div");
  subEl.style.color = "#666";
  subEl.style.fontSize = "12px";
  subEl.textContent = SUBTITLE;
  banner.appendChild(subEl);

  const verEl = document.createElement("div");
  verEl.style.color = "#444";
  verEl.style.fontSize = "11px";
  verEl.textContent = VERSION;
  banner.appendChild(verEl);
}

renderBanner();

// ─── Terminal Output ─────────────────────────────────────────────

function print(text, className) {
  const el = document.createElement("div");
  el.className = "line" + (className ? ` ${className}` : "");
  el.textContent = text;
  output.appendChild(el);
  output.scrollTop = output.scrollHeight;
}

function printChrome(text) {
  const el = document.createElement("div");
  el.className = "line chrome";
  el.textContent = text;
  output.appendChild(el);
  output.scrollTop = output.scrollHeight;
}

function printDivider() {
  const el = document.createElement("div");
  el.className = "line-divider";
  output.appendChild(el);
}

function printBlank() {
  print("");
}

function clearOutput() {
  output.innerHTML = "";
}

// ─── State Machine ───────────────────────────────────────────────

let state = "BOOTING"; // BOOTING | IDLE | LOGIN_WAIT | SCANNING | PROOF
const history = [];
let historyIdx = -1;

function setIdle() {
  state = "IDLE";
  cmdInput.disabled = false;
  cmdInput.placeholder = "Type /help for commands";
  cmdInput.focus();
}

function setScanning() {
  state = "SCANNING";
  cmdInput.disabled = true;
  cmdInput.placeholder = "Scanning...";
}

function setLoginWait() {
  state = "LOGIN_WAIT";
  cmdInput.disabled = false;
  cmdInput.placeholder = "Press ENTER when logged in";
}

// ─── Command Handling ────────────────────────────────────────────

cmdInput.addEventListener("keydown", async (e) => {
  if (e.key === "ArrowUp") {
    e.preventDefault();
    if (historyIdx < history.length - 1) {
      historyIdx++;
      cmdInput.value = history[history.length - 1 - historyIdx];
    }
    return;
  }
  if (e.key === "ArrowDown") {
    e.preventDefault();
    if (historyIdx > 0) {
      historyIdx--;
      cmdInput.value = history[history.length - 1 - historyIdx];
    } else {
      historyIdx = -1;
      cmdInput.value = "";
    }
    return;
  }

  if (e.key !== "Enter") return;
  const raw = cmdInput.value.trim();
  cmdInput.value = "";
  historyIdx = -1;

  if (state === "LOGIN_WAIT") {
    print("└─$ [confirm login]", "line-echo");
    printChrome("Saving authenticated session state...");
    window.redpilot.confirmLogin();
    return;
  }

  if (!raw) return;
  history.push(raw);

  print(`└─$ ${raw}`, "line-echo");

  const parts = raw.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1).join(" ");

  switch (cmd) {
    case "/scan":
      if (!args) {
        print("Usage: /scan <url>", "line-error");
        print("  First run:  /scan <login-page-url>     (opens browser for login)");
        print("  Second run: /scan <paywall-url>         (runs engine with saved session)");
        printBlank();
      } else {
        await handleScan(args);
      }
      break;

    case "/clear":
      clearOutput();
      break;

    case "/help":
      showHelp();
      break;

    case "/logout":
      await handleLogout();
      break;

    case "/status":
      await handleStatus();
      break;

    default:
      print(`Unknown command: ${cmd}`, "line-error");
      print("Type /help for available commands.", "line-dim");
      printBlank();
  }
});

// ─── /help ───────────────────────────────────────────────────────

function showHelp() {
  printBlank();
  printChrome("RedPilot Commands");
  printDivider();
  print("  /scan <url>     Scan a target URL");
  print("                  First use: opens Chromium for manual login");
  print("                  After login: runs the full engine with saved session");
  printBlank();
  print("  /logout         Clear saved session state");
  print("  /status         Show current session and engine status");
  print("  /clear          Clear the terminal output");
  print("  /help           Show this help message");
  printDivider();
  printBlank();
}

// ─── /status ─────────────────────────────────────────────────────

async function handleStatus() {
  printBlank();
  const has = await window.redpilot.hasSession();
  print(`  Session state: ${has ? "SAVED" : "NONE"}`, has ? "line-green" : "line-dim");
  print(`  Backend: ${state !== "BOOTING" ? "RUNNING" : "STARTING"}`);
  print(`  State: ${state}`);
  printBlank();
}

// ─── /logout ─────────────────────────────────────────────────────

async function handleLogout() {
  await window.redpilot.clearSession();
  printChrome("Session state cleared.");
  print("Run /scan <login-url> to create a new session.", "line-dim");
  printBlank();
}

// ─── /scan ───────────────────────────────────────────────────────

async function handleScan(url) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const hasSession = await window.redpilot.hasSession();

  if (!hasSession) {
    // --- LOGIN FLOW ---
    printBlank();
    print("No authenticated session found.");
    printChrome("Opening Chromium browser...");
    print(`Navigating to: ${url}`);
    printBlank();
    printChrome("Log in manually in the browser window.");
    print("When you've finished logging in, come back here and press ENTER.", "line-dim");
    printBlank();

    setLoginWait();

    const result = await window.redpilot.openLoginBrowser(url);

    if (result.success) {
      printBlank();
      printChrome("Session state saved successfully.");
      print("Chromium closed.", "line-dim");
      printBlank();
      printDivider();
      printChrome("Ready. Now run:  /scan <payment-paywall-url>");
      print("The engine will use your saved authenticated session.", "line-dim");
      printBlank();
    } else {
      printBlank();
      print(`Login flow failed: ${result.error}`, "line-error");
      printBlank();
    }

    setIdle();
  } else {
    // --- SCAN FLOW ---
    setScanning();
    printBlank();
    printChrome("Authenticated session loaded");
    printDivider();
    print(`  Target:  ${url}`);
    print("  Mode:    FULL REGRESSION — all 43 experiments, 56 tools, 67 agents");
    print("  Session: Using saved authentication state");
    printDivider();
    printBlank();
    printChrome("Engine ignited. All probes firing.");
    printBlank();

    window.redpilot.runScan(url);
  }
}

// ─── Scan event listeners ────────────────────────────────────────

window.redpilot.onScanProgress((data) => {
  switch (data.type) {
    case "chrome":
      printChrome(data.text);
      break;
    case "error":
      print(data.text, "line-error");
      break;
    case "pass":
      print(data.text, "line-pass");
      break;
    case "detail":
      print(data.text, "line-detail");
      break;
    case "status":
      print(data.text, "line-dim");
      break;
    case "divider":
      printDivider();
      break;
    default:
      print(data.text);
  }
});

window.redpilot.onScanDone((_data) => {
  printBlank();
  printDivider();
  print("Scan complete. Returned to command line.", "line-dim");
  printBlank();
  setIdle();
});

window.redpilot.onScanProof(async (data) => {
  printBlank();
  printDivider();
  printChrome("╔══════════════════════════════════════════════════════╗");
  printChrome("║   PROOF-OF-BYPASS: Opening browser to demonstrate   ║");
  printChrome("╚══════════════════════════════════════════════════════╝");
  printBlank();
  printChrome("Chromium opening with saved session → paywall URL");
  print("If the paid content loads, the bypass is confirmed.", "line-dim");
  printBlank();

  for (const flaw of data.flaws) {
    printChrome(`Exploitable flaw: ${flaw.name}`);
    if (flaw.actual) printChrome(`  ${flaw.actual.slice(0, 400)}`);
    if (flaw.recommendation) print(`  Recommended fix: ${flaw.recommendation.slice(0, 300)}`, "line-detail");
    printBlank();
  }

  const result = await window.redpilot.openProofBrowser(data.url);
  if (result.success) {
    print("Proof browser closed.", "line-dim");
  }
});

// ─── Boot sequence ───────────────────────────────────────────────

(async function boot() {
  print("Initializing RedPilot...", "line-dim");

  const result = await window.redpilot.startBackend();

  if (result.success) {
    printChrome("Backend engine online.");
  } else {
    print(`Backend: ${result.message}`, "line-error");
    print("Start the backend manually: cd backend && python -m uvicorn app.main:app --port 8420", "line-dim");
  }

  const has = await window.redpilot.hasSession();
  if (has) {
    print("Saved session state detected.", "line-dim");
  }

  printBlank();
  printDivider();
  printChrome("System ready. Type /scan <url> to begin.");
  print("Type /help for all commands.", "line-dim");
  printBlank();

  setIdle();
})();

// Keep focus on input
document.addEventListener("click", () => {
  if (state !== "SCANNING") cmdInput.focus();
});
