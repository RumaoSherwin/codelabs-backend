const express = require("express");
const cors = require("cors");
const http = require("http");
const { spawn, spawnSync } = require("child_process");
const { createHmac, randomUUID, timingSafeEqual } = require("crypto");
const { WebSocketServer } = require("ws");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const WS_PATH = process.env.WS_PATH || "/ws";
const JSON_LIMIT = process.env.JSON_LIMIT || "256kb";
const MAX_CODE_LENGTH = Number(process.env.MAX_CODE_LENGTH) || 100_000;
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS) || 8;
const RUN_TIMEOUT_MS = Number(process.env.RUN_TIMEOUT_MS) || 20_000;
const INTERACTIVE_RUN_IDLE_TIMEOUT_MS =
  Number(process.env.INTERACTIVE_RUN_IDLE_TIMEOUT_MS) || 5 * 60 * 1000;
const SESSION_IDLE_TIMEOUT_MS =
  Number(process.env.SESSION_IDLE_TIMEOUT_MS) || 10 * 60 * 1000;
const CLEANUP_INTERVAL_MS =
  Number(process.env.CLEANUP_INTERVAL_MS) || 60 * 1000;
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const RUNNER_API_KEY = String(process.env.RUNNER_API_KEY || process.env.CODELABS_RUNNER_API_KEY || "").trim();
const RUNNER_SESSION_SECRET = String(process.env.RUNNER_SESSION_SECRET || process.env.CODELABS_RUNNER_SESSION_SECRET || "").trim();
const REQUIRE_RUNNER_KEY = String(
  process.env.REQUIRE_RUNNER_KEY || (process.env.NODE_ENV === "production" ? "true" : "false"),
).trim().toLowerCase() === "true";
const CODELAB_LANGUAGE_MAP = {
  c: "c",
  cpp: "cpp",
  csharp: "csharp",
  go: "go",
  java: "java",
  javascript: "javascript",
  js: "javascript",
  node: "javascript",
  python: "python3",
  python3: "python3",
  rust: "rust",
  typescript: "typescript",
  ts: "typescript",
};

const TSC_COMMAND = path.join(process.cwd(), "node_modules", "typescript", "bin", "tsc");

const PYTHON_WORKER = String.raw`
import contextlib
import io
import json
import sys
import traceback

scope = {"__name__": "__main__"}

def emit(message_type, value=None, extra=None):
    payload = {"type": message_type}
    if value is not None:
        payload["value"] = value
    if extra:
        payload.update(extra)
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

emit("ready", "python")

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue

    try:
        command = json.loads(raw)
        code = command.get("code", "")
        command_id = command.get("commandId")

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            try:
                try:
                    compiled = compile(code, "<session>", "eval")
                except SyntaxError:
                    compiled = compile(code, "<session>", "exec")
                    exec(compiled, scope, scope)
                else:
                    result = eval(compiled, scope, scope)
                    if result is not None:
                        print(repr(result))
            except SystemExit as exc:
                print(f"SystemExit: {exc}", file=sys.stderr)
            except Exception:
                traceback.print_exc(file=sys.stderr)

        stdout_value = stdout_buffer.getvalue()
        stderr_value = stderr_buffer.getvalue()
        if stdout_value:
            emit("stdout", stdout_value, {"commandId": command_id})
        if stderr_value:
            emit("stderr", stderr_value, {"commandId": command_id})
        emit("result", "", {"commandId": command_id})
    except Exception:
        emit("stderr", traceback.format_exc())
        emit("result", "")
`;

const NODE_WORKER = String.raw`
const readline = require("readline");
const vm = require("vm");
const util = require("util");

const context = vm.createContext({
  console,
  require,
  process,
  Buffer,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  globalThis: {},
});

context.global = context;
context.globalThis = context;

function emit(type, value = "", extra = {}) {
  process.stdout.write(JSON.stringify({ type, value, ...extra }) + "\\n");
}

emit("ready", "javascript");

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
  terminal: false,
});

rl.on("line", async (line) => {
  const raw = line.trim();
  if (!raw) {
    return;
  }

  let command;
  try {
    command = JSON.parse(raw);
  } catch (error) {
    emit("stderr", error.stack || String(error));
    emit("result", "");
    return;
  }

  const { code = "", commandId } = command;
  const stdout = [];
  const stderr = [];

  const previousConsole = context.console;
  context.console = {
    ...console,
    log: (...args) => stdout.push(args.map((arg) => util.inspect(arg, { depth: 4 })).join(" ")),
    info: (...args) => stdout.push(args.map((arg) => util.inspect(arg, { depth: 4 })).join(" ")),
    warn: (...args) => stderr.push(args.map((arg) => util.inspect(arg, { depth: 4 })).join(" ")),
    error: (...args) => stderr.push(args.map((arg) => util.inspect(arg, { depth: 4 })).join(" ")),
  };

  try {
    const wrapped = \`(async () => { \${code}
})()\`;
    const script = new vm.Script(wrapped, { filename: "<session>" });
    const result = await script.runInContext(context, { timeout: 1000 });

    if (result !== undefined) {
      stdout.push(util.inspect(result, { depth: 4 }));
    }
  } catch (error) {
    stderr.push(error && error.stack ? error.stack : String(error));
  } finally {
    context.console = previousConsole;
  }

  if (stdout.length) {
    emit("stdout", stdout.join("\\n") + "\\n", { commandId });
  }
  if (stderr.length) {
    emit("stderr", stderr.join("\\n") + "\\n", { commandId });
  }
  emit("result", "", { commandId });
});
`;

function log(level, message, meta = undefined) {
  const payload = {
    level,
    message,
    ...(meta ? { meta } : {}),
    timestamp: new Date().toISOString(),
  };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  console.log(line);
}

function buildRunnerErrorPayload(error, req) {
  const statusCode =
    error?.type === "entity.too.large"
      ? 413
      : error?.statusCode || error?.status || 500;
  const reportId = randomUUID();
  const stage = String(error?.stage || (statusCode >= 500 ? "runner_internal" : "runner_request")).trim();
  const hint = String(
    error?.hint ||
      (stage === "runner_session_secret"
        ? "Set RUNNER_SESSION_SECRET on Railway and match it with the website session secret."
        : stage === "runner_api_key"
          ? "Set RUNNER_API_KEY on Railway and match it with the website runner API key."
          : stage === "runner_execute"
            ? "Check the selected language runtime and recent runner logs."
            : ""),
  ).trim();

  if (statusCode >= 500) {
    log("error", "Unhandled request error", {
      reportId,
      stage,
      route: req?.url || "",
      method: req?.method || "",
      error: error?.message || "",
      hint,
      stack: error?.stack || "",
    });
  }

  return {
    statusCode,
    payload: {
      error: String(error?.message || (statusCode >= 500 ? "Internal server error" : "Request failed")),
      report: {
        id: reportId,
        stage,
        hint,
        statusCode,
        timestamp: new Date().toISOString(),
      },
    },
  };
}

function isOriginAllowed(origin) {
  if (!origin || ALLOWED_ORIGINS.includes("*")) {
    return true;
  }
  return ALLOWED_ORIGINS.includes(origin);
}

function buildCorsOptions() {
  return {
    origin(origin, callback) {
      if (isOriginAllowed(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    credentials: true,
  };
}

function safeEquals(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  if (!leftBuffer.length || leftBuffer.length !== rightBuffer.length) return false;
  try {
    return timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

function getRunnerKeyFromRequest(req) {
  const headerKey = req.headers["x-runner-key"] || req.headers["X-Runner-Key"];
  if (typeof headerKey === "string" && headerKey.trim()) {
    return headerKey.trim();
  }
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const queryKey = url.searchParams.get("runnerKey") || url.searchParams.get("key");
    return String(queryKey || "").trim();
  } catch {
    return "";
  }
}

function getRunnerSessionTokenFromRequest(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (typeof authHeader === "string") {
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch) {
      return bearerMatch[1].trim();
    }
  }

  const headerToken =
    req.headers["x-runner-session-token"] || req.headers["X-Runner-Session-Token"];
  if (typeof headerToken === "string" && headerToken.trim()) {
    return headerToken.trim();
  }

  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    return String(url.searchParams.get("token") || "").trim();
  } catch {
    return "";
  }
}

function fromBase64Url(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function createSessionTokenSignature(payloadSegment) {
  return createHmac("sha256", RUNNER_SESSION_SECRET)
    .update(payloadSegment)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function verifyRunnerSessionToken(token, expectedSessionId = "") {
  if (!RUNNER_SESSION_SECRET) {
    return null;
  }

  const raw = String(token || "").trim();
  const separatorIndex = raw.indexOf(".");
  if (!raw || separatorIndex <= 0) {
    return null;
  }

  const payloadSegment = raw.slice(0, separatorIndex);
  const signature = raw.slice(separatorIndex + 1);
  if (!safeEquals(signature, createSessionTokenSignature(payloadSegment))) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(fromBase64Url(payloadSegment));
  } catch {
    return null;
  }

  const sessionId = String(payload?.sid || "").trim();
  const exp = Number(payload?.exp || 0);
  if (!sessionId || !Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) {
    return null;
  }
  if (expectedSessionId && sessionId !== String(expectedSessionId).trim()) {
    return null;
  }

  return {
    sessionId,
    userId: String(payload?.uid || "").trim(),
    language: String(payload?.lang || "").trim().toLowerCase(),
    expiresAt: exp,
  };
}

function authorizeRunnerRequest(req, options = {}) {
  const expectedSessionId = String(options.expectedSessionId || "").trim();

  if (RUNNER_API_KEY && safeEquals(getRunnerKeyFromRequest(req), RUNNER_API_KEY)) {
    return { type: "shared-key" };
  }

  if (options.allowSessionToken) {
    const tokenPayload = verifyRunnerSessionToken(
      getRunnerSessionTokenFromRequest(req),
      expectedSessionId,
    );
    if (tokenPayload) {
      return { type: "session-token", token: tokenPayload };
    }
  }

  if (!REQUIRE_RUNNER_KEY && !RUNNER_API_KEY && !options.allowSessionToken) {
    return { type: "unprotected" };
  }

  return null;
}

function isAuthorizedRunnerRequest(req, options = {}) {
  return Boolean(authorizeRunnerRequest(req, options));
}

function detectPythonCommand() {
  for (const candidate of ["python3", "python"]) {
    const result = spawnSync(candidate, ["--version"], {
      stdio: "ignore",
      windowsHide: true,
    });

    if (!result.error && result.status === 0) {
      return candidate;
    }
  }

  return null;
}

function detectCommand(candidates) {
  for (const candidate of candidates) {
    const result = spawnSync(candidate, ["--version"], {
      stdio: "ignore",
      windowsHide: true,
    });

    if (!result.error && result.status === 0) {
      return candidate;
    }
  }

  return null;
}

const PYTHON_COMMAND = detectPythonCommand();
const NODE_COMMAND = process.execPath;
const GCC_COMMAND = detectCommand(["gcc"]);
const GPP_COMMAND = detectCommand(["g++"]);
const GO_COMMAND = detectCommand(["go"]);
const JAVAC_COMMAND = detectCommand(["javac"]);
const JAVA_COMMAND = detectCommand(["java"]);
const MCS_COMMAND = detectCommand(["mcs"]);
const MONO_COMMAND = detectCommand(["mono"]);
const RUSTC_COMMAND = detectCommand(["rustc"]);
const sessions = new Map();

function touchSession(session) {
  session.lastActivityAt = Date.now();
}

function serializeSession(session) {
  return {
    id: session.id,
    language: session.language,
    createdAt: new Date(session.createdAt).toISOString(),
    lastActivityAt: new Date(session.lastActivityAt).toISOString(),
    running: Boolean(session.currentRun),
  };
}

function sendWebSocket(ws, payload) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(payload));
  }
}

function broadcastSession(session, payload) {
  for (const socket of session.sockets) {
    sendWebSocket(socket, payload);
  }
}

function cleanupRunArtifacts(run) {
  if (run?.workspace) {
    fs.rm(run.workspace, { recursive: true, force: true }).catch(() => {});
  }
}

function finishRun(session, status, error = null) {
  if (!session.currentRun) {
    return;
  }

  const run = session.currentRun;
  const { timer, resolve, reject, outputChunks, stderrChunks, stdoutChunks } = run;

  clearTimeout(timer);
  if (error?.stdout) {
    stdoutChunks.push(String(error.stdout));
    outputChunks.push(String(error.stdout));
  }
  if (error?.stderr) {
    stderrChunks.push(String(error.stderr));
    outputChunks.push(String(error.stderr));
  }
  const output = outputChunks.join("");
  const stdout = stdoutChunks.join("");
  const stderr = stderrChunks.join("");

  session.currentRun = null;
  touchSession(session);
  cleanupRunArtifacts(run);

  const payload = {
    type: "run_complete",
    sessionId: session.id,
    commandId: run.commandId,
    status: status === "success" ? "completed" : "error",
    output,
    stdout,
    stderr,
  };

  if (status === "success") {
    broadcastSession(session, payload);
    resolve({ output, stdout, stderr });
    return;
  }

  const message = error?.message || "Code execution failed";
  broadcastSession(session, { ...payload, error: message });
  const details = {
    output,
    stdout,
    stderr,
    error: message,
  };
  reject(Object.assign(new Error(message), details));
}

function appendRunChunk(session, stream, value) {
  if (!session.currentRun || typeof value !== "string" || !value) {
    return;
  }

  session.currentRun.outputChunks.push(value);
  if (stream === "stdout") {
    session.currentRun.stdoutChunks.push(value);
  } else {
    session.currentRun.stderrChunks.push(value);
  }
}

function refreshCurrentRunTimer(session, reason = "Execution timed out") {
  const run = session.currentRun;
  if (!run) return;

  clearTimeout(run.timer);
  run.timer = setTimeout(() => {
    if (session.currentRun?.commandId === run.commandId) {
      terminateCurrentRun(session, reason);
    }
  }, run.timeoutMs || INTERACTIVE_RUN_IDLE_TIMEOUT_MS);
  run.timer.unref();
}

function killChildProcess(child) {
  if (!child || child.killed) return;
  child.kill("SIGTERM");
  setTimeout(() => {
    if (!child.killed) {
      child.kill("SIGKILL");
    }
  }, 1500).unref();
}

function terminateCurrentRun(session, reason = "Execution stopped") {
  const run = session.currentRun;
  if (!run) return;

  run.terminationReason = reason;
  if (run.child) {
    killChildProcess(run.child);
    return;
  }
  finishRun(session, "error", new Error(reason));
}

function stopCurrentRun(session) {
  if (!session.currentRun) {
    throw Object.assign(new Error("No active program is running"), {
      statusCode: 409,
    });
  }

  terminateCurrentRun(session, "Execution stopped by user");
}

function destroySession(sessionId, reason = "destroyed") {
  const session = sessions.get(sessionId);
  if (!session) {
    return false;
  }

  if (session.currentRun) {
    terminateCurrentRun(session, `Session ${reason}`);
  }

  sessions.delete(sessionId);
  touchSession(session);
  broadcastSession(session, { type: "session_closed", sessionId, reason });

  for (const socket of session.sockets) {
    try {
      socket.close(1000, reason);
    } catch (error) {
      log("error", "Failed to close websocket", {
        sessionId,
        error: error.message,
      });
    }
  }

  session.sockets.clear();
  if (session.workspaceRoot) {
    fs.rm(session.workspaceRoot, { recursive: true, force: true }).catch(() => {});
  }

  log("info", "Session destroyed", { sessionId, reason });
  return true;
}

function createSession(language) {
  if (sessions.size >= MAX_SESSIONS) {
    throw new Error("Session limit reached. Try again after closing an idle session.");
  }

  const normalizedLanguage =
    CODELAB_LANGUAGE_MAP[String(language || "").trim().toLowerCase()] ||
    String(language || "").trim().toLowerCase();
  if (!normalizedLanguage || !Object.values(CODELAB_LANGUAGE_MAP).includes(normalizedLanguage)) {
    throw new Error("Unsupported language");
  }

  const id = randomUUID();
  const session = {
    id,
    language: normalizedLanguage,
    sockets: new Set(),
    currentRun: null,
    createdAt: Date.now(),
    lastActivityAt: Date.now(),
    workspaceRoot: null,
  };

  sessions.set(id, session);
  log("info", "Session created", { sessionId: id, language: session.language });
  return session;
}

function sanitizeJavaClassName(code) {
  const publicMatch = code.match(/\bpublic\s+class\s+([A-Za-z_]\w*)/);
  if (publicMatch) return publicMatch[1];
  const classMatch = code.match(/\bclass\s+([A-Za-z_]\w*)/);
  if (classMatch) return classMatch[1];
  return "Main";
}

function spawnProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => {
        if (!child.killed) {
          child.kill("SIGKILL");
        }
      }, 1500).unref();
    }, options.timeoutMs || RUN_TIMEOUT_MS);
    timeout.unref();

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);

      if (timedOut) {
        reject(Object.assign(new Error("Execution timed out"), { stdout, stderr }));
        return;
      }

      resolve({
        code: typeof code === "number" ? code : 1,
        stdout,
        stderr,
      });
    });

    if (options.input) {
      child.stdin.write(options.input);
    }
    child.stdin.end();
  });
}

async function withTempWorkspace(fn) {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "sifra-run-"));
  try {
    return await fn(workspace);
  } finally {
    await fs.rm(workspace, { recursive: true, force: true }).catch(() => {});
  }
}

function ensureRuntime(command, label) {
  if (command) return command;
  throw Object.assign(new Error(`${label} is not installed in this container`), { statusCode: 500 });
}

async function ensureSessionWorkspaceRoot(session) {
  if (session.workspaceRoot) return session.workspaceRoot;
  session.workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), `sifra-session-${session.id}-`));
  return session.workspaceRoot;
}

async function createRunWorkspace(session) {
  const workspaceRoot = await ensureSessionWorkspaceRoot(session);
  return fs.mkdtemp(path.join(workspaceRoot, "run-"));
}

function spawnInteractiveChild(command, args, options = {}) {
  return spawn(command, args, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

async function prepareInteractiveProgram(language, code, session) {
  const workspace = await createRunWorkspace(session);

  try {
    if (language === "javascript") {
      const sourcePath = path.join(workspace, "main.js");
      await fs.writeFile(sourcePath, code, "utf8");
      return {
        workspace,
        child: spawnInteractiveChild(NODE_COMMAND, [sourcePath], {
          cwd: workspace,
          env: { NODE_NO_WARNINGS: "1" },
        }),
      };
    }

    if (language === "python3") {
      const python = ensureRuntime(PYTHON_COMMAND, "Python");
      const sourcePath = path.join(workspace, "main.py");
      await fs.writeFile(sourcePath, code, "utf8");
      return {
        workspace,
        child: spawnInteractiveChild(python, ["-u", sourcePath], {
          cwd: workspace,
          env: { PYTHONUNBUFFERED: "1" },
        }),
      };
    }

    if (language === "c") {
      const gcc = ensureRuntime(GCC_COMMAND, "GCC");
      const sourcePath = path.join(workspace, "main.c");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(gcc, [sourcePath, "-O2", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return { workspace, child: spawnInteractiveChild(outputPath, [], { cwd: workspace }) };
    }

    if (language === "cpp") {
      const gpp = ensureRuntime(GPP_COMMAND, "G++");
      const sourcePath = path.join(workspace, "main.cpp");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(gpp, [sourcePath, "-O2", "-std=c++17", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return { workspace, child: spawnInteractiveChild(outputPath, [], { cwd: workspace }) };
    }

    if (language === "go") {
      const go = ensureRuntime(GO_COMMAND, "Go");
      const sourcePath = path.join(workspace, "main.go");
      await fs.writeFile(sourcePath, code, "utf8");
      return { workspace, child: spawnInteractiveChild(go, ["run", sourcePath], { cwd: workspace }) };
    }

    if (language === "java") {
      const javac = ensureRuntime(JAVAC_COMMAND, "Java compiler");
      const java = ensureRuntime(JAVA_COMMAND, "Java runtime");
      const className = sanitizeJavaClassName(code);
      const sourcePath = path.join(workspace, `${className}.java`);
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(javac, [sourcePath], { cwd: workspace });
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return { workspace, child: spawnInteractiveChild(java, ["-cp", workspace, className], { cwd: workspace }) };
    }

    if (language === "csharp") {
      const mcs = ensureRuntime(MCS_COMMAND, "Mono C# compiler");
      const mono = ensureRuntime(MONO_COMMAND, "Mono runtime");
      const sourcePath = path.join(workspace, "Program.cs");
      const outputPath = path.join(workspace, "Program.exe");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(mcs, ["-out:Program.exe", sourcePath], { cwd: workspace });
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return { workspace, child: spawnInteractiveChild(mono, [outputPath], { cwd: workspace }) };
    }

    if (language === "rust") {
      const rustc = ensureRuntime(RUSTC_COMMAND, "Rust compiler");
      const sourcePath = path.join(workspace, "main.rs");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(rustc, [sourcePath, "-O", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return { workspace, child: spawnInteractiveChild(outputPath, [], { cwd: workspace }) };
    }

    if (language === "typescript") {
      const sourcePath = path.join(workspace, "main.ts");
      const outputDir = path.join(workspace, "dist");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(
        NODE_COMMAND,
        [TSC_COMMAND, "--target", "ES2020", "--module", "commonjs", "--outDir", outputDir, sourcePath],
        { cwd: workspace },
      );
      if (compile.code !== 0) {
        throw Object.assign(new Error("Compilation failed"), compile);
      }
      return {
        workspace,
        child: spawnInteractiveChild(NODE_COMMAND, [path.join(outputDir, "main.js")], { cwd: workspace }),
      };
    }

    throw Object.assign(new Error(`Unsupported language: ${language}`), { statusCode: 400 });
  } catch (error) {
    await fs.rm(workspace, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

async function runNativeProgram(language, code, input = "") {
  if (language === "javascript") {
    const result = await spawnProcess(NODE_COMMAND, ["-e", code], { input });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      status: result.code === 0 ? "completed" : "error",
    };
  }

  if (language === "python3") {
    const python = ensureRuntime(PYTHON_COMMAND, "Python");
    const result = await spawnProcess(python, ["-c", code], {
      input,
      env: { PYTHONUNBUFFERED: "1" },
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      status: result.code === 0 ? "completed" : "error",
    };
  }

  return withTempWorkspace(async (workspace) => {
    if (language === "c") {
      const gcc = ensureRuntime(GCC_COMMAND, "GCC");
      const sourcePath = path.join(workspace, "main.c");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(gcc, [sourcePath, "-O2", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(outputPath, [], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "cpp") {
      const gpp = ensureRuntime(GPP_COMMAND, "G++");
      const sourcePath = path.join(workspace, "main.cpp");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(gpp, [sourcePath, "-O2", "-std=c++17", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(outputPath, [], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "go") {
      const go = ensureRuntime(GO_COMMAND, "Go");
      const sourcePath = path.join(workspace, "main.go");
      await fs.writeFile(sourcePath, code, "utf8");
      const result = await spawnProcess(go, ["run", sourcePath], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "java") {
      const javac = ensureRuntime(JAVAC_COMMAND, "Java compiler");
      const java = ensureRuntime(JAVA_COMMAND, "Java runtime");
      const className = sanitizeJavaClassName(code);
      const sourcePath = path.join(workspace, `${className}.java`);
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(javac, [sourcePath], { cwd: workspace });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(java, ["-cp", workspace, className], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "csharp") {
      const mcs = ensureRuntime(MCS_COMMAND, "Mono C# compiler");
      const mono = ensureRuntime(MONO_COMMAND, "Mono runtime");
      const sourcePath = path.join(workspace, "Program.cs");
      const outputPath = path.join(workspace, "Program.exe");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(mcs, ["-out:Program.exe", sourcePath], { cwd: workspace });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(mono, [outputPath], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "rust") {
      const rustc = ensureRuntime(RUSTC_COMMAND, "Rust compiler");
      const sourcePath = path.join(workspace, "main.rs");
      const outputPath = path.join(workspace, "main");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(rustc, [sourcePath, "-O", "-o", outputPath], { cwd: workspace });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(outputPath, [], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    if (language === "typescript") {
      const sourcePath = path.join(workspace, "main.ts");
      const outputDir = path.join(workspace, "dist");
      await fs.writeFile(sourcePath, code, "utf8");
      const compile = await spawnProcess(NODE_COMMAND, [TSC_COMMAND, "--target", "ES2020", "--module", "commonjs", "--outDir", outputDir, sourcePath], {
        cwd: workspace,
      });
      if (compile.code !== 0) {
        return { stdout: compile.stdout, stderr: compile.stderr, status: "error" };
      }
      const result = await spawnProcess(NODE_COMMAND, [path.join(outputDir, "main.js")], { cwd: workspace, input });
      return { stdout: result.stdout, stderr: result.stderr, status: result.code === 0 ? "completed" : "error" };
    }

    throw Object.assign(new Error(`Unsupported language: ${language}`), { statusCode: 400 });
  });
}

async function runForApi(languageInput, code, input) {
  const language = String(languageInput || "").trim().toLowerCase();
  const normalizedLanguage = CODELAB_LANGUAGE_MAP[language] || language;

  if (!normalizedLanguage) {
    throw Object.assign(new Error("code and language are required"), { statusCode: 400 });
  }

  return runNativeProgram(normalizedLanguage, code, input);
}

function ensureSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    const error = new Error("Session not found");
    error.statusCode = 404;
    throw error;
  }

  return session;
}

function executeCode(session, code) {
  const trimmed = typeof code === "string" ? code : "";
  if (!trimmed.trim()) {
    return Promise.resolve({ output: "", stdout: "", stderr: "" });
  }

  if (trimmed.length > MAX_CODE_LENGTH) {
    return Promise.reject(
      Object.assign(new Error("Code payload is too large"), { statusCode: 413 }),
    );
  }

  if (session.currentRun) {
    return Promise.reject(
      Object.assign(
        new Error("A run is already in progress for this session"),
        { statusCode: 409 },
      ),
    );
  }

  touchSession(session);

  return new Promise((resolve, reject) => {
    const commandId = randomUUID();

    session.currentRun = {
      commandId,
      outputChunks: [],
      stdoutChunks: [],
      stderrChunks: [],
      resolve,
      reject,
      child: null,
      workspace: null,
      terminationReason: "",
      timeoutMs: INTERACTIVE_RUN_IDLE_TIMEOUT_MS,
      timer: setTimeout(() => {
        if (session.currentRun?.commandId === commandId) {
          terminateCurrentRun(session, "Execution timed out while waiting for output or input");
        }
      }, INTERACTIVE_RUN_IDLE_TIMEOUT_MS),
    };

    session.currentRun.timer.unref();

    broadcastSession(session, {
      type: "run_started",
      sessionId: session.id,
      commandId,
      language: session.language,
    });

    prepareInteractiveProgram(session.language, trimmed, session)
      .then(({ child, workspace }) => {
        if (!session.currentRun || session.currentRun.commandId !== commandId) {
          killChildProcess(child);
          fs.rm(workspace, { recursive: true, force: true }).catch(() => {});
          return;
        }

        session.currentRun.child = child;
        session.currentRun.workspace = workspace;

        child.stdout.on("data", (chunk) => {
          const value = chunk.toString();
          appendRunChunk(session, "stdout", value);
          broadcastSession(session, {
            type: "output",
            stream: "stdout",
            value,
            sessionId: session.id,
            commandId,
          });
          refreshCurrentRunTimer(session, "Execution timed out while waiting for output or input");
          touchSession(session);
        });

        child.stderr.on("data", (chunk) => {
          const value = chunk.toString();
          appendRunChunk(session, "stderr", value);
          broadcastSession(session, {
            type: "output",
            stream: "stderr",
            value,
            sessionId: session.id,
            commandId,
          });
          refreshCurrentRunTimer(session, "Execution timed out while waiting for output or input");
          touchSession(session);
        });

        child.on("error", (error) => {
          if (session.currentRun?.commandId !== commandId) return;
          finishRun(session, "error", error);
        });

        child.on("close", (code, signal) => {
          if (session.currentRun?.commandId !== commandId) return;

          const reason = session.currentRun.terminationReason;
          if (reason) {
            finishRun(session, "error", new Error(reason));
            return;
          }

          if (signal) {
            finishRun(session, "error", new Error(`Process exited with signal ${signal}`));
            return;
          }

          if (typeof code === "number" && code !== 0) {
            finishRun(session, "error", new Error(`Process exited with code ${code}`));
            return;
          }

          finishRun(session, "success");
        });

        refreshCurrentRunTimer(session, "Execution timed out while waiting for output or input");
        touchSession(session);
      })
      .catch((error) => {
        if (session.currentRun?.commandId !== commandId) return;
        finishRun(session, "error", error);
      });
  });
}

function sendInputToRun(session, value) {
  if (!session.currentRun || !session.currentRun.child) {
    throw Object.assign(new Error("No active program is waiting for input"), {
      statusCode: 409,
    });
  }

  const text = typeof value === "string" ? value : String(value ?? "");
  try {
    session.currentRun.child.stdin.write(text);
    refreshCurrentRunTimer(session, "Execution timed out while waiting for output or input");
    touchSession(session);
  } catch (error) {
    throw Object.assign(new Error(error?.message || "Failed to send stdin"), {
      statusCode: 500,
    });
  }
}

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(cors(buildCorsOptions()));
app.use(express.json({ limit: JSON_LIMIT }));

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "browser-ide-backend",
    transport: {
      http: true,
      websocket: WS_PATH,
    },
    runtime: {
      node: process.version,
      python: PYTHON_COMMAND,
    },
    limits: {
      maxSessions: MAX_SESSIONS,
      runTimeoutMs: RUN_TIMEOUT_MS,
      interactiveRunIdleTimeoutMs: INTERACTIVE_RUN_IDLE_TIMEOUT_MS,
      sessionIdleTimeoutMs: SESSION_IDLE_TIMEOUT_MS,
      maxCodeLength: MAX_CODE_LENGTH,
    },
    sessions: sessions.size,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.post(["/run", "/api/run"], async (req, res, next) => {
  try {
    if (!isAuthorizedRunnerRequest(req)) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const code = String(req.body?.code || "");
    const languageInput = String(req.body?.language || "").trim().toLowerCase();
    const input = String(req.body?.input || "");

    if (!code.trim() || !languageInput) {
      return res.status(400).json({ error: "code and language are required" });
    }

    const result = await runForApi(languageInput, code, input);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.post("/session/create", (req, res, next) => {
  try {
    if (!authorizeRunnerRequest(req, { allowSessionToken: false })) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const session = createSession(req.body?.language);
    res.status(201).json({
      sessionId: session.id,
      language: session.language,
      websocketPath: `${WS_PATH}?sessionId=${session.id}`,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/session/run", async (req, res, next) => {
  try {
    const auth = authorizeRunnerRequest(req, {
      allowSessionToken: true,
      expectedSessionId: req.body?.sessionId,
    });
    if (!auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const session = ensureSession(req.body?.sessionId);
    const result = await executeCode(session, req.body?.code);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.delete("/session/:id", (req, res, next) => {
  try {
    const auth = authorizeRunnerRequest(req, {
      allowSessionToken: true,
      expectedSessionId: req.params.id,
    });
    if (!auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    ensureSession(req.params.id);
    destroySession(req.params.id, "deleted_by_client");
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((error, req, res, _next) => {
  const { statusCode, payload } = buildRunnerErrorPayload(error, req);
  res.status(statusCode).json(payload);
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: WS_PATH });

function attachSocketToSession(ws, sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    sendWebSocket(ws, { type: "error", error: "Session not found" });
    try {
      ws.close(1008, "Session not found");
    } catch (_error) {
      ws.terminate();
    }
    return false;
  }

  session.sockets.add(ws);
  ws.sessionId = sessionId;
  touchSession(session);
  sendWebSocket(ws, {
    type: "attached",
    session: serializeSession(session),
  });
  return true;
}

wss.on("connection", (ws, req) => {
  const auth = authorizeRunnerRequest(req, { allowSessionToken: true });
  if (!auth) {
    try {
      ws.close(1008, "Unauthorized");
    } catch (_error) {
      ws.terminate();
    }
    return;
  }

  ws.isAlive = true;
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const initialSessionId = url.searchParams.get("sessionId");
  ws.authType = auth.type;
  ws.authSessionId = auth.token?.sessionId || "";
  if (initialSessionId) {
    if (ws.authType === "session-token" && ws.authSessionId && ws.authSessionId !== initialSessionId) {
      sendWebSocket(ws, { type: "error", error: "Session token does not match this session" });
      ws.close(1008, "Unauthorized");
      return;
    }
    if (!attachSocketToSession(ws, initialSessionId)) {
      return;
    }
  }

  ws.on("message", async (rawMessage) => {
    let payload;
    try {
      payload = JSON.parse(rawMessage.toString());
    } catch (_error) {
      sendWebSocket(ws, { type: "error", error: "Invalid JSON message" });
      return;
    }

    try {
      if (payload.type === "ping") {
        sendWebSocket(ws, { type: "pong" });
        return;
      }

      if (payload.type === "attach") {
        if (ws.authType === "session-token" && ws.authSessionId && ws.authSessionId !== payload.sessionId) {
          sendWebSocket(ws, { type: "error", error: "Session token does not match this session" });
          return;
        }
        attachSocketToSession(ws, payload.sessionId);
        return;
      }

      const session = ensureSession(payload.sessionId || ws.sessionId);

      if (payload.type === "run") {
        if (!session.sockets.has(ws)) {
          session.sockets.add(ws);
          ws.sessionId = session.id;
        }

        await executeCode(session, payload.code ?? "");
        return;
      }

      if (payload.type === "input") {
        if (!session.sockets.has(ws)) {
          session.sockets.add(ws);
          ws.sessionId = session.id;
        }

        sendInputToRun(session, String(payload.value ?? ""));
        return;
      }

      if (payload.type === "stop") {
        if (!session.sockets.has(ws)) {
          session.sockets.add(ws);
          ws.sessionId = session.id;
        }

        stopCurrentRun(session);
        return;
      }

      sendWebSocket(ws, {
        type: "error",
        error: "Unsupported message type",
      });
    } catch (error) {
      sendWebSocket(ws, {
        type: "error",
        error: error.message || "WebSocket request failed",
      });
    }
  });

  ws.on("close", () => {
    const session = sessions.get(ws.sessionId);
    if (session) {
      session.sockets.delete(ws);
      touchSession(session);
    }
  });
});

const wsHeartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, 30_000);
wsHeartbeat.unref();

const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const session of sessions.values()) {
    if (session.currentRun) {
      continue;
    }

    if (now - session.lastActivityAt > SESSION_IDLE_TIMEOUT_MS) {
      destroySession(session.id, "idle_timeout");
    }
  }
}, CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

function shutdown(signal) {
  log("info", "Shutdown requested", { signal });
  clearInterval(wsHeartbeat);
  clearInterval(cleanupTimer);
  wss.close();

  for (const sessionId of [...sessions.keys()]) {
    destroySession(sessionId, `shutdown:${signal}`);
  }

  server.close(() => {
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("uncaughtException", (error) => {
  log("error", "Uncaught exception", {
    error: error.message,
    stack: error.stack,
  });
});
process.on("unhandledRejection", (reason) => {
  log("error", "Unhandled rejection", {
    reason: reason instanceof Error ? reason.message : String(reason),
  });
});

server.listen(PORT, HOST, () => {
  log("info", "Server listening", {
    host: HOST,
    port: PORT,
    websocketPath: WS_PATH,
    pythonCommand: PYTHON_COMMAND,
  });
});
