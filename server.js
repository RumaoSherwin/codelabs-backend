const express = require("express");
const cors = require("cors");
const http = require("http");
const { spawn, spawnSync } = require("child_process");
const { randomUUID } = require("crypto");
const { WebSocketServer } = require("ws");

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const WS_PATH = process.env.WS_PATH || "/ws";
const JSON_LIMIT = process.env.JSON_LIMIT || "256kb";
const MAX_CODE_LENGTH = Number(process.env.MAX_CODE_LENGTH) || 100_000;
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS) || 8;
const RUN_TIMEOUT_MS = Number(process.env.RUN_TIMEOUT_MS) || 20_000;
const SESSION_IDLE_TIMEOUT_MS =
  Number(process.env.SESSION_IDLE_TIMEOUT_MS) || 10 * 60 * 1000;
const CLEANUP_INTERVAL_MS =
  Number(process.env.CLEANUP_INTERVAL_MS) || 60 * 1000;
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

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

const PYTHON_COMMAND = detectPythonCommand();
const NODE_COMMAND = process.execPath;
const sessions = new Map();

function createLineParser(onMessage) {
  let buffer = "";

  return (chunk) => {
    buffer += chunk.toString();

    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      if (line) {
        try {
          onMessage(JSON.parse(line));
        } catch (error) {
          log("error", "Failed to parse worker message", {
            line,
            error: error.message,
          });
        }
      }

      newlineIndex = buffer.indexOf("\n");
    }
  };
}

function getLanguageConfig(language) {
  const normalized = String(language || "").trim().toLowerCase();

  if (normalized === "python") {
    if (!PYTHON_COMMAND) {
      throw new Error("Python is not installed on this server");
    }

    return {
      language: "python",
      command: PYTHON_COMMAND,
      args: ["-u", "-c", PYTHON_WORKER],
      env: {
        PYTHONUNBUFFERED: "1",
      },
    };
  }

  if (normalized === "javascript" || normalized === "node" || normalized === "js") {
    return {
      language: "javascript",
      command: NODE_COMMAND,
      args: ["-e", NODE_WORKER],
      env: {
        NODE_NO_WARNINGS: "1",
      },
    };
  }

  throw new Error("Unsupported language. Use 'python' or 'javascript'.");
}

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

function finishRun(session, status, error = null) {
  if (!session.currentRun) {
    return;
  }

  const { timer, resolve, reject, outputChunks, stderrChunks, stdoutChunks } =
    session.currentRun;

  clearTimeout(timer);
  const output = outputChunks.join("");
  const stdout = stdoutChunks.join("");
  const stderr = stderrChunks.join("");

  session.currentRun = null;
  touchSession(session);

  if (status === "success") {
    resolve({ output, stdout, stderr });
    return;
  }

  const message = error?.message || "Code execution failed";
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

function destroySession(sessionId, reason = "destroyed") {
  const session = sessions.get(sessionId);
  if (!session) {
    return false;
  }

  if (session.currentRun) {
    finishRun(session, "error", new Error(`Session ${reason}`));
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

  if (!session.process.killed) {
    session.process.kill("SIGTERM");

    setTimeout(() => {
      if (!session.process.killed) {
        session.process.kill("SIGKILL");
      }
    }, 1500).unref();
  }

  log("info", "Session destroyed", { sessionId, reason });
  return true;
}

function registerSessionProcess(session) {
  const parseStdout = createLineParser((message) => {
    const { type, value = "", commandId } = message;

    if (type === "ready") {
      touchSession(session);
      return;
    }

    if (type === "stdout" || type === "stderr") {
      appendRunChunk(session, type, value);
      broadcastSession(session, {
        type: "output",
        stream: type,
        value,
        sessionId: session.id,
        commandId,
      });
      touchSession(session);
      return;
    }

    if (type === "result") {
      finishRun(session, "success");
    }
  });

  session.process.stdout.on("data", parseStdout);

  session.process.stderr.on("data", (chunk) => {
    const value = chunk.toString();
    appendRunChunk(session, "stderr", value);
    broadcastSession(session, {
      type: "output",
      stream: "stderr",
      value,
      sessionId: session.id,
    });
    touchSession(session);
  });

  session.process.on("exit", (code, signal) => {
    if (!sessions.has(session.id)) {
      return;
    }

    destroySession(session.id, `process_exit:${signal || code || 0}`);
  });

  session.process.on("error", (error) => {
    log("error", "Session process error", {
      sessionId: session.id,
      error: error.message,
    });

    if (sessions.has(session.id)) {
      destroySession(session.id, "process_error");
    }
  });
}

function createSession(language) {
  if (sessions.size >= MAX_SESSIONS) {
    throw new Error("Session limit reached. Try again after closing an idle session.");
  }

  const config = getLanguageConfig(language);
  const id = randomUUID();
  const child = spawn(config.command, config.args, {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
    env: {
      ...process.env,
      ...config.env,
    },
  });

  const session = {
    id,
    language: config.language,
    process: child,
    sockets: new Set(),
    currentRun: null,
    createdAt: Date.now(),
    lastActivityAt: Date.now(),
  };

  sessions.set(id, session);
  registerSessionProcess(session);
  log("info", "Session created", { sessionId: id, language: session.language });
  return session;
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
      timer: setTimeout(() => {
        if (session.currentRun?.commandId === commandId) {
          finishRun(session, "error", new Error("Execution timed out"));
        }
      }, RUN_TIMEOUT_MS),
    };

    session.currentRun.timer.unref();

    try {
      session.process.stdin.write(
        `${JSON.stringify({ commandId, code: trimmed })}\n`,
      );
    } catch (error) {
      finishRun(session, "error", error);
    }
  });
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
      sessionIdleTimeoutMs: SESSION_IDLE_TIMEOUT_MS,
      maxCodeLength: MAX_CODE_LENGTH,
    },
    sessions: sessions.size,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.post("/session/create", (req, res, next) => {
  try {
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
    const session = ensureSession(req.body?.sessionId);
    const result = await executeCode(session, req.body?.code);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.delete("/session/:id", (req, res, next) => {
  try {
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

app.use((error, _req, res, _next) => {
  const statusCode =
    error.type === "entity.too.large"
      ? 413
      : error.statusCode || error.status || 500;

  if (statusCode >= 500) {
    log("error", "Unhandled request error", {
      error: error.message,
      stack: error.stack,
    });
  }

  res.status(statusCode).json({
    error:
      statusCode >= 500
        ? "Internal server error"
        : error.message || "Request failed",
  });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: WS_PATH });

function attachSocketToSession(ws, sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    sendWebSocket(ws, { type: "error", error: "Session not found" });
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
  ws.isAlive = true;
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const initialSessionId = url.searchParams.get("sessionId");
  if (initialSessionId) {
    attachSocketToSession(ws, initialSessionId);
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
        attachSocketToSession(ws, payload.sessionId);
        return;
      }

      const session = ensureSession(payload.sessionId || ws.sessionId);

      if (payload.type === "run" || payload.type === "input") {
        if (!session.sockets.has(ws)) {
          session.sockets.add(ws);
          ws.sessionId = session.id;
        }

        const code = payload.code ?? payload.value ?? "";
        const result = await executeCode(session, code);
        sendWebSocket(ws, {
          type: "run_complete",
          sessionId: session.id,
          ...result,
        });
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
