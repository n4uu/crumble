// crumble sandbox prelude.
//
// Runs before the sample inside a fresh goja runtime. Everything the sample
// can reach that would touch the outside world (network, processes, files,
// timers) is replaced by a stub that records the call through
// __crumble.record() and returns something plausible enough to keep the
// sample walking down its happy path. Nothing here performs real I/O: the
// only host functions exposed are the ones on __crumble, and they read files
// only from the analyst-supplied root, never write.
(function (g) {
  "use strict";
  const host = g.__crumble;
  const PLATFORM = host.platform;
  const IS_WIN = PLATFORM === "win32";
  const HOME = IS_WIN ? "C:\\Users\\analyst" : PLATFORM === "darwin" ? "/Users/analyst" : "/home/analyst";

  // ---------------------------------------------------------------- recording

  function summarize(v, depth, seen) {
    depth = depth || 0;
    seen = seen || [];
    if (v === null || v === undefined) return v === null ? null : "[undefined]";
    const t = typeof v;
    if (t === "string") return v.length > 4096 ? v.slice(0, 4096) + "...[" + v.length + " chars]" : v;
    if (t === "number" || t === "boolean") return v;
    if (t === "bigint") return String(v) + "n";
    if (t === "symbol") return String(v);
    if (t === "function") return "[function" + (v.name ? " " + v.name : "") + "]";
    if (isBuffer(v)) return { buffer: v.length, utf8: v.toString("utf8").slice(0, 256) };
    if (seen.indexOf(v) >= 0) return "[circular]";
    if (depth >= 4) return "[object]";
    seen.push(v);
    if (typeof v.toJSON === "function" && !(v instanceof Date)) {
      try {
        return summarize(v.toJSON(), depth + 1, seen);
      } catch (e) {}
    }
    if (Array.isArray(v)) return v.slice(0, 64).map((x) => summarize(x, depth + 1, seen));
    const out = {};
    let n = 0;
    for (const k of Object.keys(v)) {
      if (n++ >= 64) break;
      let x;
      try {
        x = v[k];
      } catch (e) {
        x = "[throws]";
      }
      if (x === undefined) continue;
      out[k] = summarize(x, depth + 1, seen);
    }
    return out;
  }

  function rec(kind, data) {
    let json;
    try {
      json = JSON.stringify(summarize(data));
    } catch (e) {
      json = JSON.stringify({ unserialisable: String(e) });
    }
    host.record(kind, json);
  }

  // A stand-in for any API we don't model: every property is another ghost,
  // calling one records the full dotted path. It refuses to be a thenable so
  // `await ghost` doesn't hang.
  function ghost(path) {
    const target = function () {};
    return new Proxy(target, {
      get(t, prop) {
        if (prop === "then" || typeof prop === "symbol") return undefined;
        if (prop === "toString" || prop === "valueOf") return () => "[" + path + "]";
        if (prop === "length") return 0;
        return ghost(path + "." + String(prop));
      },
      apply(t, self, args) {
        rec("call", { target: path, args: args });
        return ghost(path + "()");
      },
      construct(t, args) {
        rec("call", { target: "new " + path, args: args });
        return ghost("new " + path);
      },
    });
  }

  // ------------------------------------------------------------------ timers

  // Virtual timers: nothing waits, callbacks run in deadline order after the
  // main script returns. Intervals fire a few times and then stop, which is
  // enough to see a beacon loop without running it forever.
  const timers = [];
  let timerSeq = 0;
  let clock = 0;
  function addTimer(fn, ms, args, repeat) {
    if (typeof fn !== "function") {
      rec("timer.string", { code: String(fn) });
      const code = String(fn);
      fn = function () {
        stage("setTimeout(string)", code);
        (0, eval)(code);
      };
    }
    const id = ++timerSeq;
    timers.push({ id: id, at: clock + (Number(ms) || 0), seq: id, fn: fn, args: args, repeat: repeat ? 3 : 0, ms: Number(ms) || 0 });
    return { id: id, ref() { return this; }, unref() { return this; }, hasRef() { return true; }, refresh() { return this; }, [Symbol.toPrimitive]() { return id; } };
  }
  function clearTimer(h) {
    const id = h && typeof h === "object" ? h.id : h;
    for (let i = 0; i < timers.length; i++) if (timers[i].id === id) timers.splice(i, 1);
  }
  g.setTimeout = (fn, ms, ...args) => addTimer(fn, ms, args, false);
  g.setInterval = (fn, ms, ...args) => addTimer(fn, ms, args, true);
  g.setImmediate = (fn, ...args) => addTimer(fn, 0, args, false);
  g.clearTimeout = g.clearInterval = g.clearImmediate = clearTimer;

  host.nextTimer = function () {
    if (timers.length === 0) return false;
    timers.sort((a, b) => a.at - b.at || a.seq - b.seq);
    const t = timers.shift();
    clock = Math.max(clock, t.at);
    if (t.repeat > 0) {
      t.repeat--;
      t.at = clock + Math.max(t.ms, 1);
      t.seq = ++timerSeq;
      timers.push(t);
    }
    t.fn.apply(undefined, t.args);
    return true;
  };

  // ------------------------------------------------------------------ Buffer

  function isBuffer(v) {
    return v instanceof Uint8Array && v.__crumbleBuffer === true;
  }
  function toBinary(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }
  function fromBinary(s) {
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i) & 0xff;
    return u8;
  }
  function wrap(u8) {
    Object.defineProperty(u8, "__crumbleBuffer", { value: true });
    u8.toString = function (enc, start, end) {
      const view = this.subarray(start || 0, end === undefined ? this.length : end);
      return host.encode(toBinary(view), String(enc || "utf8").toLowerCase());
    };
    u8.toJSON = function () {
      return { type: "Buffer", data: Array.from(this) };
    };
    u8.slice = u8.subarray = function (s, e) {
      return wrap(Uint8Array.prototype.slice.call(this, s, e));
    };
    u8.equals = function (o) {
      return toBinary(this) === toBinary(o);
    };
    u8.write = function () {
      return 0;
    };
    u8.readUInt32LE = function (o) {
      o = o || 0;
      return (this[o] | (this[o + 1] << 8) | (this[o + 2] << 16)) + this[o + 3] * 0x1000000;
    };
    u8.readUInt32BE = function (o) {
      o = o || 0;
      return this[o] * 0x1000000 + ((this[o + 1] << 16) | (this[o + 2] << 8) | this[o + 3]);
    };
    return u8;
  }
  const Buffer = {
    from(v, enc) {
      if (typeof v === "string") return wrap(fromBinary(host.decode(v, String(enc || "utf8").toLowerCase())));
      if (isBuffer(v)) return wrap(Uint8Array.prototype.slice.call(v));
      if (v instanceof ArrayBuffer) return wrap(new Uint8Array(v.slice(0)));
      if (Array.isArray(v) || v instanceof Uint8Array) return wrap(Uint8Array.from(v));
      if (v && v.type === "Buffer" && Array.isArray(v.data)) return wrap(Uint8Array.from(v.data));
      return wrap(new Uint8Array(0));
    },
    alloc(n, fill) {
      const u8 = new Uint8Array(n);
      if (typeof fill === "number") u8.fill(fill);
      return wrap(u8);
    },
    allocUnsafe(n) {
      return wrap(new Uint8Array(n));
    },
    concat(list) {
      let s = "";
      for (const b of list) s += toBinary(b);
      return wrap(fromBinary(s));
    },
    isBuffer: isBuffer,
    byteLength(s, enc) {
      return typeof s === "string" ? host.decode(s, String(enc || "utf8").toLowerCase()).length : s.length;
    },
  };
  g.Buffer = Buffer;
  g.atob = (s) => host.decode(String(s), "base64");
  g.btoa = (s) => host.encode(String(s), "base64");

  // ------------------------------------------------------------------ stages

  function stage(via, code) {
    if (typeof code !== "string") code = String(code);
    host.stage(via, code);
  }

  const realEval = g.eval;
  // Overriding eval turns direct eval into indirect eval, so staged code runs
  // in global scope instead of the caller's. Loader stages don't depend on
  // the caller's locals in anything seen so far, and the code is captured
  // either way, which is the point.
  g.eval = function (code) {
    if (typeof code !== "string") return code;
    stage("eval", code);
    return realEval(code);
  };
  const RealFunction = Function;
  const FakeFunction = function (...args) {
    const body = args.length ? String(args[args.length - 1]) : "";
    stage("Function", body);
    return RealFunction.apply(this, args);
  };
  FakeFunction.prototype = RealFunction.prototype;
  g.Function = FakeFunction;

  // ------------------------------------------------------------------ http

  function respond(client, method, url, headers, body) {
    rec("http.request", { client: client, method: String(method || "GET").toUpperCase(), url: String(url), headers: headers || {}, body: body });
    const r = host.response();
    let data = r.body;
    if (typeof data === "string" && /json/i.test(r.contentType || "")) {
      try {
        data = JSON.parse(data);
      } catch (e) {}
    }
    return { status: r.status, statusText: String(r.status), data: data, headers: { "content-type": r.contentType }, config: { url: String(url) }, ok: r.status < 400 };
  }

  function axiosLike(name) {
    function settle(res) {
      if (res.status >= 400) {
        const err = new Error("Request failed with status code " + res.status);
        err.response = res;
        err.isAxiosError = true;
        return Promise.reject(err);
      }
      return Promise.resolve(res);
    }
    const ax = function (cfg, maybe) {
      if (typeof cfg === "string") cfg = Object.assign({ url: cfg }, maybe || {});
      cfg = cfg || {};
      return settle(respond(name, cfg.method || "GET", (cfg.baseURL || "") + (cfg.url || ""), cfg.headers, cfg.data));
    };
    ["get", "delete", "head", "options"].forEach((m) => {
      ax[m] = (url, cfg) => settle(respond(name, m, ((cfg && cfg.baseURL) || "") + url, cfg && cfg.headers, undefined));
    });
    ["post", "put", "patch"].forEach((m) => {
      ax[m] = (url, data, cfg) => settle(respond(name, m, ((cfg && cfg.baseURL) || "") + url, cfg && cfg.headers, data));
    });
    ax.request = (cfg) => ax(cfg);
    ax.create = (defaults) => {
      const inst = axiosLike(name);
      const base = (defaults && defaults.baseURL) || "";
      const wrapped = function (cfg, maybe) {
        if (typeof cfg === "string") cfg = Object.assign({ url: cfg }, maybe || {});
        return inst(Object.assign({ baseURL: base }, cfg));
      };
      Object.keys(inst).forEach((k) => {
        wrapped[k] = (url, a, b) => inst[k](base + url, a, b);
      });
      return wrapped;
    };
    ax.defaults = { headers: { common: {} } };
    ax.interceptors = { request: { use() {} }, response: { use() {} } };
    ax.default = ax;
    ax.isAxiosError = (e) => !!(e && e.isAxiosError);
    return ax;
  }

  function fetchLike(url, opts) {
    opts = opts || {};
    const res = respond("fetch", opts.method || "GET", url, opts.headers, opts.body);
    const text = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    return Promise.resolve({
      ok: res.ok,
      status: res.status,
      headers: { get: (k) => res.headers[String(k).toLowerCase()] },
      text: () => Promise.resolve(text),
      json: () => Promise.resolve(typeof res.data === "string" ? JSON.parse(res.data) : res.data),
      arrayBuffer: () => Promise.resolve(fromBinary(host.decode(text, "utf8")).buffer),
      buffer: () => Promise.resolve(Buffer.from(text)),
    });
  }
  g.fetch = fetchLike;

  // Just enough of WHATWG URL for samples that build C2 addresses with it.
  g.URL = function URL(u, base) {
    let s = String(u);
    if (base !== undefined && !/^[a-z][a-z0-9+.-]*:/i.test(s)) s = String(base).replace(/\/+$/, "") + "/" + s.replace(/^\/+/, "");
    const m = /^([a-z][a-z0-9+.-]*:)\/\/(?:([^@/?#]*)@)?(\[[^\]]+\]|[^/?#:]*)(?::(\d+))?([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(s);
    if (!m) throw new TypeError("Invalid URL: " + s);
    this.protocol = m[1].toLowerCase();
    this.hostname = m[3];
    this.port = m[4] || "";
    this.host = this.hostname + (this.port ? ":" + this.port : "");
    this.pathname = m[5] || "/";
    this.search = m[6] || "";
    this.hash = m[7] || "";
    this.origin = this.protocol + "//" + this.host;
    this.href = this.origin + this.pathname + this.search + this.hash;
    this.searchParams = { get: () => null, append() {}, set() {}, toString: () => this.search.replace(/^\?/, "") };
    this.toString = () => this.href;
  };
  g.TextEncoder = function () {
    this.encode = (s) => wrap(fromBinary(host.decode(String(s), "utf8")));
  };
  g.TextDecoder = function () {
    this.decode = (u8) => host.encode(toBinary(u8 || []), "utf8");
  };

  function requestLike(opts, cb) {
    if (typeof opts === "string") opts = { url: opts };
    const res = respond("request", opts.method || "GET", opts.url || opts.uri, opts.headers, opts.body || opts.form || opts.formData);
    if (typeof cb === "function") {
      addTimer(() => cb(res.status >= 400 ? null : null, { statusCode: res.status, body: res.data, headers: res.headers }, res.data), 0, [], false);
    }
    return emitter("request");
  }
  ["get", "post", "put"].forEach((m) => {
    requestLike[m] = (opts, cb) => requestLike(Object.assign(typeof opts === "string" ? { url: opts } : opts, { method: m }), cb);
  });

  function nodeHttp(scheme) {
    function target(a, b) {
      if (typeof a === "string") return a;
      if (a && a.href) return a.href;
      a = a || {};
      return scheme + "://" + (a.hostname || a.host || "localhost") + (a.port ? ":" + a.port : "") + (a.path || "/");
    }
    function req(a, b, c) {
      const opts = typeof a === "object" && !a.href ? a : typeof b === "object" ? b : {};
      const cb = [a, b, c].find((x) => typeof x === "function");
      const url = target(a, b);
      const chunks = [];
      const r = emitter(scheme + ".ClientRequest");
      r.write = (d) => {
        chunks.push(d);
        return true;
      };
      r.end = (d) => {
        if (d) chunks.push(d);
        const res = respond(scheme, opts.method || "GET", url, opts.headers, chunks.length ? chunks.map(String).join("") : undefined);
        if (cb) {
          const msg = emitter(scheme + ".IncomingMessage");
          msg.statusCode = res.status;
          msg.headers = res.headers;
          addTimer(() => {
            cb(msg);
            msg.emit("data", Buffer.from(typeof res.data === "string" ? res.data : JSON.stringify(res.data)));
            msg.emit("end");
          }, 0, [], false);
        }
        return r;
      };
      r.setTimeout = () => r;
      r.destroy = () => r;
      return r;
    }
    return {
      request: req,
      get(a, b, c) {
        const r = req(a, b, c);
        r.end();
        return r;
      },
      Agent: function () {},
      createServer() {
        rec("http.listen", { scheme: scheme });
        return emitter("server");
      },
    };
  }

  // ------------------------------------------------------------- emitters

  function emitter(name) {
    const handlers = {};
    const e = {
      on(ev, fn) {
        (handlers[ev] = handlers[ev] || []).push(fn);
        return e;
      },
      once(ev, fn) {
        return e.on(ev, fn);
      },
      off() {
        return e;
      },
      removeListener() {
        return e;
      },
      removeAllListeners() {
        return e;
      },
      emit(ev, ...args) {
        (handlers[ev] || []).slice().forEach((fn) => {
          try {
            fn.apply(e, args);
          } catch (err) {
            rec("error", { where: name + " " + ev + " handler", message: String(err && err.stack ? err.stack : err) });
          }
        });
        return true;
      },
      pipe(dst) {
        return dst;
      },
    };
    return e;
  }

  // ----------------------------------------------------------- socket.io

  const sockets = [];
  const BUILTIN = ["connect", "disconnect", "connect_error", "error", "reconnect", "reconnect_attempt", "reconnect_error", "reconnect_failed", "ping", "pong", "close", "open"];

  function makeSocket(url, opts) {
    const handlers = {};
    const s = {
      id: "crumble-sandbox",
      connected: true,
      disconnected: false,
      auth: opts && opts.auth,
      on(ev, fn) {
        rec("socketio.on", { url: url, event: String(ev) });
        (handlers[ev] = handlers[ev] || []).push(fn);
        return s;
      },
      once(ev, fn) {
        return s.on(ev, fn);
      },
      onAny(fn) {
        rec("socketio.on", { url: url, event: "*" });
        (handlers["*"] = handlers["*"] || []).push(fn);
        return s;
      },
      off() {
        return s;
      },
      removeAllListeners() {
        return s;
      },
      emit(ev, ...args) {
        const ack = typeof args[args.length - 1] === "function" ? args.pop() : null;
        rec("socketio.emit", { url: url, event: String(ev), args: args });
        if (ack) addTimer(() => ack({ status: "ok" }), 0, [], false);
        return s;
      },
      send(...args) {
        return s.emit("message", ...args);
      },
      connect() {
        return s;
      },
      open() {
        return s;
      },
      disconnect() {
        rec("socketio.disconnect", { url: url });
        return s;
      },
      close() {
        return s.disconnect();
      },
      compress() {
        return s;
      },
      timeout() {
        return s;
      },
      volatile: null,
      io: { on() {}, opts: opts || {}, engine: { on() {}, transport: { name: "websocket" } }, reconnection() {} },
    };
    s.volatile = s;
    sockets.push({ url: url, handlers: handlers, socket: s });
    return s;
  }

  function socketIoClient() {
    const io = function (url, opts) {
      if (typeof url === "object" && url !== null) {
        opts = url;
        url = "[same origin]";
      }
      rec("socketio.connect", { url: String(url), options: opts || {} });
      return makeSocket(String(url), opts);
    };
    io.io = io;
    io.connect = io;
    io.default = io;
    io.Manager = function (url, opts) {
      return { socket: (nsp) => io(String(url) + (nsp && nsp !== "/" ? nsp : ""), opts), on() {}, open() {} };
    };
    io.Socket = function () {};
    return io;
  }

  // Probe text handed to custom events. A handler that forwards it to
  // child_process shows up in the trace as exec("echo crumble-probe").
  const PROBE = "echo crumble-probe";
  host.drive = function (probe) {
    for (const entry of sockets) {
      for (const fn of entry.handlers["connect"] || []) {
        try {
          fn.call(entry.socket);
        } catch (err) {
          rec("error", { where: "socket.io connect handler", message: String(err) });
        }
      }
      if (!probe) continue;
      for (const ev of Object.keys(entry.handlers)) {
        if (BUILTIN.indexOf(ev) >= 0) continue;
        const payload = { message: PROBE, cmd: PROBE, command: PROBE, data: PROBE, toString: () => PROBE };
        for (const fn of entry.handlers[ev]) {
          rec("probe", { url: entry.url, event: ev });
          try {
            if (ev === "*") fn.call(entry.socket, "command", payload);
            else fn.call(entry.socket, payload);
          } catch (err) {
            rec("error", { where: "socket.io " + ev + " handler", message: String(err) });
          }
        }
      }
    }
  };

  // ------------------------------------------------------------ processes

  function childProcess() {
    function proc(cmd) {
      const p = emitter("ChildProcess");
      p.pid = 4242;
      p.stdout = emitter("stdout");
      p.stderr = emitter("stderr");
      p.stdin = { write() {}, end() {} };
      p.kill = () => true;
      p.unref = () => {};
      addTimer(() => p.emit("close", 0), 0, [], false);
      return p;
    }
    const fake = (cmd) => host.fakeOutput(String(cmd));
    return {
      exec(cmd, opts, cb) {
        cb = typeof opts === "function" ? opts : cb;
        rec("exec", { api: "exec", command: String(cmd), options: typeof opts === "object" ? opts : undefined });
        const out = fake(cmd);
        if (cb) addTimer(() => cb(null, out, ""), 0, [], false);
        return proc(cmd);
      },
      execSync(cmd, opts) {
        rec("exec", { api: "execSync", command: String(cmd), options: opts });
        const out = fake(cmd);
        return opts && opts.encoding ? out : Buffer.from(out);
      },
      spawn(cmd, args, opts) {
        rec("exec", { api: "spawn", command: String(cmd), args: args, options: opts });
        return proc(cmd);
      },
      spawnSync(cmd, args, opts) {
        rec("exec", { api: "spawnSync", command: String(cmd), args: args, options: opts });
        return { status: 0, stdout: Buffer.from(fake(cmd)), stderr: Buffer.from("") };
      },
      execFile(cmd, args, opts, cb) {
        cb = [args, opts, cb].find((x) => typeof x === "function");
        rec("exec", { api: "execFile", command: String(cmd), args: Array.isArray(args) ? args : undefined });
        if (cb) addTimer(() => cb(null, fake(cmd), ""), 0, [], false);
        return proc(cmd);
      },
      execFileSync(cmd, args) {
        rec("exec", { api: "execFileSync", command: String(cmd), args: args });
        return Buffer.from(fake(cmd));
      },
      fork(mod, args) {
        rec("exec", { api: "fork", command: String(mod), args: args });
        return proc(mod);
      },
    };
  }

  // ------------------------------------------------------------------- fs

  function enoent(p) {
    const e = new Error("ENOENT: no such file or directory, open '" + p + "'");
    e.code = "ENOENT";
    return e;
  }
  function fsModule() {
    const read = (api, p) => {
      const body = host.readFile(String(p));
      rec("fs.read", { api: api, path: String(p), found: body !== null });
      return body;
    };
    const fs = {
      existsSync(p) {
        rec("fs.read", { api: "existsSync", path: String(p), found: host.readFile(String(p)) !== null });
        return host.readFile(String(p)) !== null;
      },
      readFileSync(p, enc) {
        const body = read("readFileSync", p);
        if (body === null) throw enoent(p);
        return enc ? body : Buffer.from(body);
      },
      readFile(p, enc, cb) {
        cb = typeof enc === "function" ? enc : cb;
        const body = read("readFile", p);
        if (cb) addTimer(() => (body === null ? cb(enoent(p)) : cb(null, typeof enc === "string" ? body : Buffer.from(body))), 0, [], false);
      },
      readdirSync(p) {
        rec("fs.read", { api: "readdirSync", path: String(p), found: false });
        return [];
      },
      readdir(p, a, b) {
        const cb = typeof a === "function" ? a : b;
        rec("fs.read", { api: "readdir", path: String(p), found: false });
        if (cb) addTimer(() => cb(null, []), 0, [], false);
      },
      statSync(p) {
        rec("fs.read", { api: "statSync", path: String(p), found: false });
        throw enoent(p);
      },
      stat(p, cb) {
        rec("fs.read", { api: "stat", path: String(p), found: false });
        if (typeof cb === "function") addTimer(() => cb(enoent(p)), 0, [], false);
      },
      createReadStream(p) {
        rec("fs.read", { api: "createReadStream", path: String(p), found: false });
        return emitter("ReadStream");
      },
      createWriteStream(p) {
        rec("fs.write", { api: "createWriteStream", path: String(p) });
        const s = emitter("WriteStream");
        s.write = () => true;
        s.end = () => s;
        return s;
      },
      accessSync(p) {
        throw enoent(p);
      },
    };
    ["writeFileSync", "appendFileSync", "writeFile", "appendFile"].forEach((api) => {
      fs[api] = (p, data, a, b) => {
        rec("fs.write", { api: api, path: String(p), size: data && data.length, preview: typeof data === "string" ? data.slice(0, 256) : undefined });
        const cb = [a, b].find((x) => typeof x === "function");
        if (cb) addTimer(() => cb(null), 0, [], false);
      };
    });
    ["mkdirSync", "mkdir", "rmSync", "rm", "unlinkSync", "unlink", "copyFileSync", "copyFile", "renameSync", "rename", "chmodSync", "chmod", "rmdirSync"].forEach((api) => {
      fs[api] = (p, q, cb) => {
        rec("fs.write", { api: api, path: String(p), to: typeof q === "string" ? q : undefined });
        const fn = [q, cb].find((x) => typeof x === "function");
        if (fn) addTimer(() => fn(null), 0, [], false);
      };
    });
    fs.watch = () => emitter("FSWatcher");
    fs.constants = { F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1 };
    fs.promises = {
      readFile: (p, enc) => {
        const body = read("promises.readFile", p);
        return body === null ? Promise.reject(enoent(p)) : Promise.resolve(enc ? body : Buffer.from(body));
      },
      writeFile: (p, data) => {
        rec("fs.write", { api: "promises.writeFile", path: String(p), size: data && data.length });
        return Promise.resolve();
      },
      readdir: (p) => {
        rec("fs.read", { api: "promises.readdir", path: String(p), found: false });
        return Promise.resolve([]);
      },
      mkdir: (p) => {
        rec("fs.write", { api: "promises.mkdir", path: String(p) });
        return Promise.resolve();
      },
      access: (p) => Promise.reject(enoent(p)),
      stat: (p) => Promise.reject(enoent(p)),
    };
    return fs;
  }

  // ------------------------------------------------------------- os, path

  const osModule = {
    platform: () => PLATFORM,
    type: () => (IS_WIN ? "Windows_NT" : PLATFORM === "darwin" ? "Darwin" : "Linux"),
    release: () => (IS_WIN ? "10.0.19045" : PLATFORM === "darwin" ? "23.4.0" : "6.1.0-18-amd64"),
    arch: () => "x64",
    hostname: () => "CRUMBLE-SANDBOX",
    homedir: () => HOME,
    tmpdir: () => (IS_WIN ? HOME + "\\AppData\\Local\\Temp" : "/tmp"),
    userInfo: () => ({ username: "analyst", uid: 1000, gid: 1000, homedir: HOME, shell: IS_WIN ? null : "/bin/bash" }),
    cpus: () => [{ model: "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz", speed: 2904, times: {} }],
    totalmem: () => 17179869184,
    freemem: () => 8589934592,
    uptime: () => 86400,
    networkInterfaces: () => ({}),
    loadavg: () => [0, 0, 0],
    endianness: () => "LE",
    version: () => "",
    EOL: IS_WIN ? "\r\n" : "\n",
  };

  function pathModule(win) {
    const sep = win ? "\\" : "/";
    const norm = (p) => (win ? String(p).replace(/\//g, "\\") : String(p));
    const join = (...parts) =>
      norm(parts.filter((x) => x !== "" && x !== undefined && x !== null).join(sep)).replace(win ? /\\+/g : /\/+/g, sep);
    const p = {
      sep: sep,
      delimiter: win ? ";" : ":",
      join: join,
      resolve: (...parts) => {
        let out = "";
        for (const part of parts) {
          const s = norm(part);
          if (win ? /^[A-Za-z]:/.test(s) || s.startsWith("\\") : s.startsWith("/")) out = s;
          else out = out ? join(out, s) : s;
        }
        return out || (win ? "C:\\" : "/");
      },
      normalize: norm,
      basename: (s, ext) => {
        const b = norm(s).split(sep).pop();
        return ext && b.endsWith(ext) ? b.slice(0, -ext.length) : b;
      },
      dirname: (s) => {
        const parts = norm(s).split(sep);
        parts.pop();
        return parts.join(sep) || ".";
      },
      extname: (s) => {
        const b = norm(s).split(sep).pop();
        const i = b.lastIndexOf(".");
        return i > 0 ? b.slice(i) : "";
      },
      isAbsolute: (s) => (win ? /^[A-Za-z]:\\/.test(norm(s)) : String(s).startsWith("/")),
      relative: (a, b) => b,
      parse: (s) => ({ root: "", dir: p.dirname(s), base: p.basename(s), ext: p.extname(s), name: p.basename(s, p.extname(s)) }),
      format: (o) => join(o.dir || "", o.base || (o.name || "") + (o.ext || "")),
    };
    return p;
  }

  // --------------------------------------------------------------- crypto

  function cryptoModule() {
    const hash = (alg) => {
      let data = "";
      const h = {
        update(d) {
          data += isBuffer(d) ? toBinary(d) : host.decode(String(d), "utf8");
          return h;
        },
        digest(enc) {
          const out = host.digest(String(alg), data);
          return enc ? host.encode(out, String(enc)) : Buffer.from(out, "latin1");
        },
      };
      return h;
    };
    const keyText = (k) => (isBuffer(k) ? host.encode(toBinary(k), "hex") : String(k));
    const cipher = (kind) => (alg, key, iv) => {
      rec("crypto." + kind, { algorithm: String(alg), key: keyText(key), iv: iv === undefined || iv === null ? null : keyText(iv) });
      return ghost("crypto." + kind + "(" + alg + ")");
    };
    return {
      createHash: hash,
      createHmac: (alg) => hash(alg),
      randomBytes: (n) => Buffer.alloc(n, 0x41),
      randomUUID: () => "00000000-0000-4000-8000-000000000000",
      randomInt: (a, b) => (b === undefined ? 0 : a),
      createDecipheriv: cipher("decipher"),
      createDecipher: cipher("decipher"),
      createCipheriv: cipher("cipher"),
      createCipher: cipher("cipher"),
      webcrypto: ghost("crypto.webcrypto"),
    };
  }

  // -------------------------------------------------------------- process

  const env = {
    USERPROFILE: IS_WIN ? HOME : undefined,
    APPDATA: IS_WIN ? HOME + "\\AppData\\Roaming" : undefined,
    LOCALAPPDATA: IS_WIN ? HOME + "\\AppData\\Local" : undefined,
    TEMP: IS_WIN ? HOME + "\\AppData\\Local\\Temp" : undefined,
    HOME: IS_WIN ? undefined : HOME,
    USER: "analyst",
    USERNAME: "analyst",
    COMPUTERNAME: "CRUMBLE-SANDBOX",
    PATH: IS_WIN ? "C:\\Windows\\system32;C:\\Program Files\\nodejs" : "/usr/local/bin:/usr/bin:/bin",
  };
  const ExitSignal = function (code) {
    this.code = code;
  };
  const processObj = {
    platform: PLATFORM,
    arch: "x64",
    pid: 31337,
    ppid: 31336,
    version: "v20.11.1",
    versions: { node: "20.11.1", v8: "11.3.244.8" },
    argv: ["node", host.filename],
    execArgv: [],
    execPath: IS_WIN ? "C:\\Program Files\\nodejs\\node.exe" : "/usr/bin/node",
    env: new Proxy(env, {
      get(t, k) {
        if (typeof k === "string" && !(k in t)) rec("env.read", { name: k });
        return t[k];
      },
    }),
    cwd: () => host.dirname,
    chdir() {},
    exit(code) {
      rec("process.exit", { code: code });
      throw new ExitSignal(code);
    },
    on() {
      return processObj;
    },
    once() {
      return processObj;
    },
    off() {
      return processObj;
    },
    emit() {
      return false;
    },
    nextTick: (fn, ...args) => Promise.resolve().then(() => fn(...args)),
    hrtime: Object.assign(() => [0, 0], { bigint: () => 0 }),
    uptime: () => 1,
    memoryUsage: () => ({ rss: 0, heapTotal: 0, heapUsed: 0 }),
    cpuUsage: () => ({ user: 0, system: 0 }),
    stdout: { write() {}, isTTY: false },
    stderr: { write() {}, isTTY: false },
    stdin: emitter("stdin"),
    kill() {},
    title: "node",
  };
  g.process = processObj;
  g.__crumbleExit = ExitSignal;

  g.console = {};
  ["log", "info", "warn", "error", "debug", "trace"].forEach((lvl) => {
    g.console[lvl] = (...args) => rec("console", { level: lvl, args: args });
  });

  // -------------------------------------------------------------- require

  const builtins = {
    "socket.io-client": socketIoClient,
    axios: () => axiosLike("axios"),
    "node-fetch": () => Object.assign(fetchLike, { default: fetchLike }),
    request: () => requestLike,
    http: () => nodeHttp("http"),
    https: () => nodeHttp("https"),
    child_process: childProcess,
    fs: fsModule,
    "fs/promises": () => fsModule().promises,
    os: () => osModule,
    path: () => pathModule(IS_WIN),
    crypto: cryptoModule,
    buffer: () => ({ Buffer: Buffer }),
    events: () => {
      const E = function () {
        Object.assign(this, emitter("EventEmitter"));
      };
      E.EventEmitter = E;
      return E;
    },
    util: () => ({
      promisify: (fn) => (...args) => new Promise((res, rej) => fn(...args, (e, v) => (e ? rej(e) : res(v)))),
      inspect: (v) => JSON.stringify(summarize(v)),
      format: (...a) => a.map(String).join(" "),
      inherits() {},
      TextDecoder: function () {
        this.decode = (u8) => host.encode(toBinary(u8 || []), "utf8");
      },
    }),
    url: () => ({ URL: g.URL, parse: (u) => ({ href: u }) }),
    querystring: () => ({ stringify: (o) => Object.keys(o).map((k) => k + "=" + o[k]).join("&"), parse: () => ({}) }),
    zlib: () => ghost("zlib"),
    net: () => ({
      connect(a, b) {
        rec("net.connect", { target: typeof a === "object" ? (a.host || "") + ":" + a.port : String(b || "") + ":" + String(a) });
        return emitter("Socket");
      },
      createConnection(a, b) {
        return this.connect(a, b);
      },
      Socket: function () {
        const s = emitter("Socket");
        s.connect = (port, h) => {
          rec("net.connect", { target: String(h) + ":" + String(port) });
          return s;
        };
        s.write = () => true;
        s.end = () => s;
        return s;
      },
    }),
    "form-data": () => {
      const FD = function () {
        const parts = [];
        this.append = (k, v, o) => {
          parts.push({ field: k, filename: o && (o.filename || o), value: isBuffer(v) ? "[buffer " + v.length + "]" : typeof v === "string" ? v.slice(0, 256) : summarize(v) });
          rec("formdata.append", { field: k, filename: o && (o.filename || o) });
        };
        this.getHeaders = () => ({ "content-type": "multipart/form-data; boundary=crumble" });
        this.getBoundary = () => "crumble";
        this.toJSON = () => ({ multipart: parts });
        this.pipe = (d) => d;
        this.submit = (url) => respond("form-data", "POST", url, {}, { multipart: parts });
      };
      return FD;
    },
    module: () => ({ createRequire: () => requireFrom(host.dirname), _compile: compileShim }),
  };

  function compileShim(code, filename) {
    stage("Module._compile", code);
    return runModule(code, String(filename || "[memory]"));
  }

  const cache = {};
  function runModule(code, filename) {
    const dirname = filename.replace(/[\\/][^\\/]*$/, "") || host.dirname;
    const mod = { exports: {}, filename: filename, id: filename, loaded: false, paths: [] };
    mod.constructor = ModuleCtor;
    const fn = (0, realEval)("(function (exports, require, module, __filename, __dirname) {" + code + "\n})");
    fn.call(mod.exports, mod.exports, requireFrom(dirname), mod, filename, dirname);
    mod.loaded = true;
    return mod.exports;
  }
  // new module.constructor()._compile(src, name) is how some loaders run a
  // string as a CommonJS module without touching disk.
  function ModuleCtor() {
    this.exports = {};
    this.paths = [];
    this._compile = (code, filename) => {
      this.exports = compileShim(code, filename);
      return this.exports;
    };
  }

  function requireFrom(dirname) {
    const req = function (name) {
      name = String(name);
      const bare = name.replace(/^node:/, "");
      rec("require", { module: name });
      if (Object.prototype.hasOwnProperty.call(builtins, bare)) {
        if (!(bare in cache)) cache[bare] = builtins[bare]();
        return cache[bare];
      }
      if (/^(\.{1,2}[\\/]|[\\/]|[A-Za-z]:\\)/.test(name)) {
        const found = host.resolve(dirname, name);
        if (found !== null) {
          if (found.path in cache) return cache[found.path];
          if (/\.json$/i.test(found.path)) return (cache[found.path] = JSON.parse(found.code));
          stage("require " + found.path, found.code);
          cache[found.path] = {};
          return (cache[found.path] = runModule(found.code, found.path));
        }
      }
      return ghost("require('" + name + "')");
    };
    req.resolve = (n) => n;
    req.cache = {};
    req.main = { filename: host.filename };
    return req;
  }

  // Staged code runs through indirect eval (see the eval override above) and
  // so sees global scope, not the module wrapper. Node code evaluated from a
  // module expects require/module/__dirname to resolve, so provide them
  // globally as well.
  g.require = requireFrom(host.dirname);
  g.module = { exports: {}, filename: host.filename, constructor: ModuleCtor, paths: [] };
  g.exports = g.module.exports;
  g.__dirname = host.dirname;
  g.__filename = host.filename;

  g.__crumbleMain = function (code) {
    return runModule(code, host.filename);
  };
  g.global = g;
  g.globalThis = g;
})(this);
