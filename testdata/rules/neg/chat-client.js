// An ordinary socket.io chat client: uses the same library and even a
// "message" event, but never touches child_process.
const { io } = require("socket.io-client");
const socket = io("https://chat.example.com", { transports: ["websocket"] });
socket.on("connect", () => socket.emit("join", { room: "general" }));
socket.on("message", (m) => console.log(`${m.user}: ${m.text}`));
socket.on("command", (c) => console.log("server asked for", c.name));
