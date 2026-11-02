// Runs build commands and reports progress over socket.io. Has
// child_process and socket.io-client, but no "command" handler feeding a
// shell and no "message" reply.
const { io } = require("socket.io-client");
const { execSync } = require("child_process");
const socket = io("http://localhost:4000");
socket.on("build", (job) => {
  const out = execSync("npm run build", { cwd: job.dir }).toString();
  socket.emit("progress", { id: job.id, out });
});
