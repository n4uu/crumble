// Negative: an ordinary build agent that keeps a TCP connection to its
// coordinator, reports status as JSON lines and runs build steps.
const net = require('net');
const { execFile } = require('child_process');
const os = require('os');

const sock = net.connect(7070, 'ci.example.com');
function report(status, message) {
  sock.write(JSON.stringify({ status: status, message: message, agent: os.hostname() }) + '\n');
}
sock.on('connect', () => report('connected', 'agent ready'));
setInterval(() => report('keepalive', ''), 30000);
sock.on('data', (buf) => {
  const job = JSON.parse(buf.toString());
  execFile('npm', ['run', job.script], { cwd: job.dir }, (err, out) => {
    report(err ? 'failed' : 'done', String(out).slice(0, 2000));
  });
});
