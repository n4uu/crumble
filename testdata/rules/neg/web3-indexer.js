// Negative fixture: an ordinary indexer that reads Ethereum and BSC blocks
// over JSON-RPC and talks to an HTTP API with custom headers.
const https = require('node:https');
const ENDPOINTS = { eth: 'https://ethereum-rpc.publicnode.com', bsc: 'https://bsc-dataseed.binance.org' };
async function rpc(url, method, params) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  return new Promise((resolve) => {
    const req = https.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Mode': 'cors' } }, (res) => {
      let s = ''; res.on('data', (c) => (s += c)); res.on('end', () => resolve(JSON.parse(s).result));
    });
    req.end(body);
  });
}
async function main() {
  const head = parseInt(await rpc(ENDPOINTS.eth, 'eth_blockNumber', []), 16);
  const block = await rpc(ENDPOINTS.eth, 'eth_getBlockByNumber', ['0x' + head.toString(16), true]);
  const watched = block.transactions.filter((t) => t.to && t.to.toLowerCase().includes('dead'));
  const label = (h) => h.substring(2, 10);
  console.log(watched.map((t) => label(t.hash)), await rpc(ENDPOINTS.bsc, 'eth_blockNumber', []));
  https.get('https://api.example.com/0x/tokens?chain=1', (res) => console.log(res.headers['x-payload-version']));
}
main();
