// axios with error handling that logs the error body instead of running it.
const axios = require("axios");
async function getToken(key) {
  try {
    return (await axios.get("https://api.example.com/token/" + key)).data;
  } catch (err) {
    console.error("token failed", err.response && err.response.data);
    return null;
  }
}
module.exports = { getToken };
