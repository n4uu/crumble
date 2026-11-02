// Package extract turns a JavaScript sample into a configuration report by
// combining static string recovery (jsdeob) with emulation (sandbox).
package extract

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/n4uu/crumble/internal/jsdeob"
	"github.com/n4uu/crumble/internal/sandbox"
)

// Report is the extracted configuration of one sample.
type Report struct {
	File   string `json:"file"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5"`

	Obfuscation *Obfuscation `json:"obfuscation,omitempty"`

	Verdict      string           `json:"verdict"`
	Roles        []Finding        `json:"roles,omitempty"`
	Capabilities []Finding        `json:"capabilities,omitempty"`
	C2           []Endpoint       `json:"c2,omitempty"`
	SocketIO     []SocketIO       `json:"socketio,omitempty"`
	Identity     map[string]any   `json:"identity,omitempty"`
	Commands     []string         `json:"commands,omitempty"`
	Files        []string         `json:"files,omitempty"`
	Crypto       []map[string]any `json:"crypto,omitempty"`
	Stages       []sandbox.Stage  `json:"stages,omitempty"`
	Indicators   []Indicator      `json:"indicators,omitempty"`
	Modules      []string         `json:"modules,omitempty"`
	Notes        []string         `json:"notes,omitempty"`

	Deobfuscated string         `json:"-"`
	Trace        *sandbox.Trace `json:"-"`
}

// Obfuscation summarises what jsdeob found and undid.
type Obfuscation struct {
	Tool      string `json:"tool"`
	Encoding  string `json:"encoding"`
	ArraySize int    `json:"string_array_size"`
	Rotated   bool   `json:"rotated"`
	Wrappers  int    `json:"wrappers"`
	Aliases   int    `json:"aliases"`
	Resolved  int    `json:"calls_resolved"`
	Failed    int    `json:"calls_failed,omitempty"`
}

// Finding is a role or capability with the evidence that triggered it.
type Finding struct {
	Name       string   `json:"name"`
	Confidence string   `json:"confidence"` // "observed" (emulation) or "static"
	Evidence   []string `json:"evidence"`
}

// Endpoint is one C2 or staging address.
type Endpoint struct {
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Port    int      `json:"port,omitempty"`
	Path    string   `json:"path,omitempty"`
	Role    string   `json:"role"`
	Methods []string `json:"methods,omitempty"`
	Source  string   `json:"source"` // "emulation" or "static"
}

// SocketIO is a socket.io connection the sample opened.
type SocketIO struct {
	URL      string         `json:"url"`
	Options  map[string]any `json:"options,omitempty"`
	Handlers []string       `json:"handlers"`
	Emits    []string       `json:"emits"`
	// CommandEvent is the handler that passed the probe to a process API;
	// ReplyEvent is what it answered with. Both empty if probing was off
	// or nothing reached child_process.
	CommandEvent string `json:"command_event,omitempty"`
	ReplyEvent   string `json:"reply_event,omitempty"`
	// CommandExec is true when the probe payload reached a child_process
	// API, i.e. the handler is a remote shell rather than just an echo.
	CommandExec bool `json:"command_exec,omitempty"`
}

// Options configures Extract.
type Options struct {
	Name      string
	Platforms []string // emulate once per platform; default win32
	Root      string
	Response  sandbox.Response
	NoEmulate bool
	Budget    time.Duration
}

// Extract analyses one script.
func Extract(src []byte, opts Options) (*Report, error) {
	if len(opts.Platforms) == 0 {
		opts.Platforms = []string{"win32"}
	}
	sha := sha256.Sum256(src)
	md := md5.Sum(src)
	rep := &Report{
		File:   opts.Name,
		Size:   len(src),
		SHA256: hex.EncodeToString(sha[:]),
		MD5:    hex.EncodeToString(md[:]),
	}

	code := string(src)
	d, err := jsdeob.Deobfuscate(code, jsdeob.Options{})
	switch {
	case d == nil:
		return nil, err
	case errors.Is(err, jsdeob.ErrNoStringArray):
		rep.Notes = append(rep.Notes, "no javascript-obfuscator string array; analysed as-is")
	case err != nil:
		rep.Notes = append(rep.Notes, "string array found but bootstrap failed: "+err.Error())
	default:
		rep.Obfuscation = &Obfuscation{
			Tool: "javascript-obfuscator", Encoding: d.Encoding, ArraySize: d.ArraySize,
			Rotated: d.Rotated, Wrappers: d.Wrappers, Aliases: d.Aliases,
			Resolved: d.Replaced, Failed: d.Failed,
		}
	}
	rep.Deobfuscated = d.Source

	var traces []*sandbox.Trace
	if !opts.NoEmulate {
		for _, p := range opts.Platforms {
			tr, err := sandbox.Run(code, sandbox.Options{
				Platform: p, Root: opts.Root, Probe: true,
				Response: opts.Response, Budget: opts.Budget, Filename: baseName(opts.Name),
			})
			if err != nil {
				return nil, err
			}
			if tr.TimedOut {
				rep.Notes = append(rep.Notes, p+": emulation hit its time budget; trace is partial")
			}
			if tr.Error != "" {
				rep.Notes = append(rep.Notes, p+": sample threw: "+firstLine(tr.Error))
			}
			traces = append(traces, tr)
		}
		rep.Trace = merge(traces)
	}

	strs := d.Strings
	if rep.Trace != nil {
		strs = append(strs, traceStrings(rep.Trace)...)
	}
	rep.Indicators = indicators(strs)

	if rep.Trace != nil {
		rep.fromTrace(rep.Trace)
	}
	rep.addStaticEndpoints()
	rep.Capabilities = capabilities(d.Strings, rep)
	rep.Roles = roles(d, rep)
	rep.Verdict = verdict(rep)
	return rep, nil
}

func baseName(p string) string {
	if p == "" {
		return "index.js"
	}
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

// merge concatenates traces from several platform runs.
func merge(ts []*sandbox.Trace) *sandbox.Trace {
	out := &sandbox.Trace{}
	for _, t := range ts {
		out.Events = append(out.Events, t.Events...)
		out.Stages = append(out.Stages, t.Stages...)
		out.TimedOut = out.TimedOut || t.TimedOut
	}
	return out
}

// traceStrings returns every string value the sample produced at runtime.
// It catches C2 addresses that are assembled from pieces and never exist as
// a single literal.
func traceStrings(t *sandbox.Trace) []string {
	var out []string
	var visit func(v any)
	visit = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			for _, y := range x {
				visit(y)
			}
		case []any:
			for _, y := range x {
				visit(y)
			}
		}
	}
	for _, e := range t.Events {
		visit(e.Data)
	}
	return out
}

func (r *Report) fromTrace(t *sandbox.Trace) {
	mods := map[string]bool{}
	sockets := map[string]*SocketIO{}
	var sockOrder []string
	endpoints := map[string]*Endpoint{}
	var epOrder []string
	files := map[string]bool{}
	cmds := map[string]bool{}
	lastProbe := ""
	lastProbeURL := ""

	addEP := func(raw, role, method string) {
		ep, key, ok := endpoint(raw)
		if !ok {
			return
		}
		if have, ok := endpoints[key]; ok {
			if method != "" && !contains(have.Methods, method) {
				have.Methods = append(have.Methods, method)
			}
			if rank(role) > rank(have.Role) {
				have.Role = role
			}
			return
		}
		ep.Role = role
		ep.Source = "emulation"
		if method != "" {
			ep.Methods = []string{method}
		}
		endpoints[key] = &ep
		epOrder = append(epOrder, key)
	}

	for i, e := range t.Events {
		str := func(k string) string { s, _ := e.Data[k].(string); return s }
		switch e.Kind {
		case "require":
			mods[str("module")] = true
		case "socketio.connect":
			u := str("url")
			if _, ok := sockets[u]; !ok {
				opts, _ := e.Data["options"].(map[string]any)
				sockets[u] = &SocketIO{URL: u, Options: opts}
				sockOrder = append(sockOrder, u)
			}
			addEP(u, "socket.io C2", "")
		case "socketio.on":
			if s := sockets[str("url")]; s != nil && !contains(s.Handlers, str("event")) {
				s.Handlers = append(s.Handlers, str("event"))
			}
		case "socketio.emit":
			s := sockets[str("url")]
			if s == nil {
				continue
			}
			ev := str("event")
			if !contains(s.Emits, ev) {
				s.Emits = append(s.Emits, ev)
			}
			if lastProbe != "" && lastProbeURL == s.URL && s.ReplyEvent == "" {
				if s.CommandEvent == lastProbe || mentionsProbe(e.Data["args"]) {
					s.CommandEvent = lastProbe
					s.ReplyEvent = ev
				}
			}
			if lastProbe == "" && r.Identity == nil {
				// The first thing sent after connect is the victim
				// registration: campaign id, uid, hostname, OS.
				if args, ok := e.Data["args"].([]any); ok && len(args) > 0 {
					if m, ok := args[0].(map[string]any); ok {
						r.Identity = m
						r.Identity["_event"] = ev
					}
				}
			}
		case "probe":
			lastProbe = str("event")
			lastProbeURL = str("url")
		case "exec":
			c := str("command")
			if args, ok := e.Data["args"].([]any); ok && len(args) > 0 {
				parts := []string{c}
				for _, a := range args {
					parts = append(parts, fmt.Sprint(a))
				}
				c = strings.Join(parts, " ")
			}
			if lastProbe != "" && strings.Contains(c, "crumble-probe") {
				if s := sockets[lastProbeURL]; s != nil && (s.CommandEvent == "" || s.CommandEvent == lastProbe) {
					s.CommandEvent = lastProbe
					s.CommandExec = true
				}
				continue // our own probe, not the sample's
			}
			if !cmds[c] {
				cmds[c] = true
				r.Commands = append(r.Commands, c)
			}
		case "http.request":
			role := "http"
			if stagedAfter(t.Events, i) {
				role = "stage delivery"
			}
			u := str("url")
			if p := pathOf(u); p != "" {
				switch {
				case strings.Contains(p, "/cldbs"):
					role = "browser data upload"
				case strings.Contains(p, "/upload"):
					role = "file upload"
				}
			}
			addEP(u, role, str("method"))
		case "net.connect":
			addEP("tcp://"+str("target"), "raw tcp", "")
		case "fs.write":
			files[str("api")+" "+str("path")] = true
		case "crypto.decipher", "crypto.cipher":
			r.Crypto = append(r.Crypto, e.Data)
		}
	}

	for _, u := range sockOrder {
		r.SocketIO = append(r.SocketIO, *sockets[u])
	}
	for _, k := range epOrder {
		r.C2 = append(r.C2, *endpoints[k])
	}
	for f := range files {
		r.Files = append(r.Files, f)
	}
	sort.Strings(r.Files)
	for m := range mods {
		r.Modules = append(r.Modules, m)
	}
	sort.Strings(r.Modules)
	r.Stages = t.Stages
}

func mentionsProbe(v any) bool {
	for _, s := range traceStrings(&sandbox.Trace{Events: []sandbox.Event{{Data: map[string]any{"v": v}}}}) {
		if strings.Contains(s, "crumble-probe") {
			return true
		}
	}
	return false
}

// stagedAfter reports whether code was staged (eval, Function, ...) soon
// after the request at index i, before any other request went out.
func stagedAfter(evs []sandbox.Event, i int) bool {
	for j := i + 1; j < len(evs) && j < i+40; j++ {
		switch evs[j].Kind {
		case "stage":
			return true
		case "http.request":
			return false
		}
	}
	return false
}

// addStaticEndpoints lists URLs and ip:port pairs from the strings that the
// emulation never contacted: unreachable branches, other platforms' paths,
// fallbacks.
func (r *Report) addStaticEndpoints() {
	have := map[string]bool{}
	for _, e := range r.C2 {
		have[e.URL] = true
		have[e.Host] = true
		have[e.Host+":"+strconv.Itoa(e.Port)] = true
	}
	for _, ind := range r.Indicators {
		if ind.Benign {
			continue
		}
		var raw string
		switch ind.Type {
		case "url":
			raw = ind.Value
		case "ip:port":
			raw = "tcp://" + ind.Value
		default:
			continue
		}
		ep, key, ok := endpoint(raw)
		if !ok || have[key] || have[ep.Host+":"+strconv.Itoa(ep.Port)] {
			continue
		}
		have[key] = true
		ep.Role = "static only"
		ep.Source = "static"
		r.C2 = append(r.C2, ep)
	}
}

func endpoint(raw string) (Endpoint, string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Endpoint{}, "", false
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	} else {
		switch u.Scheme {
		case "http", "ws":
			port = 80
		case "https", "wss":
			port = 443
		}
	}
	ep := Endpoint{URL: raw, Host: u.Hostname(), Port: port, Path: u.EscapedPath()}
	return ep, raw, true
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

func rank(role string) int {
	switch role {
	case "socket.io C2":
		return 5
	case "stage delivery":
		return 4
	case "file upload", "browser data upload":
		return 3
	case "http", "raw tcp":
		return 1
	}
	return 0
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
