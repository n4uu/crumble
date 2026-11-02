// Package extract turns a JavaScript sample into a configuration report by
// combining static string recovery (jsdeob) with emulation (sandbox).
package extract

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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
	TCP          []TCPConn        `json:"tcp,omitempty"`
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

// TCPConn is a raw TCP connection the sample opened with the net module.
type TCPConn struct {
	URL    string `json:"url"`
	Hello  string `json:"first_write,omitempty"` // first thing the sample sent
	Writes int    `json:"writes"`
	// CommandExec is true when the probe, delivered as data from the
	// server, reached a child_process API.
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
	if field, inner, ok := jsonEnvelope(code); ok {
		rep.Notes = append(rep.Notes, fmt.Sprintf("JSON envelope; analysing the script in field %q (%d bytes)", field, len(inner)))
		code = inner
	}
	d, err := jsdeob.Deobfuscate(code, jsdeob.Options{})
	switch {
	case d == nil && errors.Is(err, jsdeob.ErrParse):
		// Samples get tagged by family, not by file type: batch and shell
		// droppers from the same campaign land next to the JavaScript.
		// The URLs in them are still worth having.
		rep.Notes = append(rep.Notes, "not JavaScript ("+firstLine(err.Error())+"); indicators come from the raw text, nothing was emulated")
		rep.Indicators = indicators([]string{code})
		rep.addStaticEndpoints()
		rep.Verdict = "not JavaScript; static indicators only"
		return rep, nil
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
			tr, stubs, err := emulate(code, sandbox.Options{
				Platform: p, Root: opts.Root, Probe: true,
				Response: opts.Response, Budget: opts.Budget, Filename: baseName(opts.Name),
			})
			if err != nil {
				return nil, err
			}
			if len(stubs) > 0 {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: sample uses names it never defines (%s), probably from the file it was appended to; re-ran with them stubbed", p, strings.Join(stubs, ", ")))
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
		if len(rep.Trace.Of("antidebug")) > 0 {
			rep.Notes = append(rep.Notes, "debug protection (Function(\"debugger\") loop) seen and neutralised")
		}
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
	awaitReply := ""
	tcp := map[string]*TCPConn{}
	var tcpOrder []string

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
			if awaitReply == s.URL && s.ReplyEvent == "" {
				// First thing sent after the probe reached exec: the
				// command output going back, even if it no longer
				// contains the probe text.
				s.ReplyEvent = ev
				awaitReply = ""
			}
			if lastProbe != "" && lastProbeURL == s.URL && s.ReplyEvent == "" {
				if pe, ok := mentionsProbe(e.Data["args"]); ok {
					if pe == "" {
						pe = lastProbe
					}
					if s.CommandEvent == "" || s.CommandEvent == pe {
						s.CommandEvent = pe
						s.ReplyEvent = ev
					}
				} else if s.CommandEvent == lastProbe {
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
				pe := probeEvent(c)
				if pe == "" {
					pe = lastProbe
				}
				if s := sockets[lastProbeURL]; s != nil && (s.CommandEvent == "" || s.CommandEvent == pe) {
					s.CommandEvent = pe
					s.CommandExec = true
					awaitReply = s.URL
				}
				if c := tcp[lastProbeURL]; c != nil {
					c.CommandExec = true
				}
				continue // our own probe, not the sample's
			}
			// BeaverTail fetches its Python stage with curl rather than
			// an HTTP module; the URL is still one the sample contacted.
			for _, u := range urlRE.FindAllString(c, -1) {
				addEP(strings.TrimRight(u, `.,;)]}"`), "download via shell", "")
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
			u := "tcp://" + str("target")
			addEP(u, "raw tcp", "")
			if tcp[u] == nil {
				tcp[u] = &TCPConn{URL: u}
				tcpOrder = append(tcpOrder, u)
			}
		case "net.write":
			if c := tcp["tcp://"+str("target")]; c != nil {
				c.Writes++
				if c.Hello == "" {
					c.Hello = strings.TrimSpace(fmt.Sprint(e.Data["data"]))
					if len(c.Hello) > 200 {
						c.Hello = c.Hello[:200] + "..."
					}
				}
			}
		case "fs.write":
			files[str("api")+" "+str("path")] = true
		case "crypto.decipher", "crypto.cipher":
			r.Crypto = append(r.Crypto, e.Data)
		}
	}

	for _, u := range sockOrder {
		r.SocketIO = append(r.SocketIO, *sockets[u])
	}
	for _, u := range tcpOrder {
		r.TCP = append(r.TCP, *tcp[u])
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

// mentionsProbe reports whether v carries the probe text, and which event
// it was sent to if the text survived intact.
func mentionsProbe(v any) (string, bool) {
	for _, s := range traceStrings(&sandbox.Trace{Events: []sandbox.Event{{Data: map[string]any{"v": v}}}}) {
		if strings.Contains(s, "crumble-probe") {
			return probeEvent(s), true
		}
	}
	return "", false
}

// probeEvent returns the event name tagged onto the probe text in s
// ("crumble-probe:command" -> "command"), or "" if there is none.
func probeEvent(s string) string {
	_, rest, ok := strings.Cut(s, "crumble-probe:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, " \t\r\n\"'`;&|)"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// stagedAfter reports whether code was staged (eval, Function, ...) soon
// after the request at index i, before any other request went out.
func stagedAfter(evs []sandbox.Event, i int) bool {
	for j := i + 1; j < len(evs) && j < i+40; j++ {
		switch evs[j].Kind {
		case "stage":
			// Code handed to a child node process came from the sample,
			// not from the response.
			if via, _ := evs[j].Data["via"].(string); strings.HasPrefix(via, "node ") {
				continue
			}
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

// jsonEnvelope handles stages saved as the server sent them. The first
// OtterCookie loaders read a JSON response and eval'd one of its fields
// ({"cookie": "<script>"}). If src is a JSON object, the longest string
// field that parses as JavaScript is returned.
func jsonEnvelope(src string) (field, code string, ok bool) {
	t := strings.TrimSpace(src)
	if !strings.HasPrefix(t, "{") {
		return "", "", false
	}
	var obj map[string]any
	if json.Unmarshal([]byte(t), &obj) != nil {
		return "", "", false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, isStr := obj[k].(string)
		if !isStr || len(v) <= len(code) || !jsdeob.Parses(v) {
			continue
		}
		field, code, ok = k, v, true
	}
	return field, code, ok
}

var undefinedRE = regexp.MustCompile(`^ReferenceError: ([\p{L}_$][\p{L}\p{N}_$]*) is not defined`)

// emulate runs the sandbox and, when the sample dies on a free variable
// before doing anything else, runs it again with that name stubbed.
// BeaverTail is often pasted after the last line of a real source file
// ("module.exports = router;" and a few hundred spaces), so on its own the
// first statement throws. At most four names are stubbed.
func emulate(code string, o sandbox.Options) (*sandbox.Trace, []string, error) {
	for {
		tr, err := sandbox.Run(code, o)
		if err != nil {
			return nil, nil, err
		}
		m := undefinedRE.FindStringSubmatch(tr.Error)
		if m == nil || len(o.Stubs) >= 4 || contains(o.Stubs, m[1]) || didSomething(tr) {
			return tr, o.Stubs, nil
		}
		o.Stubs = append(o.Stubs, m[1])
	}
}

// didSomething reports whether the trace has anything past module loading.
func didSomething(t *sandbox.Trace) bool {
	for _, e := range t.Events {
		switch e.Kind {
		case "require", "env.read", "console", "error":
		default:
			return true
		}
	}
	return false
}
