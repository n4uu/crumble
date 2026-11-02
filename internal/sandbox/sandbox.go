// Package sandbox runs a JavaScript sample inside goja with every Node.js
// API that reaches the outside world replaced by a recording stub.
//
// Static string recovery (package jsdeob) tells you which strings a sample
// carries. Emulation tells you how they're used: which one actually goes to
// io(), what the sample sends once connected, which socket.io event feeds
// child_process, and what a loader passes to eval. The two are complementary
// and crumble runs both.
//
// Safety model: goja is a pure-Go interpreter with no access to the host
// beyond what's explicitly handed to it, and the only things handed in are
// the functions on the __crumble object below. None of them open sockets,
// spawn processes or write files. Reads are confined to an optional root
// directory supplied by the analyst (for multi-file packages). Runaway code
// is stopped by a wall-clock budget. Memory is not capped, so don't point
// this at something designed to exhaust it on a box you care about.
package sandbox

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

//go:embed prelude.js
var prelude string

// Options configures one emulation run. The zero value is usable.
type Options struct {
	// Platform is what os.platform() and process.platform report:
	// "win32" (default), "darwin" or "linux". Samples branch on it, so
	// running all three is worthwhile when hunting for every path.
	Platform string
	// Filename is reported as __filename / process.argv[1].
	Filename string
	// Root, if set, lets require('./x') and fs.readFileSync read real files
	// under this directory. Nothing outside it is reachable.
	Root string
	// Budget is the total wall-clock time for the run (default 5s).
	Budget time.Duration
	// MaxTimers caps how many virtual timer callbacks fire (default 200).
	MaxTimers int
	// Probe delivers a synthetic payload to every custom socket.io event
	// handler after connect, to see what the handler does with it.
	Probe bool
	// Response is what every HTTP stub answers with. Leave the body empty
	// to see the request only. Set Status >= 400 to reproduce loaders that
	// expect their stage in an error response (see README).
	Response Response
	// MaxEvents caps the trace length (default 10000).
	MaxEvents int
}

// Response is the canned answer given to every outbound HTTP request.
type Response struct {
	Status      int
	Body        string
	ContentType string
}

// Event is one recorded call.
type Event struct {
	Seq  int            `json:"seq"`
	Kind string         `json:"kind"`
	Data map[string]any `json:"data,omitempty"`
}

// Stage is code the sample handed to eval, Function, Module._compile or a
// local require.
type Stage struct {
	Via    string `json:"via"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Code   string `json:"-"`
}

// Trace is everything recorded during a run.
type Trace struct {
	Events    []Event `json:"events"`
	Stages    []Stage `json:"stages,omitempty"`
	Error     string  `json:"error,omitempty"`
	TimedOut  bool    `json:"timed_out,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Exited    bool    `json:"exited,omitempty"`
}

// Of returns the events of the given kind.
func (t *Trace) Of(kind string) []Event {
	var out []Event
	for _, e := range t.Events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func (o *Options) defaults() {
	if o.Platform == "" {
		o.Platform = "win32"
	}
	if o.Filename == "" {
		o.Filename = "index.js"
	}
	if o.Budget == 0 {
		o.Budget = 5 * time.Second
	}
	if o.MaxTimers == 0 {
		o.MaxTimers = 200
	}
	if o.MaxEvents == 0 {
		o.MaxEvents = 10000
	}
	if o.Response.Status == 0 {
		o.Response.Status = 200
	}
	if o.Response.ContentType == "" {
		o.Response.ContentType = "text/plain"
	}
}

type runner struct {
	opts     Options
	vm       *goja.Runtime
	trace    *Trace
	deadline time.Time
	dir      string // virtual dirname of the sample
}

// Run emulates src and returns what it tried to do. A sample that throws,
// exits or times out still returns its trace up to that point; err is only
// non-nil if the sandbox itself couldn't start.
func Run(src string, opts Options) (*Trace, error) {
	opts.defaults()
	switch opts.Platform {
	case "win32", "darwin", "linux":
	default:
		return nil, fmt.Errorf("unsupported platform %q", opts.Platform)
	}

	r := &runner{
		opts:     opts,
		vm:       goja.New(),
		trace:    &Trace{},
		deadline: time.Now().Add(opts.Budget),
	}
	r.dir = r.virtualDir()

	if err := r.install(); err != nil {
		return nil, err
	}
	if _, err := r.vm.RunString(prelude); err != nil {
		return nil, fmt.Errorf("sandbox prelude: %w", err)
	}

	// A leading shebang is legal in Node but not inside the function body
	// the sample gets wrapped in.
	code := src
	if strings.HasPrefix(code, "#!") {
		code = ""
		if i := strings.IndexByte(src, '\n'); i >= 0 {
			code = src[i:]
		}
	}
	if err := r.vm.Set("__crumble_src", code); err != nil {
		return nil, err
	}

	if r.step("__crumbleMain(__crumble_src)") {
		r.timers()
		if r.step(fmt.Sprintf("__crumble.drive(%v)", opts.Probe)) {
			r.timers()
		}
	}
	return r.trace, nil
}

// step runs one top-level piece of JS within the remaining budget. goja
// drains the promise job queue when a top-level run returns, so async code
// progresses between steps. Returns false once the run should stop.
func (r *runner) step(code string) bool {
	left := time.Until(r.deadline)
	if left <= 0 {
		r.trace.TimedOut = true
		return false
	}
	timer := time.AfterFunc(left, func() { r.vm.Interrupt("budget") })
	defer timer.Stop()
	defer r.vm.ClearInterrupt()

	_, err := r.vm.RunString(code)
	if err == nil {
		return true
	}
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		r.trace.TimedOut = true
		return false
	}
	var ex *goja.Exception
	if errors.As(err, &ex) {
		if obj, ok := ex.Value().(*goja.Object); ok {
			if exit := r.vm.Get("__crumbleExit"); exit != nil {
				if r.vm.InstanceOf(obj, exit.ToObject(r.vm)) {
					r.trace.Exited = true
					return false
				}
			}
		}
	}
	if r.trace.Error == "" {
		r.trace.Error = err.Error()
	}
	r.record("error", fmt.Sprintf(`{"where":"uncaught","message":%q}`, err.Error()))
	// An uncaught exception in the main script doesn't stop handlers that
	// were already registered from firing, same as in Node.
	return true
}

func (r *runner) timers() {
	for i := 0; i < r.opts.MaxTimers; i++ {
		v, ok := r.stepValue("__crumble.nextTimer()")
		if !ok || !v {
			return
		}
	}
}

func (r *runner) stepValue(code string) (bool, bool) {
	left := time.Until(r.deadline)
	if left <= 0 {
		r.trace.TimedOut = true
		return false, false
	}
	timer := time.AfterFunc(left, func() { r.vm.Interrupt("budget") })
	defer timer.Stop()
	defer r.vm.ClearInterrupt()
	v, err := r.vm.RunString(code)
	if err != nil {
		var interrupted *goja.InterruptedError
		if errors.As(err, &interrupted) {
			r.trace.TimedOut = true
			return false, false
		}
		r.record("error", fmt.Sprintf(`{"where":"timer","message":%q}`, err.Error()))
		return true, true // a throwing timer callback doesn't stop the others
	}
	return v.ToBoolean(), true
}

func (r *runner) virtualDir() string {
	if r.opts.Platform == "win32" {
		return `C:\Users\analyst\project`
	}
	if r.opts.Platform == "darwin" {
		return "/Users/analyst/project"
	}
	return "/home/analyst/project"
}

func (r *runner) record(kind, payload string) {
	if len(r.trace.Events) >= r.opts.MaxEvents {
		r.trace.Truncated = true
		return
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		data = map[string]any{"raw": payload}
	}
	r.trace.Events = append(r.trace.Events, Event{Seq: len(r.trace.Events), Kind: kind, Data: data})
}

func (r *runner) install() error {
	h := r.vm.NewObject()
	set := func(name string, v any) {
		if err := h.Set(name, v); err != nil {
			panic(err) // only fails for non-extensible objects
		}
	}
	set("platform", r.opts.Platform)
	set("filename", r.joinVirtual(r.opts.Filename))
	set("dirname", r.dir)
	set("record", r.record)
	set("stage", func(via, code string) {
		sum := sha256.Sum256([]byte(code))
		r.trace.Stages = append(r.trace.Stages, Stage{Via: via, Size: len(code), SHA256: hex.EncodeToString(sum[:]), Code: code})
		r.record("stage", fmt.Sprintf(`{"via":%q,"size":%d,"sha256":%q}`, via, len(code), hex.EncodeToString(sum[:])))
	})
	set("encode", encode)
	set("decode", decode)
	set("digest", digest)
	set("fakeOutput", fakeOutput)
	set("response", func() map[string]any {
		return map[string]any{
			"status":      r.opts.Response.Status,
			"body":        r.opts.Response.Body,
			"contentType": r.opts.Response.ContentType,
		}
	})
	set("readFile", func(p string) goja.Value {
		b, ok := r.readRooted(p)
		if !ok {
			return goja.Null()
		}
		return r.vm.ToValue(string(b))
	})
	set("resolve", func(dir, name string) goja.Value {
		for _, cand := range []string{name, name + ".js", name + ".json", name + "/index.js"} {
			p := r.joinVirtualFrom(dir, cand)
			if b, ok := r.readRooted(p); ok {
				return r.vm.ToValue(map[string]any{"path": p, "code": string(b)})
			}
		}
		return goja.Null()
	})
	return r.vm.Set("__crumble", h)
}

func (r *runner) joinVirtual(name string) string {
	return r.joinVirtualFrom(r.dir, name)
}

func (r *runner) joinVirtualFrom(dir, name string) string {
	sep := "/"
	if r.opts.Platform == "win32" {
		sep = `\`
		name = strings.ReplaceAll(name, "/", `\`)
	}
	if strings.HasPrefix(name, sep) || (len(name) > 2 && name[1] == ':') {
		return name
	}
	parts := strings.Split(dir, sep)
	for _, p := range strings.Split(name, sep) {
		switch p {
		case "", ".":
		case "..":
			if len(parts) > 1 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, sep)
}

// readRooted maps a virtual path under the sample's directory onto Root and
// reads it, refusing anything that would land outside Root.
func (r *runner) readRooted(virtual string) ([]byte, bool) {
	if r.opts.Root == "" {
		return nil, false
	}
	sep := "/"
	if r.opts.Platform == "win32" {
		sep = `\`
	}
	prefix := r.dir + sep
	if !strings.HasPrefix(virtual, prefix) {
		return nil, false
	}
	rel := filepath.FromSlash(strings.ReplaceAll(strings.TrimPrefix(virtual, prefix), sep, "/"))
	root, err := filepath.Abs(r.opts.Root)
	if err != nil {
		return nil, false
	}
	full := filepath.Join(root, rel)
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return nil, false
	}
	// Follow symlinks only if they stay inside root.
	if real, err := filepath.EvalSymlinks(full); err == nil {
		realRoot, _ := filepath.EvalSymlinks(root)
		if real != realRoot && !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
			return nil, false
		}
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() || st.Size() > 32<<20 {
		return nil, false
	}
	b, err := os.ReadFile(full)
	return b, err == nil
}

// ---------------------------------------------------------------------------
// byte helpers. Inside the VM a "binary string" is a JS string whose code
// units are all <= 0xff, one per byte.

func binaryToBytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		out = append(out, byte(r))
	}
	return out
}

func bytesToBinary(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// encode turns a binary string into text in the given Node encoding.
func encode(bin, enc string) string {
	b := binaryToBytes(bin)
	switch enc {
	case "hex":
		return hex.EncodeToString(b)
	case "base64":
		return base64.StdEncoding.EncodeToString(b)
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(b)
	case "latin1", "binary", "ascii":
		return bin
	default: // utf8, utf-8, and anything unknown
		if utf8.Valid(b) {
			return string(b)
		}
		return strings.ToValidUTF8(string(b), "\uFFFD")
	}
}

// decode turns text in a Node encoding into a binary string.
func decode(text, enc string) string {
	switch enc {
	case "hex":
		n := len(text) &^ 1
		b, err := hex.DecodeString(text[:n])
		if err != nil {
			// Node stops at the first bad pair rather than failing.
			var out []byte
			for i := 0; i+1 < n; i += 2 {
				v, err := hex.DecodeString(text[i : i+2])
				if err != nil {
					break
				}
				out = append(out, v...)
			}
			return bytesToBinary(out)
		}
		return bytesToBinary(b)
	case "base64", "base64url":
		return bytesToBinary(lenientBase64(text))
	case "latin1", "binary", "ascii":
		return bin1(text)
	default:
		return bytesToBinary([]byte(text))
	}
}

func bin1(text string) string {
	var sb strings.Builder
	for _, r := range text {
		sb.WriteRune(rune(byte(r)))
	}
	return sb.String()
}

// lenientBase64 decodes the way Buffer.from(s, 'base64') does: either
// alphabet, padding optional, whitespace and junk skipped.
func lenientBase64(s string) []byte {
	var clean strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			clean.WriteRune(c)
		case c == '-':
			clean.WriteByte('+')
		case c == '_':
			clean.WriteByte('/')
		case c == '=':
			goto done
		}
	}
done:
	t := clean.String()
	if len(t)%4 == 1 { // a lone trailing sextet carries no full byte
		t = t[:len(t)-1]
	}
	b, err := base64.RawStdEncoding.DecodeString(t)
	if err != nil {
		return nil
	}
	return b
}

func digest(alg, bin string) string {
	var h hash.Hash
	switch strings.ToLower(alg) {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha512":
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write(binaryToBytes(bin))
	return bytesToBinary(h.Sum(nil))
}

// fakeOutput gives a few recon commands a believable answer, since some
// samples parse the output before deciding what to do next (the v4 VM check
// looks for hypervisor vendor names in it).
func fakeOutput(cmd string) string {
	c := strings.ToLower(cmd)
	switch {
	case strings.Contains(c, "computersystem"):
		return "Manufacturer  Model\r\nDell Inc.     OptiPlex 7090\r\n"
	case strings.Contains(c, "system_profiler"):
		return "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Pro\n      Chip: Apple M2\n"
	case strings.Contains(c, "/proc/cpuinfo") || strings.Contains(c, "lscpu"):
		return "model name\t: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz\n"
	case strings.Contains(c, "whoami"):
		return "crumble-sandbox\\analyst\n"
	case strings.Contains(c, "hostname"):
		return "CRUMBLE-SANDBOX\n"
	}
	return ""
}
