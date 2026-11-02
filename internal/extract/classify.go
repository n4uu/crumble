package extract

import (
	"fmt"
	"strings"

	"github.com/n4uu/crumble/internal/jsdeob"
)

// capability rules. Each one is a set of string groups: the rule fires when
// at least `need` groups have a hit. Strings come from the deobfuscated
// source, so this works whether or not the code path ran under emulation.
type capRule struct {
	name   string
	need   int
	groups [][]string
}

var capRules = []capRule{
	{"browser credential theft", 2, [][]string{
		{"Login Data", "Web Data", "Cookies", "logins.json", "key4.db"},
		{"Local State", "encrypted_key", "CryptUnprotectData", "dpapi"},
		{"Google/Chrome", `Google\Chrome`, "BraveSoftware", "Microsoft/Edge", `Microsoft\Edge`, "Opera Software", "Mozilla/Firefox"},
	}},
	{"crypto wallet theft", 1, [][]string{
		{
			"nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
			"bfnaelmomeimhlpmgjnjophhpkkoljpa", // Phantom
			"hnfanknocfeofbddgcijnmhnfnkdnaad", // Coinbase Wallet
			"ibnejdfjmmkpcnlpebklmnkoeoihofec", // TronLink
			"fhbohimaelbohpjbbldcngcnapndodjp", // Binance Wallet
			"wallet.dat", "exodus.wallet", "Electrum", "solana/id.json",
		},
	}},
	{"keylogging", 1, [][]string{{"node-global-key-listener", "GetAsyncKeyState", "iohook", "uiohook"}}},
	{"screen capture", 1, [][]string{{"screenshot-desktop", "screencapture -x", "CopyFromScreen"}}},
	{"clipboard monitoring", 1, [][]string{{"pbpaste", "Get-Clipboard", "clipboardy", "xclip -o", "xsel"}}},
	{"virtualisation / sandbox check", 2, [][]string{
		{"VMware", "VirtualBox", "QEMU", "Hyper-V", "KVM", "Parallels", "Xen"},
		{"computersystem", "system_profiler", "/proc/cpuinfo", "hypervisor", "Manufacturer", "Model"},
	}},
	{"secret file hunting", 2, [][]string{
		{".env", "id_rsa", "id_ed25519", ".kdbx", ".pem", "credentials", "keychain-db", ".aws", "secret"},
		{"readdir", "readdirSync", "*.", "patterns"},
	}},
	{"file exfiltration", 2, [][]string{
		{"form-data", "multipart/form-data", "FormData"},
		{"/upload", "/uploads", "/cldbs"},
	}},
	{"remote shell", 2, [][]string{
		{"child_process", "exec", "execSync", "spawn"},
		{"socket.io-client", "command"},
	}},
}

func capabilities(strs []string, r *Report) []Finding {
	var out []Finding
	for _, rule := range capRules {
		hits := 0
		var ev []string
		for _, g := range rule.groups {
			if s, ok := firstContaining(strs, g); ok {
				hits++
				ev = append(ev, fmt.Sprintf("string %q", s))
			}
		}
		if hits >= rule.need {
			f := Finding{Name: rule.name, Confidence: "static", Evidence: ev}
			upgrade(&f, r)
			out = append(out, f)
		}
	}
	return out
}

// firstContaining returns the first string that contains any needle, so
// the evidence shows what the sample actually carries ("*.kdbx", not "*.").
// Needles longer than six characters also match case-insensitively.
func firstContaining(strs []string, needles []string) (string, bool) {
	for _, n := range needles {
		ln := strings.ToLower(n)
		for _, s := range strs {
			if strings.Contains(s, n) || (len(n) > 6 && strings.Contains(strings.ToLower(s), ln)) {
				if len(s) > 60 {
					s = s[:60] + "..."
				}
				return s, true
			}
		}
	}
	return "", false
}

// upgrade marks a static capability as observed when the emulation trace
// shows the matching behaviour actually happening.
func upgrade(f *Finding, r *Report) {
	switch f.Name {
	case "remote shell":
		for _, s := range r.SocketIO {
			if s.CommandExec {
				f.Confidence = "observed"
				f.Evidence = append(f.Evidence, fmt.Sprintf("socket.io %q handler passed its payload to child_process", s.CommandEvent))
			}
		}
	case "file exfiltration":
		for _, e := range r.C2 {
			if e.Source == "emulation" && (e.Role == "file upload" || e.Role == "browser data upload") {
				f.Confidence = "observed"
				f.Evidence = append(f.Evidence, fmt.Sprintf("%s %s", strings.Join(e.Methods, "/"), e.URL))
			}
		}
	case "virtualisation / sandbox check":
		for _, c := range r.Commands {
			lc := strings.ToLower(c)
			if strings.Contains(lc, "computersystem") || strings.Contains(lc, "system_profiler") || strings.Contains(lc, "cpuinfo") {
				f.Confidence = "observed"
				f.Evidence = append(f.Evidence, "ran "+c)
			}
		}
	}
}

// roles are what the module is for, as opposed to the individual things it
// can do. OtterCookie builds have shipped as separate modules (loader,
// shell, upload, keylogger) and as merged bundles, so several can apply.
func roles(d *jsdeob.Result, r *Report) []Finding {
	var out []Finding

	// Loader: fetches code and runs it.
	for _, e := range r.C2 {
		if e.Role == "stage delivery" {
			out = append(out, Finding{"loader", "observed", []string{
				fmt.Sprintf("response from %s was passed to %s", e.URL, stageVia(r)),
			}})
			break
		}
	}
	if len(out) == 0 && hasHTTPClient(r, d) && strings.Contains(d.Source, "eval(") {
		ev := []string{"HTTP client and eval() in the same script"}
		if strings.Contains(d.Source, ".response.data") || strings.Contains(d.Source, "response.data") {
			ev = append(ev, "eval() is fed from response.data (error-handler stage delivery)")
		}
		out = append(out, Finding{"loader", "static", ev})
	}

	for _, s := range r.SocketIO {
		f := Finding{Name: "socket.io implant", Confidence: "observed", Evidence: []string{"connects to " + s.URL}}
		if s.CommandEvent != "" {
			line := fmt.Sprintf("operator tasking arrives as %q", s.CommandEvent)
			if s.ReplyEvent != "" {
				line += fmt.Sprintf(", results go back as %q", s.ReplyEvent)
			}
			f.Evidence = append(f.Evidence, line)
		}
		if r.Identity != nil {
			f.Evidence = append(f.Evidence, fmt.Sprintf("registers with %q on connect", r.Identity["_event"]))
		}
		out = append(out, f)
	}

	for _, c := range r.Capabilities {
		if c.Name == "keylogging" || c.Name == "screen capture" {
			out = append(out, Finding{"surveillance module", c.Confidence, c.Evidence})
			break
		}
	}
	for _, c := range r.Capabilities {
		if c.Name == "file exfiltration" || c.Name == "crypto wallet theft" || c.Name == "browser credential theft" {
			out = append(out, Finding{"collector", c.Confidence, []string{"capability: " + c.Name}})
			break
		}
	}
	return out
}

func stageVia(r *Report) string {
	if len(r.Stages) == 0 {
		return "eval"
	}
	return r.Stages[0].Via
}

func hasHTTPClient(r *Report, d *jsdeob.Result) bool {
	for _, m := range r.Modules {
		switch m {
		case "axios", "request", "node-fetch", "http", "https":
			return true
		}
	}
	for _, s := range d.Strings {
		switch s {
		case "axios", "request", "node-fetch", "http", "https":
			return true
		}
	}
	return false
}

// verdict is deliberately conservative. It names OtterCookie only when the
// behaviour lines up with what's been published about it (socket.io C2 with
// a command/reply event pair, or an error-handler loader), and says
// "consistent with", because structure alone can't attribute a sample.
func verdict(r *Report) string {
	var shell, loader, collector bool
	for _, f := range r.Roles {
		switch f.Name {
		case "socket.io implant":
			for _, s := range r.SocketIO {
				if s.CommandEvent != "" {
					shell = true
				}
			}
		case "loader":
			for _, e := range f.Evidence {
				if strings.Contains(e, "response.data") || strings.Contains(e, "was passed to") {
					loader = true
				}
			}
		case "collector", "surveillance module":
			collector = true
		}
	}
	switch {
	case shell:
		return "consistent with an OtterCookie socket.io shell module"
	case loader:
		return "consistent with a Contagious Interview loader (remote code delivered in an HTTP response and eval'd)"
	case collector:
		return "consistent with an OtterCookie collection module (upload / wallet / surveillance)"
	case len(r.Roles) > 0:
		return "Node.js implant behaviour, no family match"
	}
	return "no implant behaviour identified"
}
