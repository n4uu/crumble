package extract

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RenderJSON returns the report as indented JSON.
func RenderJSON(r *Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderText returns a human-readable report.
func RenderText(r *Report) string {
	var b strings.Builder
	kv := func(k, v string) { fmt.Fprintf(&b, "%-12s %s\n", k, v) }

	kv("sample", fmt.Sprintf("%s (%d bytes)", r.File, r.Size))
	kv("sha256", r.SHA256)
	if o := r.Obfuscation; o != nil {
		rot := ""
		if o.Rotated {
			rot = ", rotated"
		}
		enc := o.Encoding + "-encoded"
		if o.Encoding == "none" {
			enc = "plain"
		}
		line := fmt.Sprintf("%s, %s string array (%d entries%s), %d wrappers, %d aliases, %d calls resolved",
			o.Tool, enc, o.ArraySize, rot, o.Wrappers, o.Aliases, o.Resolved)
		if o.Failed > 0 {
			line += fmt.Sprintf(", %d unresolved", o.Failed)
		}
		kv("obfuscation", line)
	}
	kv("verdict", r.Verdict)

	if len(r.C2) > 0 {
		b.WriteString("\nendpoints\n")
		w := 0
		for _, e := range r.C2 {
			if len(e.Role) > w {
				w = len(e.Role)
			}
		}
		for _, e := range r.C2 {
			m := ""
			if len(e.Methods) > 0 {
				m = strings.Join(e.Methods, ",") + " "
			}
			fmt.Fprintf(&b, "  %-*s  %s%s  [%s]\n", w, e.Role, m, e.URL, e.Source)
		}
	}

	for _, s := range r.SocketIO {
		fmt.Fprintf(&b, "\nsocket.io %s\n", s.URL)
		if len(s.Options) > 0 {
			fmt.Fprintf(&b, "  %-10s %s\n", "options", flat(s.Options))
		}
		fmt.Fprintf(&b, "  %-10s %s\n", "handlers", strings.Join(s.Handlers, ", "))
		if len(s.Emits) > 0 {
			fmt.Fprintf(&b, "  %-10s %s\n", "emits", strings.Join(s.Emits, ", "))
		}
		if s.CommandEvent != "" {
			line := fmt.Sprintf("%q", s.CommandEvent)
			if s.ReplyEvent != "" {
				line += fmt.Sprintf(" -> %q", s.ReplyEvent)
			}
			if s.CommandExec {
				line += "  (payload reached child_process)"
			} else {
				line += "  (payload echoed back, never reached child_process)"
			}
			fmt.Fprintf(&b, "  %-10s %s\n", "tasking", line)
		}
	}
	if r.Identity != nil {
		ev, _ := r.Identity["_event"].(string)
		id := map[string]any{}
		for k, v := range r.Identity {
			if k != "_event" {
				id[k] = v
			}
		}
		fmt.Fprintf(&b, "  %-10s %q %s\n", "check-in", ev, flat(id))
		fmt.Fprintf(&b, "  %-10s %s\n", "", "(host fields are the sandbox's; ids and constants are the sample's)")
	}

	section := func(title string, fs []Finding) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s\n", title)
		w := 0
		for _, f := range fs {
			if len(f.Name) > w {
				w = len(f.Name)
			}
		}
		for _, f := range fs {
			fmt.Fprintf(&b, "  %-*s  %-8s  %s\n", w, f.Name, f.Confidence, strings.Join(f.Evidence, "; "))
		}
	}
	section("roles", r.Roles)
	section("capabilities", r.Capabilities)

	if len(r.Commands) > 0 {
		b.WriteString("\ncommands\n")
		for _, c := range r.Commands {
			fmt.Fprintf(&b, "  %s\n", c)
		}
	}
	if len(r.Stages) > 0 {
		b.WriteString("\nstages\n")
		for _, s := range r.Stages {
			fmt.Fprintf(&b, "  %-16s %7d bytes  sha256 %s\n", s.Via, s.Size, s.SHA256)
		}
	}
	if len(r.Crypto) > 0 {
		b.WriteString("\ncrypto\n")
		for _, c := range r.Crypto {
			fmt.Fprintf(&b, "  %s\n", flat(c))
		}
	}
	if len(r.Files) > 0 {
		b.WriteString("\nfile writes\n")
		for _, f := range r.Files {
			fmt.Fprintf(&b, "  %s\n", f)
		}
	}
	if len(r.Indicators) > 0 {
		b.WriteString("\nindicators\n")
		for _, i := range r.Indicators {
			tag := ""
			if i.Benign {
				tag = "  (well-known, not C2)"
			}
			fmt.Fprintf(&b, "  %-8s %s%s\n", i.Type, i.Value, tag)
		}
	}
	if len(r.Modules) > 0 {
		fmt.Fprintf(&b, "\n%-12s %s\n", "modules", strings.Join(r.Modules, ", "))
	}
	if len(r.Notes) > 0 {
		b.WriteString("\nnotes\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	return b.String()
}

// flat renders a map as k=v pairs in key order, one level deep.
func flat(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := m[k]
		switch x := v.(type) {
		case map[string]any, []any:
			j, _ := json.Marshal(x)
			parts = append(parts, fmt.Sprintf("%s=%s", k, j))
		case float64:
			parts = append(parts, fmt.Sprintf("%s=%v", k, x))
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", k, x))
		}
	}
	return strings.Join(parts, " ")
}
