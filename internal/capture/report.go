package capture

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Tasking is one operator instruction pulled out of a session.
type Tasking struct {
	Time    time.Time `json:"time"`
	Event   string    `json:"event"`
	Command string    `json:"command"`
	Reply   string    `json:"reply_event,omitempty"`
	Output  string    `json:"output,omitempty"`
}

// Taskings pairs every server->client event with the next client->server
// event, and pulls a human-readable command out of the payload. Field names
// tried, in order: message (OtterCookie), cmd, command, then a bare string.
func (s *Session) Taskings() []Tasking {
	var out []Tasking
	for i, it := range s.Items {
		if it.Dir != "down" || it.Event == "" {
			continue
		}
		t := Tasking{Time: it.Time, Event: it.Event, Command: commandText(it.Args)}
		for _, nx := range s.Items[i+1:] {
			if nx.Dir == "down" && nx.Event != "" {
				break
			}
			if nx.Dir == "up" && nx.Event != "" {
				t.Reply = nx.Event
				t.Output = outputText(nx.Args)
				break
			}
		}
		out = append(out, t)
	}
	return out
}

func commandText(args []json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(args[0], &s) == nil {
		return s
	}
	var m map[string]any
	if json.Unmarshal(args[0], &m) == nil {
		for _, k := range []string{"message", "cmd", "command", "data"} {
			if v, ok := m[k].(string); ok {
				return v
			}
		}
	}
	return string(args[0])
}

func outputText(args []json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(args[0], &m) == nil {
		for _, k := range []string{"result", "output", "data", "message"} {
			if v, ok := m[k].(string); ok {
				return v
			}
		}
	}
	var s string
	if json.Unmarshal(args[0], &s) == nil {
		return s
	}
	return ""
}

// Registration returns the first client->server event of the session,
// which for OtterCookie is the victim check-in.
func (s *Session) Registration() *Item {
	for i := range s.Items {
		if s.Items[i].Dir == "up" && s.Items[i].Event != "" {
			return &s.Items[i]
		}
	}
	return nil
}

// knownPorts are ports reported for Contagious Interview implants. 1418 is
// the OtterCookie socket.io listener (Cisco Talos); 1224/1244/1245 are the
// BeaverTail / InvisibleFerret HTTP ports (MITRE S1246, ANY.RUN), which the
// later merged builds share.
var knownPorts = map[uint16]string{
	1418: "OtterCookie socket.io port (Talos)",
	1224: "BeaverTail/InvisibleFerret port",
	1244: "BeaverTail/InvisibleFerret port",
	1245: "InvisibleFerret port",
}

// knownPaths are HTTP paths published for this cluster's implants.
var knownPaths = map[string]string{
	"/uploads": "BeaverTail/OtterCookie exfiltration path (MITRE S1246, ANY.RUN)",
	"/upload":  "OtterCookie v4 upload module path (Elastic)",
	"/cldbs":   "OtterCookie v4 browser database upload path (Elastic)",
	"/pdown":   "BeaverTail portable Python download (ANY.RUN)",
	"/keys":    "InvisibleFerret next-stage path (ANY.RUN)",
	"/brow":    "InvisibleFerret browser module path (ANY.RUN)",
	"/bow":     "InvisibleFerret browser module path (ANY.RUN)",
}

// Notes returns why an HTTP request is interesting, if it is.
func (r HTTPRequest) Notes() []string {
	var out []string
	path, _, _ := strings.Cut(r.Target, "?")
	for p, why := range knownPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			out = append(out, "path "+p+": "+why)
		}
	}
	if ap, err := netip.ParseAddrPort(r.Server); err == nil {
		if why, ok := knownPorts[ap.Port()]; ok {
			out = append(out, fmt.Sprintf("port %d: %s", ap.Port(), why))
		}
	}
	return out
}

// Assessment explains, in one or two lines, why a session does or doesn't
// look like OtterCookie C2. It never says more than the traffic supports.
func (s *Session) Assessment() []string {
	var out []string
	if ap, err := netip.ParseAddrPort(s.Server); err == nil {
		if why, ok := knownPorts[ap.Port()]; ok {
			out = append(out, fmt.Sprintf("server port %d: %s", ap.Port(), why))
		}
	}
	tasks := s.Taskings()
	events := map[string]bool{}
	for _, t := range tasks {
		events[t.Event+">"+t.Reply] = true
	}
	if events["command>message"] {
		out = append(out, `operator sends "command" events and the client answers with "message": the OtterCookie remote shell exchange`)
	} else if len(tasks) > 0 {
		out = append(out, fmt.Sprintf("%d server-initiated event(s); not the OtterCookie command/message pair", len(tasks)))
	}
	return out
}

// RenderText prints the capture analysis. verbose includes ping/pong and
// transport housekeeping in the timeline.
func RenderText(a *Analysis, verbose bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "capture: %d frames, %d tcp connections, %d engine.io session(s), %d other http request(s)\n",
		a.Frames, a.Connections, len(a.Sessions), len(a.HTTP))

	for _, s := range a.Sessions {
		fmt.Fprintf(&b, "\nsession %s  %s -> %s\n", s.SID, s.Client, s.Endpoint())
		proto := "engine.io v4 (socket.io 3.x/4.x)"
		if s.EIO == 3 {
			proto = "engine.io v3 (socket.io 2.x)"
		}
		fmt.Fprintf(&b, "  %s  path %s  transports %s", proto, s.Path, strings.Join(s.Transports, " -> "))
		if s.PingInterval > 0 {
			fmt.Fprintf(&b, "  ping %d/%d ms", s.PingInterval, s.PingTimeout)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "  %s to %s (%s), %d tcp connection(s)\n", clock(s.Start), clock(s.End), s.End.Sub(s.Start).Round(time.Millisecond), s.Connections)
		if s.UserAgent != "" {
			fmt.Fprintf(&b, "  user-agent %s\n", s.UserAgent)
		}
		for _, line := range s.Assessment() {
			fmt.Fprintf(&b, "  * %s\n", line)
		}

		b.WriteString("\n")
		folded := 0
		for _, it := range s.Items {
			if !verbose && (it.EIO == "ping" || it.EIO == "pong" || it.EIO == "upgrade" || it.EIO == "noop") {
				folded++
				continue
			}
			via := "poll"
			if it.Transport == "websocket" {
				via = "ws"
			}
			arrow := "->"
			if it.Dir == "down" {
				arrow = "<-"
			}
			label := it.EIO
			if it.SIO != "" {
				label = it.SIO
			}
			fmt.Fprintf(&b, "  %s  %s %-4s %-13s %s\n", clock(it.Time), arrow, via, label, itemText(it))
		}
		if folded > 0 {
			fmt.Fprintf(&b, "  (%d ping/pong/upgrade packets not shown, use -v)\n", folded)
		}

		if reg := s.Registration(); reg != nil {
			fmt.Fprintf(&b, "\n  check-in   %q %s\n", reg.Event, joinRaw(reg.Args))
		}
		if tasks := s.Taskings(); len(tasks) > 0 {
			b.WriteString("\n  operator tasking\n")
			for _, t := range tasks {
				fmt.Fprintf(&b, "    %s  %-8s %s\n", clock(t.Time), t.Event, t.Command)
				if t.Output != "" {
					fmt.Fprintf(&b, "    %s  %-8s %s\n", strings.Repeat(" ", 12), t.Reply, firstLines(t.Output, 3))
				}
			}
		}
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "  decode error: %s\n", e)
		}
	}

	if len(a.HTTP) > 0 {
		b.WriteString("\nother http\n")
		for _, r := range a.HTTP {
			host := r.Host
			if host == "" {
				host = r.Server
			}
			fmt.Fprintf(&b, "  %s  %s -> %s  %s http://%s%s  %d", clock(r.Time), r.Client, r.Server, r.Method, host, r.Target, r.Status)
			if r.ReqBytes > 0 {
				fmt.Fprintf(&b, "  (%d bytes up)", r.ReqBytes)
			}
			b.WriteString("\n")
			if len(r.Files) > 0 {
				fmt.Fprintf(&b, "      uploaded files: %s\n", strings.Join(quoteAll(r.Files), ", "))
			}
			if len(r.Fields) > 0 {
				fmt.Fprintf(&b, "      form fields: %s\n", strings.Join(r.Fields, ", "))
			}
			if r.UserAgent != "" {
				fmt.Fprintf(&b, "      user-agent: %s\n", r.UserAgent)
			}
			for _, n := range r.Notes() {
				fmt.Fprintf(&b, "      * %s\n", n)
			}
		}
	}
	return b.String()
}

func itemText(it Item) string {
	var parts []string
	if it.Namespace != "" {
		parts = append(parts, it.Namespace)
	}
	if it.Event != "" {
		parts = append(parts, fmt.Sprintf("%q", it.Event))
		if len(it.Args) > 0 {
			parts = append(parts, joinRaw(it.Args))
		}
	} else if len(it.Data) > 0 {
		parts = append(parts, string(it.Data))
	}
	if it.Text != "" {
		parts = append(parts, it.Text)
	}
	return truncate(strings.Join(parts, " "), 160)
}

func joinRaw(args []json.RawMessage) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = string(a)
	}
	return strings.Join(parts, " ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("... (%d bytes)", len(s))
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimRight(s, "\r\n"), "\r\n", "\n"), "\n")
	if len(lines) > n {
		return strings.Join(lines[:n], " | ") + fmt.Sprintf(" | ... (%d lines)", len(lines))
	}
	return strings.Join(lines, " | ")
}

func quoteAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = fmt.Sprintf("%q", x)
	}
	return out
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "--:--:--.---"
	}
	return t.UTC().Format("15:04:05.000")
}
