package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/n4uu/crumble/internal/eio"
)

// Session is one Engine.IO session, rebuilt from every connection that
// carried its sid: the polling requests and the WebSocket it upgraded to.
type Session struct {
	SID          string    `json:"sid"`
	EIO          int       `json:"eio"`
	Client       string    `json:"client"`
	Server       string    `json:"server"`
	Host         string    `json:"host,omitempty"`
	Path         string    `json:"path"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Transports   []string  `json:"transports"`
	Upgrades     []string  `json:"upgrades,omitempty"`
	PingInterval int       `json:"ping_interval_ms,omitempty"`
	PingTimeout  int       `json:"ping_timeout_ms,omitempty"`
	MaxPayload   int       `json:"max_payload,omitempty"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	Connections  int       `json:"tcp_connections"`
	Items        []Item    `json:"timeline"`
	Errors       []string  `json:"decode_errors,omitempty"`

	conns map[*Conn]bool
}

// Item is one Engine.IO packet in a session, with the Socket.IO packet it
// carried if it was a message.
type Item struct {
	Time      time.Time         `json:"time"`
	Dir       string            `json:"dir"` // "up" (client->server) or "down"
	Transport string            `json:"transport"`
	EIO       string            `json:"eio"`
	SIO       string            `json:"sio,omitempty"`
	Namespace string            `json:"nsp,omitempty"`
	AckID     int               `json:"ack,omitempty"`
	Event     string            `json:"event,omitempty"`
	Args      []json.RawMessage `json:"args,omitempty"`
	Data      json.RawMessage   `json:"data,omitempty"`
	Text      string            `json:"text,omitempty"` // non-JSON payloads (ping "probe", raw messages)

	attachments [][]byte
	nAttach     int
}

// HTTPRequest is a non-Engine.IO request worth listing, e.g. a file upload
// from the collection module.
type HTTPRequest struct {
	Time      time.Time `json:"time"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	Method    string    `json:"method"`
	Host      string    `json:"host,omitempty"`
	Target    string    `json:"target"`
	Status    int       `json:"status,omitempty"`
	ReqBytes  int       `json:"request_bytes"`
	RespBytes int       `json:"response_bytes"`
	UserAgent string    `json:"user_agent,omitempty"`
	Files     []string  `json:"upload_filenames,omitempty"`
	Fields    []string  `json:"form_fields,omitempty"`
}

// Analysis is the result of reading one capture.
type Analysis struct {
	Frames      int           `json:"frames"`
	Connections int           `json:"tcp_connections"`
	Sessions    []*Session    `json:"sessions"`
	HTTP        []HTTPRequest `json:"http,omitempty"`
}

// Analyze rebuilds Engine.IO sessions and lists other HTTP requests.
func Analyze(frames []Frame) *Analysis {
	conns := Reassemble(frames)
	a := &Analysis{Frames: len(frames), Connections: len(conns)}
	sessions := map[string]*Session{}
	var order []string

	get := func(sid string, ex *Exchange, version int) *Session {
		s := sessions[sid]
		if s == nil {
			s = &Session{SID: sid, EIO: version, conns: map[*Conn]bool{}}
			sessions[sid] = s
			order = append(order, sid)
		}
		if s.Client == "" {
			s.Client = ex.Conn.Client.String()
			s.Server = ex.Conn.Server.String()
			s.Host = ex.Host
			s.UserAgent = ex.ReqHdr.Get("User-Agent")
		}
		s.conns[ex.Conn] = true
		return s
	}

	anon := 0
	for _, c := range conns {
		for _, ex := range Exchanges(c) {
			u, err := url.Parse(ex.Target)
			if err != nil {
				continue
			}
			q := u.Query()
			version, _ := strconv.Atoi(q.Get("EIO"))
			if version == 0 {
				a.HTTP = append(a.HTTP, plainRequest(ex))
				continue
			}
			transport := q.Get("transport")
			sid := q.Get("sid")

			switch {
			case transport == "websocket" && ex.Upgraded:
				msgs := wsItems(ex, version)
				if sid == "" {
					// Direct WebSocket session: the sid is in the open packet.
					sid = openSID(msgs)
					if sid == "" {
						anon++
						sid = "(no sid #" + strconv.Itoa(anon) + ")"
					}
				}
				s := get(sid, ex, version)
				s.Path = u.Path
				addTransport(s, "websocket")
				s.Items = append(s.Items, msgs...)
			case transport == "polling" || transport == "":
				var items []Item
				var errs []string
				if strings.EqualFold(ex.Method, "POST") {
					items, errs = pollItems(ex.ReqBody, version, "up", ex.ReqTime)
				} else {
					items, errs = pollItems(ex.RespBody, version, "down", firstTime(ex.RespTime, ex.ReqTime))
				}
				if sid == "" {
					sid = openSID(items)
					if sid == "" {
						anon++
						sid = "(no sid #" + strconv.Itoa(anon) + ")"
					}
				}
				s := get(sid, ex, version)
				s.Path = u.Path
				addTransport(s, "polling")
				s.Items = append(s.Items, items...)
				s.Errors = append(s.Errors, errs...)
			}
		}
	}

	for _, sid := range order {
		s := sessions[sid]
		s.Connections = len(s.conns)
		sort.SliceStable(s.Items, func(i, j int) bool { return s.Items[i].Time.Before(s.Items[j].Time) })
		s.finish()
		a.Sessions = append(a.Sessions, s)
	}
	return a
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func addTransport(s *Session, t string) {
	for _, x := range s.Transports {
		if x == t {
			return
		}
	}
	s.Transports = append(s.Transports, t)
}

func openSID(items []Item) string {
	for _, it := range items {
		if it.EIO == "open" && len(it.Data) > 0 {
			var o struct {
				SID string `json:"sid"`
			}
			if json.Unmarshal(it.Data, &o) == nil {
				return o.SID
			}
		}
	}
	return ""
}

func pollItems(body []byte, version int, dir string, t time.Time) ([]Item, []string) {
	if len(body) == 0 || string(body) == "ok" {
		return nil, nil
	}
	pkts, err := eio.DecodePayload(body, version)
	var errs []string
	if err != nil {
		errs = append(errs, err.Error())
	}
	var out []Item
	for _, p := range pkts {
		out = append(out, packetItem(p, dir, "polling", t))
	}
	return out, errs
}

func wsItems(ex *Exchange, version int) []Item {
	up, down := NegotiatedDeflate(ex.RespHdr.Get("Sec-WebSocket-Extensions"))
	var out []Item
	for _, m := range WSMessages(ex.Conn.Up, ex.WSUp, up) {
		if p, err := eio.DecodePacket(m.Data, m.Binary, version); err == nil {
			out = append(out, packetItem(p, "up", "websocket", m.Time))
		}
	}
	for _, m := range WSMessages(ex.Conn.Down, ex.WSDown, down) {
		if p, err := eio.DecodePacket(m.Data, m.Binary, version); err == nil {
			out = append(out, packetItem(p, "down", "websocket", m.Time))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func packetItem(p eio.Packet, dir, transport string, t time.Time) Item {
	it := Item{Time: t, Dir: dir, Transport: transport, EIO: p.Type.String()}
	if p.Binary {
		it.attachments = [][]byte{p.Data}
		it.SIO = "binary attachment"
		it.Data = describeBinary(p.Data)
		return it
	}
	switch p.Type {
	case eio.Open:
		if json.Valid(p.Data) {
			it.Data = json.RawMessage(p.Data)
		}
	case eio.Message:
		sp, err := eio.DecodeSocketIO(p.Data)
		if err != nil {
			it.Text = string(p.Data)
			break
		}
		it.SIO = sp.Type.String()
		if sp.Namespace != "/" {
			it.Namespace = sp.Namespace
		}
		if sp.ID >= 0 {
			it.AckID = sp.ID
		}
		if ev, args, ok := sp.Event(); ok {
			it.Event = ev
			it.Args = args
		} else if sp.Data != nil {
			it.Data = sp.Data
		}
		if sp.Attachments > 0 {
			it.nAttach = sp.Attachments
		}
	default:
		if len(p.Data) > 0 {
			it.Text = string(p.Data)
		}
	}
	return it
}

// describeBinary summarises an attachment for the transcript: size, hash,
// and a text preview when it's mostly printable.
func describeBinary(b []byte) json.RawMessage {
	sum := sha256.Sum256(b)
	d := map[string]any{"bytes": len(b), "sha256": hex.EncodeToString(sum[:])}
	if utf8.Valid(b) && printable(b) {
		pv := string(b)
		if len(pv) > 200 {
			pv = pv[:200] + "..."
		}
		d["preview"] = pv
	}
	out, _ := json.Marshal(d)
	return out
}

func printable(b []byte) bool {
	n := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			n++
		}
	}
	return len(b) > 0 && n*10 >= len(b)*9
}

// finish sets session metadata from the open packet and attaches binary
// attachments to the BINARY_EVENT they belong to.
func (s *Session) finish() {
	for _, it := range s.Items {
		if it.EIO != "open" || len(it.Data) == 0 {
			continue
		}
		var o struct {
			Upgrades     []string `json:"upgrades"`
			PingInterval int      `json:"pingInterval"`
			PingTimeout  int      `json:"pingTimeout"`
			MaxPayload   int      `json:"maxPayload"`
		}
		if json.Unmarshal(it.Data, &o) == nil {
			s.Upgrades, s.PingInterval, s.PingTimeout, s.MaxPayload = o.Upgrades, o.PingInterval, o.PingTimeout, o.MaxPayload
		}
		break
	}
	if len(s.Items) > 0 {
		s.Start = s.Items[0].Time
		s.End = s.Items[len(s.Items)-1].Time
	}

	// Attachments follow their BINARY_EVENT in the same direction.
	var kept []Item
	pending := map[string]int{} // direction -> index in kept awaiting attachments
	for _, it := range s.Items {
		if it.SIO == "binary attachment" {
			if i, ok := pending[it.Dir]; ok {
				kept[i].attachments = append(kept[i].attachments, it.attachments...)
				if len(kept[i].attachments) >= kept[i].nAttach {
					delete(pending, it.Dir)
				}
				continue
			}
		}
		kept = append(kept, it)
		if it.nAttach > 0 {
			pending[it.Dir] = len(kept) - 1
		}
	}
	for i := range kept {
		if kept[i].nAttach > 0 {
			fillPlaceholders(&kept[i])
		}
	}
	s.Items = kept
}

func fillPlaceholders(it *Item) {
	if len(it.attachments) == 0 {
		return
	}
	desc := func(b []byte) any {
		var v any
		_ = json.Unmarshal(describeBinary(b), &v)
		return map[string]any{"_binary": v}
	}
	for i, a := range it.Args {
		it.Args[i] = eio.FillAttachments(a, it.attachments, desc)
	}
	if it.Data != nil {
		it.Data = eio.FillAttachments(it.Data, it.attachments, desc)
	}
}

func plainRequest(ex *Exchange) HTTPRequest {
	r := HTTPRequest{
		Time: ex.ReqTime, Client: ex.Conn.Client.String(), Server: ex.Conn.Server.String(),
		Method: ex.Method, Host: ex.Host, Target: ex.Target, Status: ex.Status,
		ReqBytes: len(ex.ReqBody), RespBytes: len(ex.RespBody), UserAgent: ex.ReqHdr.Get("User-Agent"),
	}
	r.Fields, r.Files = multipartNames(ex)
	return r
}

// Endpoint returns host:port for display, preferring the Host header.
func (s *Session) Endpoint() string {
	if s.Server != "" {
		if ap, err := netip.ParseAddrPort(s.Server); err == nil && s.Host != "" && !strings.Contains(s.Host, ap.Addr().String()) {
			return s.Host + " (" + s.Server + ")"
		}
		return s.Server
	}
	return s.Host
}
