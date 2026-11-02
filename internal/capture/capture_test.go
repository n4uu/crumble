package capture

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/crumble/internal/fixture"
)

func readFixture(t *testing.T, f fixture.Format) *Analysis {
	t.Helper()
	var buf bytes.Buffer
	if err := fixture.Write(&buf, fixture.DefaultScenario(), f); err != nil {
		t.Fatal(err)
	}
	frames, err := ReadAll(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(frames)
}

func TestFixtureSession(t *testing.T) {
	for name, f := range map[string]fixture.Format{"pcap": fixture.Pcap, "pcapng": fixture.Pcapng} {
		t.Run(name, func(t *testing.T) {
			a := readFixture(t, f)
			if len(a.Sessions) != 1 {
				t.Fatalf("got %d sessions", len(a.Sessions))
			}
			s := a.Sessions[0]
			if s.SID != "Gq8vRk2LmZ0aT1xXAAAB" || s.EIO != 4 || s.Server != "203.0.113.47:1418" {
				t.Errorf("session header: %+v", s)
			}
			if strings.Join(s.Transports, ",") != "polling,websocket" || s.Connections != 2 || s.PingInterval != 25000 {
				t.Errorf("transports=%v conns=%d ping=%d", s.Transports, s.Connections, s.PingInterval)
			}
			reg := s.Registration()
			if reg == nil || reg.Event != "identify" || !strings.Contains(string(reg.Args[0]), `"uid":"c7f2a1e09b"`) {
				t.Errorf("registration = %+v", reg)
			}

			tasks := s.Taskings()
			want := []string{"whoami", `dir %USERPROFILE%\Documents`, "tasklist /v"}
			if len(tasks) != len(want) {
				t.Fatalf("got %d taskings: %+v", len(tasks), tasks)
			}
			for i, w := range want {
				if tasks[i].Command != w || tasks[i].Event != "command" || tasks[i].Reply != "message" {
					t.Errorf("tasking %d = %+v", i, tasks[i])
				}
			}
			// The dir output went over the wire deflated (RSV1).
			if !strings.Contains(tasks[1].Output, "wallet-recovery.txt") {
				t.Errorf("compressed reply not inflated: %q", tasks[1].Output)
			}

			var bin *Item
			for i := range s.Items {
				if s.Items[i].SIO == "BINARY_EVENT" {
					bin = &s.Items[i]
				}
			}
			if bin == nil || !strings.Contains(string(bin.Args[0]), "synthetic attachment") {
				t.Errorf("binary attachment not merged: %+v", bin)
			}

			if len(a.HTTP) != 1 || a.HTTP[0].Target != "/uploads" || len(a.HTTP[0].Files) != 1 || a.HTTP[0].Files[0] != "Login Data" {
				t.Errorf("upload request: %+v", a.HTTP)
			}
			if notes := a.HTTP[0].Notes(); len(notes) != 2 {
				t.Errorf("upload notes = %v", notes)
			}
			if as := s.Assessment(); len(as) != 2 {
				t.Errorf("assessment = %v", as)
			}
		})
	}
}

// segment builders for hand-made streams

func ethFrame(src, dst netip.AddrPort, seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	copy(tcp[20:], payload)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[9] = 6
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	return append(append(eth, ip...), tcp...)
}

func TestReassemblyOrderAndRetransmits(t *testing.T) {
	cli := netip.MustParseAddrPort("198.51.100.7:40000")
	srv := netip.MustParseAddrPort("203.0.113.47:1418")
	base := time.Unix(1_700_000_000, 0)
	msg := []byte("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	isn := uint32(0xfffffff0) // forces sequence wraparound mid-stream
	frames := []Frame{
		{Time: base, LinkType: LinkEthernet, Data: ethFrame(cli, srv, isn, 0x02, nil)},
		{Time: base.Add(1), LinkType: LinkEthernet, Data: ethFrame(cli, srv, isn+1+10, 0x18, msg[10:20])},
		{Time: base.Add(2), LinkType: LinkEthernet, Data: ethFrame(cli, srv, isn+1, 0x18, msg[:10])},
		{Time: base.Add(3), LinkType: LinkEthernet, Data: ethFrame(cli, srv, isn+1, 0x18, msg[:12])}, // overlapping retransmit
		{Time: base.Add(4), LinkType: LinkEthernet, Data: ethFrame(cli, srv, isn+1+20, 0x18, msg[20:])},
	}
	conns := Reassemble(frames)
	if len(conns) != 1 {
		t.Fatalf("got %d conns", len(conns))
	}
	if got := string(conns[0].Up.Data); got != string(msg) || conns[0].Up.Gaps != 0 {
		t.Errorf("reassembled %q gaps=%d", got, conns[0].Up.Gaps)
	}
	if conns[0].Client != cli {
		t.Errorf("client = %v", conns[0].Client)
	}
}

func TestChunkedGzipResponse(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("0{\"sid\":\"abc\",\"upgrades\":[],\"pingInterval\":1000,\"pingTimeout\":500}\x1e42[\"command\",{\"message\":\"id\"}]"))
	zw.Close()
	z := gz.Bytes()
	half := len(z) / 2
	chunked := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n")
	for _, part := range [][]byte{z[:half], z[half:]} {
		chunked = append(chunked, []byte(strings.ToUpper(strconvHex(len(part)))+"\r\n")...)
		chunked = append(chunked, part...)
		chunked = append(chunked, '\r', '\n')
	}
	chunked = append(chunked, []byte("0\r\n\r\n")...)

	c := &Conn{
		Client: netip.MustParseAddrPort("198.51.100.7:40001"),
		Server: netip.MustParseAddrPort("203.0.113.47:1418"),
		Up:     &Stream{Data: []byte("GET /socket.io/?EIO=4&transport=polling HTTP/1.1\r\nHost: x\r\n\r\n")},
		Down:   &Stream{Data: chunked},
	}
	ex := Exchanges(c)
	if len(ex) != 1 || !bytes.Contains(ex[0].RespBody, []byte(`"command"`)) {
		t.Fatalf("exchanges: %+v", ex)
	}
}

func strconvHex(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%16]}, b...)
		n /= 16
	}
	return string(b)
}

func TestDeflateContextTakeover(t *testing.T) {
	// One deflate stream, flushed per message: the second message
	// back-references the first, so it only inflates with the window.
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	msgs := []string{`42["message","` + strings.Repeat("abcdefgh", 40) + `"]`, `42["message","` + strings.Repeat("abcdefgh", 40) + `!"]`}
	var frames []byte
	for _, m := range msgs {
		start := buf.Len()
		fw.Write([]byte(m))
		fw.Flush()
		payload := bytes.TrimSuffix(buf.Bytes()[start:], []byte{0, 0, 0xff, 0xff})
		frames = append(frames, 0xc1, byte(len(payload)))
		frames = append(frames, payload...)
	}
	s := &Stream{Data: frames}
	got := WSMessages(s, 0, Deflate{Enabled: true})
	if len(got) != 2 || string(got[0].Data) != msgs[0] || string(got[1].Data) != msgs[1] {
		t.Fatalf("got %d messages: %+v", len(got), got)
	}
}

func TestNotPcap(t *testing.T) {
	if _, err := ReadAll(strings.NewReader("definitely not a capture file")); err == nil {
		t.Error("no error for garbage input")
	}
}
