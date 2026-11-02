package eio

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestV4Payload(t *testing.T) {
	body := []byte("4hello\x1e2\x1ebAQID\x1e42[\"command\",{\"message\":\"whoami\"}]")
	pkts, err := DecodePayload(body, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 4 {
		t.Fatalf("got %d packets", len(pkts))
	}
	if pkts[0].Type != Message || string(pkts[0].Data) != "hello" {
		t.Errorf("pkt0 = %+v", pkts[0])
	}
	if pkts[1].Type != Ping {
		t.Errorf("pkt1 = %+v", pkts[1])
	}
	if !pkts[2].Binary || string(pkts[2].Data) != "\x01\x02\x03" {
		t.Errorf("pkt2 = %+v", pkts[2])
	}
}

func TestV3TextLengthsAreUTF16(t *testing.T) {
	// "é" is one UTF-16 unit (2 UTF-8 bytes); the otter is a surrogate pair
	// (2 units, 4 bytes). A byte-counting decoder desyncs on both.
	p1 := `42["message","café"]`
	p2 := `42["message","🦦"]`
	body := []byte(lenU16(p1) + ":" + p1 + lenU16(p2) + ":" + p2 + "1:2")
	pkts, err := DecodePayload(body, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 3 || string(pkts[0].Data) != p1[1:] || string(pkts[1].Data) != p2[1:] || pkts[2].Type != Ping {
		t.Fatalf("decoded %+v", pkts)
	}
}

func lenU16(s string) string {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestV3BinaryFraming(t *testing.T) {
	// string packet "4hi" (len 3), then binary message 0x04 + {0xde,0xad}
	body := []byte{0x00, 3, 0xff, '4', 'h', 'i', 0x01, 3, 0xff, 0x04, 0xde, 0xad}
	pkts, err := DecodePayload(body, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 || string(pkts[0].Data) != "hi" || !pkts[1].Binary || pkts[1].Type != Message || string(pkts[1].Data) != "\xde\xad" {
		t.Fatalf("decoded %+v", pkts)
	}
}

func TestMalformed(t *testing.T) {
	for _, body := range []string{"x4hello", "99:4short", "4:"} {
		if _, err := DecodePayload([]byte(body), 3); err == nil {
			t.Errorf("v3 %q: no error", body)
		}
	}
	if _, err := DecodePayload([]byte("9oops"), 4); err == nil {
		t.Error("v4 bad type: no error")
	}
}

func TestSocketIOPackets(t *testing.T) {
	cases := []struct {
		in      string
		typ     SIOType
		nsp     string
		id      int
		att     int
		event   string
		dataNil bool
	}{
		{"0", SIOConnect, "/", -1, 0, "", true},
		{`0{"token":"x"}`, SIOConnect, "/", -1, 0, "", false},
		{`0/admin,{"sid":"a"}`, SIOConnect, "/admin", -1, 0, "", false},
		{`2["command",{"message":"id"}]`, SIOEvent, "/", -1, 0, "command", false},
		{`2/shell,12["exec","ls"]`, SIOEvent, "/shell", 12, 0, "exec", false},
		{`31["ok"]`, SIOAck, "/", 1, 0, "", false},
		{`51-["file",{"_placeholder":true,"num":0}]`, SIOBinaryEvent, "/", -1, 1, "file", false},
		{`52-/up,7["two",{"_placeholder":true,"num":0},{"_placeholder":true,"num":1}]`, SIOBinaryEvent, "/up", 7, 2, "two", false},
		{"1/admin,", SIODisconnect, "/admin", -1, 0, "", true},
	}
	for _, c := range cases {
		p, err := DecodeSocketIO([]byte(c.in))
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if p.Type != c.typ || p.Namespace != c.nsp || p.ID != c.id || p.Attachments != c.att || (p.Data == nil) != c.dataNil {
			t.Errorf("%q: got %+v", c.in, p)
		}
		if ev, _, ok := p.Event(); c.event != "" && (!ok || ev != c.event) {
			t.Errorf("%q: event %q", c.in, ev)
		}
	}
	for _, bad := range []string{"", "9", `2["unterminated`, "5[]"} {
		if _, err := DecodeSocketIO([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestFillAttachments(t *testing.T) {
	data := json.RawMessage(`{"name":"a.txt","data":{"_placeholder":true,"num":0},"x":[{"_placeholder":true,"num":1}]}`)
	got := FillAttachments(data, [][]byte{[]byte("abc"), []byte("de")}, func(b []byte) any { return len(b) })
	if s := string(got); !strings.Contains(s, `"data":3`) || !strings.Contains(s, `"x":[2]`) {
		t.Errorf("got %s", s)
	}
}
