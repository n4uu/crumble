// Package fixture builds synthetic test material: packet captures of a
// socket.io C2 conversation that never happened, written byte for byte the
// way socket.io-client and an Engine.IO server would put it on the wire.
// Every address is from the RFC 5737 documentation ranges.
package fixture

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

// Format selects the capture container.
type Format int

const (
	Pcap Format = iota
	Pcapng
)

// packet is one Ethernet/IPv4/TCP frame waiting to be written.
type packet struct {
	t    time.Time
	data []byte
}

type tcpConn struct {
	w          *Writer
	cli, srv   netip.AddrPort
	cseq, sseq uint32
}

// Writer accumulates frames and writes them as pcap or pcapng.
type Writer struct {
	now     time.Time
	packets []packet
	ipid    uint16
}

// NewWriter starts a capture at t.
func NewWriter(t time.Time) *Writer { return &Writer{now: t} }

func (w *Writer) tick(d time.Duration) time.Time {
	w.now = w.now.Add(d)
	return w.now
}

// Dial records a three-way handshake and returns the connection.
func (w *Writer) Dial(cli, srv netip.AddrPort, isn uint32) *tcpConn {
	c := &tcpConn{w: w, cli: cli, srv: srv, cseq: isn, sseq: isn ^ 0x5a5a5a5a}
	c.emit(true, 0x02, nil) // SYN
	c.cseq++
	c.w.tick(18 * time.Millisecond)
	c.emit(false, 0x12, nil) // SYN/ACK
	c.sseq++
	c.w.tick(150 * time.Microsecond)
	c.emit(true, 0x10, nil) // ACK
	return c
}

// Send writes data from the client (up) or server, split at a 1448-byte MSS.
func (c *tcpConn) Send(up bool, data []byte) {
	c.w.tick(2 * time.Millisecond)
	for len(data) > 0 {
		n := len(data)
		if n > 1448 {
			n = 1448
		}
		c.emit(up, 0x18, data[:n]) // PSH/ACK
		if up {
			c.cseq += uint32(n)
		} else {
			c.sseq += uint32(n)
		}
		data = data[n:]
		c.w.tick(40 * time.Microsecond)
	}
}

// Close records a FIN exchange.
func (c *tcpConn) Close() {
	c.w.tick(time.Millisecond)
	c.emit(true, 0x11, nil)
	c.cseq++
	c.emit(false, 0x11, nil)
	c.sseq++
	c.emit(true, 0x10, nil)
}

func (c *tcpConn) emit(up bool, flags byte, payload []byte) {
	src, dst, seq, ack := c.cli, c.srv, c.cseq, c.sseq
	if !up {
		src, dst, seq, ack = c.srv, c.cli, c.sseq, c.cseq
	}
	if flags == 0x02 {
		ack = 0
	}
	c.w.ipid++
	c.w.packets = append(c.w.packets, packet{t: c.w.now, data: frame(src, dst, seq, ack, flags, payload, c.w.ipid)})
}

// frame builds Ethernet + IPv4 + TCP with correct checksums, so the result
// opens cleanly in Wireshark as well as in crumble.
func frame(src, dst netip.AddrPort, seq, ack uint32, flags byte, payload []byte, id uint16) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], payload)

	s, d := src.Addr().As4(), dst.Addr().As4()
	pseudo := make([]byte, 0, 12+len(tcp))
	pseudo = append(pseudo, s[:]...)
	pseudo = append(pseudo, d[:]...)
	pseudo = append(pseudo, 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	binary.BigEndian.PutUint16(ip[4:], id)
	ip[6] = 0x40 // don't fragment
	ip[8] = 128
	ip[9] = 6
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))

	eth := []byte{0x00, 0x15, 0x5d, 0x01, 0x02, 0x03, 0x00, 0x15, 0x5d, 0x0a, 0x0b, 0x0c, 0x08, 0x00}
	if src.Port() > dst.Port() { // client -> server: swap MACs for realism
		copy(eth[0:6], []byte{0x00, 0x15, 0x5d, 0x0a, 0x0b, 0x0c})
		copy(eth[6:12], []byte{0x00, 0x15, 0x5d, 0x01, 0x02, 0x03})
	}
	return append(append(eth, ip...), tcp...)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// WriteTo writes the capture.
func (w *Writer) WriteTo(out io.Writer, f Format) error {
	var b bytes.Buffer
	le := binary.LittleEndian
	if f == Pcap {
		hdr := make([]byte, 24)
		le.PutUint32(hdr[0:], 0xa1b2c3d4)
		le.PutUint16(hdr[4:], 2)
		le.PutUint16(hdr[6:], 4)
		le.PutUint32(hdr[16:], 65535)
		le.PutUint32(hdr[20:], 1) // Ethernet
		b.Write(hdr)
		for _, p := range w.packets {
			rec := make([]byte, 16)
			le.PutUint32(rec[0:], uint32(p.t.Unix()))
			le.PutUint32(rec[4:], uint32(p.t.Nanosecond()/1000))
			le.PutUint32(rec[8:], uint32(len(p.data)))
			le.PutUint32(rec[12:], uint32(len(p.data)))
			b.Write(rec)
			b.Write(p.data)
		}
	} else {
		block := func(typ uint32, body []byte) {
			pad := (4 - len(body)%4) % 4
			total := uint32(12 + len(body) + pad)
			h := make([]byte, 8)
			le.PutUint32(h[0:], typ)
			le.PutUint32(h[4:], total)
			b.Write(h)
			b.Write(body)
			b.Write(make([]byte, pad))
			t := make([]byte, 4)
			le.PutUint32(t, total)
			b.Write(t)
		}
		shb := make([]byte, 16)
		le.PutUint32(shb[0:], 0x1a2b3c4d)
		le.PutUint16(shb[4:], 1)
		le.PutUint64(shb[8:], 0xffffffffffffffff)
		block(0x0a0d0d0a, shb)
		idb := make([]byte, 8)
		le.PutUint16(idb[0:], 1)
		le.PutUint32(idb[4:], 65535)
		// if_tsresol = 9 (nanoseconds), then opt_endofopt
		idb = append(idb, 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0)
		block(1, idb)
		for _, p := range w.packets {
			ts := uint64(p.t.UnixNano())
			epb := make([]byte, 20)
			le.PutUint32(epb[4:], uint32(ts>>32))
			le.PutUint32(epb[8:], uint32(ts))
			le.PutUint32(epb[12:], uint32(len(p.data)))
			le.PutUint32(epb[16:], uint32(len(p.data)))
			block(6, append(epb, p.data...))
		}
	}
	_, err := out.Write(b.Bytes())
	return err
}

// ---------------------------------------------------------------------------
// WebSocket framing

func wsFrame(opcode byte, payload []byte, masked, compressed bool, key [4]byte) []byte {
	b0 := 0x80 | opcode
	if compressed {
		b0 |= 0x40
	}
	out := []byte{b0}
	m := byte(0)
	if masked {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 65536:
		out = append(out, m|126, byte(n>>8), byte(n))
	default:
		out = append(out, m|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if masked {
		out = append(out, key[:]...)
		p := append([]byte(nil), payload...)
		for i := range p {
			p[i] ^= key[i&3]
		}
		return append(out, p...)
	}
	return append(out, payload...)
}

// deflateMessage compresses one permessage-deflate message with a fresh
// context (the fixture negotiates client_no_context_takeover).
func deflateMessage(p []byte) []byte {
	var b bytes.Buffer
	fw, _ := flate.NewWriter(&b, flate.BestCompression)
	fw.Write(p)
	fw.Flush()
	out := b.Bytes()
	return bytes.TrimSuffix(out, []byte{0x00, 0x00, 0xff, 0xff})
}

func httpReq(method, target, host string, hdrs []string, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, target, host)
	for _, h := range hdrs {
		b.WriteString(h + "\r\n")
	}
	if body != "" || method == "POST" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n" + body)
	return []byte(b.String())
}

func httpResp(status string, hdrs []string, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", status)
	for _, h := range hdrs {
		b.WriteString(h + "\r\n")
	}
	if !strings.HasPrefix(status, "101") {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n" + body)
	return []byte(b.String())
}
