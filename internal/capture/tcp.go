package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"time"
)

// segment is one TCP segment with payload or a SYN/FIN flag.
type segment struct {
	src, dst netip.AddrPort
	seq      uint32
	syn, ack bool
	fin, rst bool
	payload  []byte
	time     time.Time
}

// decodeTCP walks link -> IP -> TCP. Non-TCP traffic and IP fragments are
// skipped; fragmented TCP is vanishingly rare on the paths this tool cares
// about and reassembling it isn't worth the code.
func decodeTCP(f Frame) (segment, bool) {
	ip, v, ok := linkPayload(f.LinkType, f.Data)
	if !ok {
		return segment{}, false
	}
	var src, dst netip.Addr
	var tcp []byte
	switch v {
	case 4:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return segment{}, false
		}
		ihl := int(ip[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if ihl < 20 || len(ip) < ihl || ip[9] != 6 {
			return segment{}, false
		}
		if frag := binary.BigEndian.Uint16(ip[6:8]); frag&0x3fff != 0 {
			return segment{}, false // MF set or non-zero offset
		}
		if total >= ihl && total <= len(ip) {
			ip = ip[:total] // drop Ethernet padding
		}
		src = netip.AddrFrom4([4]byte(ip[12:16]))
		dst = netip.AddrFrom4([4]byte(ip[16:20]))
		tcp = ip[ihl:]
	case 6:
		if len(ip) < 40 || ip[0]>>4 != 6 {
			return segment{}, false
		}
		plen := int(binary.BigEndian.Uint16(ip[4:6]))
		if 40+plen <= len(ip) {
			ip = ip[:40+plen]
		}
		src = netip.AddrFrom16([16]byte(ip[8:24]))
		dst = netip.AddrFrom16([16]byte(ip[24:40]))
		next := ip[6]
		rest := ip[40:]
		for next != 6 {
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(rest) < 8 {
					return segment{}, false
				}
				n := (int(rest[1]) + 1) * 8
				if n > len(rest) {
					return segment{}, false
				}
				next, rest = rest[0], rest[n:]
			default: // fragment header (44) or not TCP
				return segment{}, false
			}
		}
		tcp = rest
	default:
		return segment{}, false
	}

	if len(tcp) < 20 {
		return segment{}, false
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		return segment{}, false
	}
	flags := tcp[13]
	return segment{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		fin:     flags&0x01 != 0,
		syn:     flags&0x02 != 0,
		rst:     flags&0x04 != 0,
		ack:     flags&0x10 != 0,
		payload: tcp[off:],
		time:    f.Time,
	}, true
}

// linkPayload strips the link layer and returns the IP packet and version.
func linkPayload(link int, b []byte) ([]byte, int, bool) {
	etherIP := func(et uint16, rest []byte) ([]byte, int, bool) {
		switch et {
		case 0x0800:
			return rest, 4, true
		case 0x86dd:
			return rest, 6, true
		}
		return nil, 0, false
	}
	switch link {
	case LinkEthernet:
		if len(b) < 14 {
			return nil, 0, false
		}
		et := binary.BigEndian.Uint16(b[12:14])
		rest := b[14:]
		for (et == 0x8100 || et == 0x88a8) && len(rest) >= 4 { // VLAN / QinQ
			et = binary.BigEndian.Uint16(rest[2:4])
			rest = rest[4:]
		}
		return etherIP(et, rest)
	case LinkSLL:
		if len(b) < 16 {
			return nil, 0, false
		}
		return etherIP(binary.BigEndian.Uint16(b[14:16]), b[16:])
	case LinkSLL2:
		if len(b) < 20 {
			return nil, 0, false
		}
		return etherIP(binary.BigEndian.Uint16(b[0:2]), b[20:])
	case LinkNull, LinkLoop:
		if len(b) < 4 {
			return nil, 0, false
		}
		fam := binary.LittleEndian.Uint32(b[0:4])
		if link == LinkLoop || fam > 0xffff {
			fam = binary.BigEndian.Uint32(b[0:4])
		}
		switch fam {
		case 2:
			return b[4:], 4, true
		case 10, 24, 28, 30:
			return b[4:], 6, true
		}
		return nil, 0, false
	case LinkRaw, LinkRawBSD, LinkRawBSD2, LinkIPv4, LinkIPv6:
		if len(b) == 0 {
			return nil, 0, false
		}
		switch b[0] >> 4 {
		case 4:
			return b, 4, true
		case 6:
			return b, 6, true
		}
	}
	return nil, 0, false
}

// Stream is one direction of a TCP connection, reassembled.
type Stream struct {
	Data  []byte
	marks []mark // byte offset -> capture time, ascending
	Gaps  int    // holes left by packets missing from the capture
}

type mark struct {
	off int
	t   time.Time
}

// TimeAt returns the capture time of the segment that carried byte off.
func (s *Stream) TimeAt(off int) time.Time {
	i := sort.Search(len(s.marks), func(i int) bool { return s.marks[i].off > off })
	if i == 0 {
		if len(s.marks) > 0 {
			return s.marks[0].t
		}
		return time.Time{}
	}
	return s.marks[i-1].t
}

// Conn is a reassembled TCP connection.
type Conn struct {
	Client, Server netip.AddrPort
	Up, Down       *Stream // client->server, server->client
	Start          time.Time
	SawSYN         bool
}

type half struct {
	isn     uint32
	haveISN bool
	first   uint32
	segs    []segment
}

type connKey struct{ a, b netip.AddrPort }

func keyOf(s segment) connKey {
	if s.src.Addr().Less(s.dst.Addr()) || (s.src.Addr() == s.dst.Addr() && s.src.Port() < s.dst.Port()) {
		return connKey{s.src, s.dst}
	}
	return connKey{s.dst, s.src}
}

// Reassemble groups frames into TCP connections. A new SYN on a 4-tuple
// that already carried data starts a new connection (port reuse in long
// captures is common with a C2 that reconnects every few seconds).
func Reassemble(frames []Frame) []*Conn {
	type state struct {
		conn   *Conn
		halves map[netip.AddrPort]*half
		data   bool
	}
	active := map[connKey]*state{}
	var all []*state

	for _, f := range frames {
		seg, ok := decodeTCP(f)
		if !ok {
			continue
		}
		k := keyOf(seg)
		st := active[k]
		if st != nil && seg.syn && !seg.ack && st.data {
			st = nil
		}
		if st == nil {
			st = &state{conn: &Conn{Start: seg.time}, halves: map[netip.AddrPort]*half{}}
			active[k] = st
			all = append(all, st)
		}
		if seg.syn && !seg.ack {
			st.conn.Client, st.conn.Server, st.conn.SawSYN = seg.src, seg.dst, true
		}
		h := st.halves[seg.src]
		if h == nil {
			h = &half{first: seg.seq}
			st.halves[seg.src] = h
		}
		if seg.syn {
			h.isn, h.haveISN = seg.seq, true
		}
		if len(seg.payload) > 0 {
			st.data = true
			h.segs = append(h.segs, seg)
		}
	}

	var out []*Conn
	for _, st := range all {
		c := st.conn
		if !c.SawSYN {
			c.Client, c.Server = guessRoles(st.halves)
		}
		c.Up = assemble(st.halves[c.Client])
		c.Down = assemble(st.halves[c.Server])
		if len(c.Up.Data) == 0 && len(c.Down.Data) == 0 {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// guessRoles handles captures that start mid-connection: whoever sent an
// HTTP request line is the client; failing that, the higher port.
func guessRoles(halves map[netip.AddrPort]*half) (netip.AddrPort, netip.AddrPort) {
	var eps []netip.AddrPort
	for ep := range halves {
		eps = append(eps, ep)
	}
	if len(eps) == 1 {
		// one-sided capture; treat the sender as the client if it speaks HTTP
		return eps[0], netip.AddrPort{}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].Port() > eps[j].Port() })
	for _, ep := range eps {
		h := halves[ep]
		if len(h.segs) > 0 && looksLikeRequest(h.segs[0].payload) {
			other := eps[0]
			if other == ep {
				other = eps[1]
			}
			return ep, other
		}
	}
	return eps[0], eps[1]
}

var methods = [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "), []byte("OPTIONS "), []byte("DELETE "), []byte("PATCH ")}

func looksLikeRequest(b []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func assemble(h *half) *Stream {
	s := &Stream{}
	if h == nil || len(h.segs) == 0 {
		return s
	}
	base := h.first
	if h.haveISN {
		base = h.isn + 1
	}
	// Offsets are computed modulo 2^32 relative to the base, which handles
	// sequence wraparound for any stream shorter than 2 GiB.
	rel := func(seq uint32) int64 { return int64(int32(seq - base)) }
	sort.SliceStable(h.segs, func(i, j int) bool { return rel(h.segs[i].seq) < rel(h.segs[j].seq) })

	var cursor int64
	if r := rel(h.segs[0].seq); r > 0 && !h.haveISN {
		cursor = r
	}
	for _, seg := range h.segs {
		off := rel(seg.seq)
		end := off + int64(len(seg.payload))
		if end <= cursor {
			continue // retransmission of data we already have
		}
		if off > cursor {
			s.Gaps++
			cursor = off
		}
		s.marks = append(s.marks, mark{off: len(s.Data), t: seg.time})
		s.Data = append(s.Data, seg.payload[cursor-off:]...)
		cursor = end
	}
	return s
}
