// Package capture reads packet captures and rebuilds the TCP conversations
// in them, enough to recover HTTP, WebSocket and Engine.IO traffic. It is a
// small, dependency-free reader for the formats and link types that show up
// in sandbox and IR captures, not a general dissector.
package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// Link types (http://www.tcpdump.org/linktypes.html).
const (
	LinkNull     = 0
	LinkEthernet = 1
	LinkRawBSD   = 12
	LinkRawBSD2  = 14
	LinkRaw      = 101
	LinkLoop     = 108
	LinkSLL      = 113
	LinkIPv4     = 228
	LinkIPv6     = 229
	LinkSLL2     = 276
)

// Frame is one captured link-layer frame.
type Frame struct {
	Time     time.Time
	LinkType int
	Data     []byte
}

// ReadAll reads every frame from a pcap or pcapng stream.
func ReadAll(r io.Reader) ([]Frame, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	switch {
	case binary.LittleEndian.Uint32(magic) == 0x0a0d0d0a:
		return readPcapng(br)
	default:
		return readPcap(br)
	}
}

func readPcap(r io.Reader) ([]Frame, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	var bo binary.ByteOrder
	nano := false
	switch m := binary.LittleEndian.Uint32(hdr[:4]); m {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	case 0xd4c3b2a1:
		bo = binary.BigEndian
	case 0x4d3cb2a1:
		bo, nano = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("not a pcap or pcapng file (magic %#08x)", m)
	}
	link := int(bo.Uint32(hdr[20:24]) & 0x0fffffff)

	var out []Frame
	var rec [16]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil // truncated capture: keep what we have
			}
			return out, err
		}
		sec := int64(bo.Uint32(rec[0:4]))
		frac := int64(bo.Uint32(rec[4:8]))
		incl := bo.Uint32(rec[8:12])
		if incl > 256<<20 {
			return out, fmt.Errorf("pcap record of %d bytes, file is corrupt", incl)
		}
		data := make([]byte, incl)
		if _, err := io.ReadFull(r, data); err != nil {
			return out, nil
		}
		if !nano {
			frac *= 1000
		}
		out = append(out, Frame{Time: time.Unix(sec, frac).UTC(), LinkType: link, Data: data})
	}
}

type pcapngIface struct {
	link  int
	tsDiv float64 // ticks per second
}

func readPcapng(r io.Reader) ([]Frame, error) {
	var out []Frame
	var bo binary.ByteOrder = binary.LittleEndian
	var ifaces []pcapngIface

	for {
		var head [8]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil
			}
			return out, err
		}
		btype := binary.LittleEndian.Uint32(head[0:4])
		if btype == 0x0a0d0d0a {
			// Section header: the byte-order magic decides endianness for
			// everything in this section, including this block's length.
			var bom [4]byte
			if _, err := io.ReadFull(r, bom[:]); err != nil {
				return out, nil
			}
			switch binary.LittleEndian.Uint32(bom[:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return out, fmt.Errorf("pcapng: bad byte-order magic")
			}
			blen := bo.Uint32(head[4:8])
			if blen < 28 || blen > 64<<20 {
				return out, fmt.Errorf("pcapng: bad section header length %d", blen)
			}
			if _, err := io.CopyN(io.Discard, r, int64(blen)-12); err != nil {
				return out, nil
			}
			ifaces = nil
			continue
		}
		btype = bo.Uint32(head[0:4])
		blen := bo.Uint32(head[4:8])
		if blen < 12 || blen%4 != 0 || blen > 256<<20 {
			return out, fmt.Errorf("pcapng: bad block length %d", blen)
		}
		body := make([]byte, blen-12)
		if _, err := io.ReadFull(r, body); err != nil {
			return out, nil
		}
		var trailer [4]byte
		if _, err := io.ReadFull(r, trailer[:]); err != nil {
			return out, nil
		}

		switch btype {
		case 1: // interface description
			if len(body) < 8 {
				continue
			}
			ifc := pcapngIface{link: int(bo.Uint16(body[0:2])), tsDiv: 1e6}
			parseOptions(body[8:], bo, func(code uint16, val []byte) {
				if code == 9 && len(val) >= 1 { // if_tsresol
					v := val[0]
					if v&0x80 == 0 {
						ifc.tsDiv = math.Pow(10, float64(v))
					} else {
						ifc.tsDiv = math.Pow(2, float64(v&0x7f))
					}
				}
			})
			ifaces = append(ifaces, ifc)
		case 6: // enhanced packet
			if len(body) < 20 {
				continue
			}
			id := int(bo.Uint32(body[0:4]))
			if id >= len(ifaces) {
				continue
			}
			ts := uint64(bo.Uint32(body[4:8]))<<32 | uint64(bo.Uint32(body[8:12]))
			capLen := int(bo.Uint32(body[12:16]))
			if 20+capLen > len(body) {
				continue
			}
			out = append(out, Frame{
				Time:     tsTime(ts, ifaces[id].tsDiv),
				LinkType: ifaces[id].link,
				Data:     append([]byte(nil), body[20:20+capLen]...),
			})
		case 3: // simple packet: interface 0, no timestamp
			if len(body) < 4 || len(ifaces) == 0 {
				continue
			}
			orig := int(bo.Uint32(body[0:4]))
			n := len(body) - 4
			if orig < n {
				n = orig
			}
			out = append(out, Frame{LinkType: ifaces[0].link, Data: append([]byte(nil), body[4:4+n]...)})
		case 2: // obsolete packet block
			if len(body) < 20 {
				continue
			}
			id := int(bo.Uint16(body[0:2]))
			if id >= len(ifaces) {
				continue
			}
			ts := uint64(bo.Uint32(body[4:8]))<<32 | uint64(bo.Uint32(body[8:12]))
			capLen := int(bo.Uint32(body[12:16]))
			if 20+capLen > len(body) {
				continue
			}
			out = append(out, Frame{Time: tsTime(ts, ifaces[id].tsDiv), LinkType: ifaces[id].link, Data: append([]byte(nil), body[20:20+capLen]...)})
		}
	}
}

func tsTime(ticks uint64, perSec float64) time.Time {
	sec := float64(ticks) / perSec
	whole := math.Floor(sec)
	return time.Unix(int64(whole), int64((sec-whole)*1e9)).UTC()
}

func parseOptions(b []byte, bo binary.ByteOrder, fn func(code uint16, val []byte)) {
	for len(b) >= 4 {
		code := bo.Uint16(b[0:2])
		n := int(bo.Uint16(b[2:4]))
		if code == 0 || 4+n > len(b) {
			return
		}
		fn(code, b[4:4+n])
		adv := 4 + (n+3)&^3
		if adv > len(b) {
			return
		}
		b = b[adv:]
	}
}
