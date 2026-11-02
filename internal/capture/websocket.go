package capture

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

// WSMessage is one complete WebSocket data message (after reassembling
// fragments and inflating permessage-deflate).
type WSMessage struct {
	Time   time.Time
	Binary bool
	Data   []byte
}

// Deflate holds the negotiated permessage-deflate parameters for one
// direction.
type Deflate struct {
	Enabled           bool
	NoContextTakeover bool
}

// NegotiatedDeflate reads the server's Sec-WebSocket-Extensions answer and
// returns the parameters for client->server and server->client messages.
func NegotiatedDeflate(ext string) (up, down Deflate) {
	for _, e := range strings.Split(ext, ",") {
		params := strings.Split(e, ";")
		if strings.TrimSpace(params[0]) != "permessage-deflate" {
			continue
		}
		up.Enabled, down.Enabled = true, true
		for _, p := range params[1:] {
			switch strings.TrimSpace(strings.SplitN(p, "=", 2)[0]) {
			case "client_no_context_takeover":
				up.NoContextTakeover = true
			case "server_no_context_takeover":
				down.NoContextTakeover = true
			}
		}
		break
	}
	return up, down
}

var errShortFrame = errors.New("short websocket frame")

// WSMessages decodes the frames in b (which starts at a frame boundary)
// into messages. Control frames are dropped; close ends the stream.
func WSMessages(s *Stream, start int, dfl Deflate) []WSMessage {
	b := s.Data[start:]
	var out []WSMessage
	var cur []byte
	var curBinary, curCompressed bool
	var curStart int
	var window []byte // permessage-deflate sliding window (context takeover)

	off := 0
	for off < len(b) {
		fr, n, err := readFrame(b[off:])
		if err != nil {
			break
		}
		frameOff := off
		off += n

		switch fr.opcode {
		case 0x8: // close
			return out
		case 0x9, 0xa: // ping, pong
			continue
		case 0x1, 0x2:
			cur = append(cur[:0], fr.payload...)
			curBinary = fr.opcode == 0x2
			curCompressed = fr.rsv1
			curStart = frameOff
		case 0x0:
			cur = append(cur, fr.payload...)
		default:
			continue
		}
		if !fr.fin {
			continue
		}

		data := append([]byte(nil), cur...)
		if curCompressed && dfl.Enabled {
			inflated, ok := inflate(data, window)
			if ok {
				data = inflated
				if !dfl.NoContextTakeover {
					window = append(window, data...)
					if len(window) > 32<<10 {
						window = window[len(window)-32<<10:]
					}
				}
			}
		}
		out = append(out, WSMessage{Time: s.TimeAt(start + curStart), Binary: curBinary, Data: data})
		cur = cur[:0]
	}
	return out
}

type frame struct {
	fin, rsv1 bool
	opcode    byte
	payload   []byte
}

func readFrame(b []byte) (frame, int, error) {
	if len(b) < 2 {
		return frame{}, 0, errShortFrame
	}
	f := frame{fin: b[0]&0x80 != 0, rsv1: b[0]&0x40 != 0, opcode: b[0] & 0x0f}
	masked := b[1]&0x80 != 0
	n := uint64(b[1] & 0x7f)
	i := 2
	switch n {
	case 126:
		if len(b) < 4 {
			return frame{}, 0, errShortFrame
		}
		n = uint64(binary.BigEndian.Uint16(b[2:4]))
		i = 4
	case 127:
		if len(b) < 10 {
			return frame{}, 0, errShortFrame
		}
		n = binary.BigEndian.Uint64(b[2:10])
		i = 10
	}
	var key [4]byte
	if masked {
		if len(b) < i+4 {
			return frame{}, 0, errShortFrame
		}
		copy(key[:], b[i:i+4])
		i += 4
	}
	if n > uint64(len(b)-i) {
		return frame{}, 0, errShortFrame
	}
	p := append([]byte(nil), b[i:i+int(n)]...)
	if masked {
		for j := range p {
			p[j] ^= key[j&3]
		}
	}
	f.payload = p
	return f, i + int(n), nil
}

// inflate decompresses one permessage-deflate message (RFC 7692 7.2.2): the
// sender strips the trailing 00 00 ff ff of a sync flush, so it goes back on
// before inflating. With context takeover, the previous plaintext is the
// LZ77 window and is supplied as the preset dictionary.
func inflate(data, window []byte) ([]byte, bool) {
	msg := append(append([]byte(nil), data...), 0x00, 0x00, 0xff, 0xff)
	r := flate.NewReaderDict(bytes.NewReader(msg), window)
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false
	}
	return out, true
}
