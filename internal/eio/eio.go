// Package eio decodes the Engine.IO transport and the Socket.IO protocol
// that rides on it, which is how OtterCookie's shell module talks to its C2.
//
// Engine.IO is the transport layer: a session id handshake, ping/pong, and
// a "message" packet type that carries Socket.IO packets. It runs over HTTP
// long-polling, WebSocket, or polling first and then an upgrade to WebSocket
// (the default for socket.io-client, and what Talos observed on port 1418).
//
// Two protocol revisions matter in practice:
//
//	EIO=3  socket.io 2.x. Polling payloads are length-prefixed: "12:4hello..."
//	       for text, or a binary framing with 0x00/0x01 type bytes.
//	EIO=4  socket.io 3.x and 4.x. Polling payloads are packets joined by the
//	       ASCII record separator 0x1e; binary packets are base64 with a "b"
//	       prefix.
//
// Both are decoded. The version comes from the EIO= query parameter on the
// handshake request.
//
// Spec: https://github.com/socketio/engine.io-protocol and
// https://github.com/socketio/socket.io-protocol
package eio

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// PacketType is an Engine.IO packet type.
type PacketType byte

const (
	Open PacketType = iota
	Close
	Ping
	Pong
	Message
	Upgrade
	Noop
)

func (t PacketType) String() string {
	switch t {
	case Open:
		return "open"
	case Close:
		return "close"
	case Ping:
		return "ping"
	case Pong:
		return "pong"
	case Message:
		return "message"
	case Upgrade:
		return "upgrade"
	case Noop:
		return "noop"
	}
	return fmt.Sprintf("type%d", byte(t))
}

// Packet is one Engine.IO packet.
type Packet struct {
	Type   PacketType
	Data   []byte
	Binary bool
}

var ErrMalformed = errors.New("malformed engine.io payload")

// DecodePayload splits an HTTP long-polling body into packets.
func DecodePayload(body []byte, version int) ([]Packet, error) {
	if version >= 4 {
		return decodeV4(body)
	}
	if len(body) > 0 && (body[0] == 0x00 || body[0] == 0x01) {
		return decodeV3Binary(body)
	}
	return decodeV3Text(body)
}

func decodeV4(body []byte) ([]Packet, error) {
	var out []Packet
	start := 0
	for i := 0; i <= len(body); i++ {
		if i < len(body) && body[i] != 0x1e {
			continue
		}
		chunk := body[start:i]
		start = i + 1
		if len(chunk) == 0 {
			continue
		}
		if chunk[0] == 'b' {
			data, err := base64.StdEncoding.DecodeString(string(chunk[1:]))
			if err != nil {
				return out, fmt.Errorf("%w: bad base64 binary packet", ErrMalformed)
			}
			out = append(out, Packet{Type: Message, Data: data, Binary: true})
			continue
		}
		p, err := DecodePacket(chunk, false, 4)
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// decodeV3Text handles "<len>:<packet><len>:<packet>...". The length counts
// UTF-16 code units, because the reference implementation is JavaScript and
// uses String.length. Getting this wrong only shows up with non-ASCII
// payloads, which is exactly when command output is interesting.
func decodeV3Text(body []byte) ([]Packet, error) {
	var out []Packet
	s := body
	for len(s) > 0 {
		colon := -1
		for i, c := range s {
			if c == ':' {
				colon = i
				break
			}
			if c < '0' || c > '9' {
				return out, fmt.Errorf("%w: expected length prefix", ErrMalformed)
			}
		}
		if colon <= 0 {
			return out, fmt.Errorf("%w: missing ':'", ErrMalformed)
		}
		n, _ := strconv.Atoi(string(s[:colon]))
		s = s[colon+1:]
		size := utf16Prefix(s, n)
		if size < 0 {
			return out, fmt.Errorf("%w: length %d overruns payload", ErrMalformed, n)
		}
		chunk := s[:size]
		s = s[size:]
		if len(chunk) > 0 && chunk[0] == 'b' {
			// base64 binary in text mode: "b4<base64>"
			if len(chunk) < 2 {
				return out, ErrMalformed
			}
			data, err := base64.StdEncoding.DecodeString(string(chunk[2:]))
			if err != nil {
				return out, fmt.Errorf("%w: bad base64", ErrMalformed)
			}
			out = append(out, Packet{Type: PacketType(chunk[1] - '0'), Data: data, Binary: true})
			continue
		}
		p, err := DecodePacket(chunk, false, 3)
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// utf16Prefix returns how many bytes of UTF-8 s make up n UTF-16 code units,
// or -1 if s is too short.
func utf16Prefix(s []byte, n int) int {
	units, i := 0, 0
	for units < n {
		if i >= len(s) {
			return -1
		}
		r, size := utf8.DecodeRune(s[i:])
		if utf16.IsSurrogate(r) || r > 0xffff {
			units += 2
		} else {
			units++
		}
		i += size
	}
	return i
}

// decodeV3Binary handles the XHR2 framing: one type byte (0 string, 1
// binary), the length as decimal digits one per byte, 0xff, then the data.
func decodeV3Binary(body []byte) ([]Packet, error) {
	var out []Packet
	s := body
	for len(s) > 0 {
		isBinary := s[0] == 1
		i := 1
		n := 0
		for ; i < len(s) && s[i] != 0xff; i++ {
			if s[i] > 9 {
				return out, fmt.Errorf("%w: bad binary length", ErrMalformed)
			}
			n = n*10 + int(s[i])
		}
		if i >= len(s) {
			return out, ErrMalformed
		}
		s = s[i+1:]
		if !isBinary {
			size := utf16Prefix(s, n)
			if size < 0 {
				return out, ErrMalformed
			}
			p, err := DecodePacket(s[:size], false, 3)
			if err != nil {
				return out, err
			}
			out = append(out, p)
			s = s[size:]
			continue
		}
		if n > len(s) || n < 1 {
			return out, ErrMalformed
		}
		out = append(out, Packet{Type: PacketType(s[0]), Data: append([]byte(nil), s[1:n]...), Binary: true})
		s = s[n:]
	}
	return out, nil
}

// DecodePacket decodes a single packet as carried in a WebSocket frame.
// binary is true for WebSocket binary frames. In EIO=4 a binary frame is
// always a message with no type byte; in EIO=3 it starts with the type.
func DecodePacket(frame []byte, binary bool, version int) (Packet, error) {
	if binary {
		if version >= 4 {
			return Packet{Type: Message, Data: frame, Binary: true}, nil
		}
		if len(frame) == 0 {
			return Packet{}, ErrMalformed
		}
		return Packet{Type: PacketType(frame[0]), Data: frame[1:], Binary: true}, nil
	}
	if len(frame) == 0 || frame[0] < '0' || frame[0] > '6' {
		return Packet{}, fmt.Errorf("%w: bad packet type %q", ErrMalformed, frame)
	}
	return Packet{Type: PacketType(frame[0] - '0'), Data: frame[1:]}, nil
}
