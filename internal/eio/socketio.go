package eio

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// SIOType is a Socket.IO packet type.
type SIOType byte

const (
	SIOConnect SIOType = iota
	SIODisconnect
	SIOEvent
	SIOAck
	SIOConnectError // "ERROR" in protocol v4 (socket.io 2.x)
	SIOBinaryEvent
	SIOBinaryAck
)

func (t SIOType) String() string {
	switch t {
	case SIOConnect:
		return "CONNECT"
	case SIODisconnect:
		return "DISCONNECT"
	case SIOEvent:
		return "EVENT"
	case SIOAck:
		return "ACK"
	case SIOConnectError:
		return "CONNECT_ERROR"
	case SIOBinaryEvent:
		return "BINARY_EVENT"
	case SIOBinaryAck:
		return "BINARY_ACK"
	}
	return fmt.Sprintf("TYPE%d", byte(t))
}

// SIOPacket is one decoded Socket.IO packet.
type SIOPacket struct {
	Type        SIOType
	Namespace   string
	ID          int // ack id, -1 if none
	Attachments int
	Data        json.RawMessage // nil if the packet carried no payload
}

// Event returns the event name and arguments of an EVENT/BINARY_EVENT.
func (p SIOPacket) Event() (string, []json.RawMessage, bool) {
	if p.Type != SIOEvent && p.Type != SIOBinaryEvent {
		return "", nil, false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(p.Data, &arr); err != nil || len(arr) == 0 {
		return "", nil, false
	}
	var name string
	if err := json.Unmarshal(arr[0], &name); err != nil {
		return "", nil, false
	}
	return name, arr[1:], true
}

// DecodeSocketIO parses the payload of an Engine.IO message packet:
//
//	<type>[<attachments>-][<namespace>,][<ack id>][<json>]
func DecodeSocketIO(b []byte) (SIOPacket, error) {
	p := SIOPacket{ID: -1}
	if len(b) == 0 || b[0] < '0' || b[0] > '6' {
		return p, fmt.Errorf("%w: bad socket.io type", ErrMalformed)
	}
	p.Type = SIOType(b[0] - '0')
	i := 1

	if p.Type == SIOBinaryEvent || p.Type == SIOBinaryAck {
		j := i
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			j++
		}
		if j == i || j >= len(b) || b[j] != '-' {
			return p, fmt.Errorf("%w: binary packet without attachment count", ErrMalformed)
		}
		p.Attachments, _ = strconv.Atoi(string(b[i:j]))
		i = j + 1
	}

	p.Namespace = "/"
	if i < len(b) && b[i] == '/' {
		j := i
		for j < len(b) && b[j] != ',' {
			j++
		}
		p.Namespace = string(b[i:j])
		i = j
		if i < len(b) {
			i++ // the comma
		}
	}

	j := i
	for j < len(b) && b[j] >= '0' && b[j] <= '9' {
		j++
	}
	if j > i {
		p.ID, _ = strconv.Atoi(string(b[i:j]))
		i = j
	}

	if i < len(b) {
		if !json.Valid(b[i:]) {
			return p, fmt.Errorf("%w: invalid JSON payload", ErrMalformed)
		}
		p.Data = json.RawMessage(append([]byte(nil), b[i:]...))
	}
	return p, nil
}

// FillAttachments replaces {"_placeholder":true,"num":N} entries in a binary
// packet's payload with a description of the attachment, so the transcript
// shows where the binary data went.
func FillAttachments(data json.RawMessage, att [][]byte, describe func([]byte) any) json.RawMessage {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return data
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			if ph, _ := t["_placeholder"].(bool); ph {
				if n, ok := t["num"].(float64); ok && int(n) >= 0 && int(n) < len(att) {
					return describe(att[int(n)])
				}
			}
			for k, y := range t {
				t[k] = walk(y)
			}
		case []any:
			for i, y := range t {
				t[i] = walk(y)
			}
		}
		return x
	}
	out, err := json.Marshal(walk(v))
	if err != nil {
		return data
	}
	return out
}
