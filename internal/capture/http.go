package capture

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Exchange is one HTTP request and, if it was captured, its response.
type Exchange struct {
	Conn *Conn

	Method   string
	Target   string // request-target as sent, e.g. /socket.io/?EIO=4&transport=polling
	Host     string
	ReqHdr   http.Header
	ReqBody  []byte
	ReqTime  time.Time
	Status   int
	RespHdr  http.Header
	RespBody []byte
	RespTime time.Time

	// For a successful WebSocket upgrade: the offsets in Conn.Up/Down where
	// the frame streams begin.
	Upgraded bool
	WSUp     int
	WSDown   int
}

// Exchanges parses the HTTP/1.x traffic in a connection. It stops at the
// first thing that isn't HTTP, and after a 101 Switching Protocols.
func Exchanges(c *Conn) []*Exchange {
	var out []*Exchange
	up := c.Up.Data
	down := c.Down.Data
	upOff, downOff := 0, 0

	for upOff < len(up) && looksLikeRequest(up[upOff:]) {
		ex := &Exchange{Conn: c, ReqTime: c.Up.TimeAt(upOff)}
		n, ok := parseRequest(up[upOff:], ex)
		if !ok {
			break
		}
		upOff += n
		out = append(out, ex)

		if downOff < len(down) && bytes.HasPrefix(down[downOff:], []byte("HTTP/1.")) {
			ex.RespTime = c.Down.TimeAt(downOff)
			m, ok := parseResponse(down[downOff:], ex)
			if ok {
				downOff += m
			} else {
				downOff = len(down)
			}
		}
		if ex.Status == http.StatusSwitchingProtocols {
			ex.Upgraded = true
			ex.WSUp, ex.WSDown = upOff, downOff
			return out
		}
	}
	return out
}

func parseHead(b []byte) (string, http.Header, int, bool) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return "", nil, 0, false
	}
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(b[:end+4])))
	line, err := tp.ReadLine()
	if err != nil {
		return "", nil, 0, false
	}
	mh, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return "", nil, 0, false
	}
	return line, http.Header(mh), end + 4, true
}

func parseRequest(b []byte, ex *Exchange) (int, bool) {
	line, hdr, n, ok := parseHead(b)
	if !ok {
		return 0, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, false
	}
	ex.Method, ex.Target, ex.ReqHdr = parts[0], parts[1], hdr
	ex.Host = hdr.Get("Host")

	body, used, ok := readBody(b[n:], hdr, false)
	if !ok {
		return 0, false
	}
	ex.ReqBody = decodeContent(body, hdr.Get("Content-Encoding"))
	return n + used, true
}

func parseResponse(b []byte, ex *Exchange) (int, bool) {
	line, hdr, n, ok := parseHead(b)
	if !ok {
		return 0, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, false
	}
	ex.Status, _ = strconv.Atoi(parts[1])
	ex.RespHdr = hdr
	if ex.Method == http.MethodHead || ex.Status == 204 || ex.Status == 304 || ex.Status/100 == 1 {
		return n, true
	}
	body, used, ok := readBody(b[n:], hdr, true)
	if !ok {
		return 0, false
	}
	ex.RespBody = decodeContent(body, hdr.Get("Content-Encoding"))
	return n + used, true
}

// readBody returns the message body and how many bytes it occupied on the
// wire. A response with neither Content-Length nor chunking runs to the end
// of the stream.
func readBody(b []byte, hdr http.Header, toEOF bool) ([]byte, int, bool) {
	if strings.Contains(strings.ToLower(hdr.Get("Transfer-Encoding")), "chunked") {
		return dechunk(b)
	}
	if cl := hdr.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			return nil, 0, false
		}
		if n > len(b) {
			return b, len(b), true // truncated capture: keep what's there
		}
		return b[:n], n, true
	}
	if toEOF {
		return b, len(b), true
	}
	return nil, 0, true
}

func dechunk(b []byte) ([]byte, int, bool) {
	var out []byte
	i := 0
	for {
		eol := bytes.Index(b[i:], []byte("\r\n"))
		if eol < 0 {
			return out, len(b), true
		}
		sizeStr, _, _ := strings.Cut(string(b[i:i+eol]), ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return nil, 0, false
		}
		i += eol + 2
		if size == 0 {
			// skip trailers up to the blank line
			if end := bytes.Index(b[i:], []byte("\r\n")); end >= 0 {
				i += end + 2
			}
			return out, i, true
		}
		if i+int(size) > len(b) {
			return append(out, b[i:]...), len(b), true
		}
		out = append(out, b[i:i+int(size)]...)
		i += int(size) + 2
		if i > len(b) {
			i = len(b)
		}
	}
}

// decodeContent undoes Content-Encoding. Engine.IO compresses polling
// responses over 1 KiB by default (httpCompression), which is exactly the
// size range where command output lives.
func decodeContent(b []byte, enc string) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		r = zr
	case "deflate":
		// "deflate" is zlib-wrapped per the RFC, raw in practice about
		// half the time. Try both.
		if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(b))
		}
	default:
		return b
	}
	out, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil && len(out) == 0 {
		return b
	}
	return out
}

// multipartNames lists the form fields and uploaded file names of a
// multipart request. The collection modules upload stolen files this way,
// and the filename is often the most useful thing in the whole capture.
func multipartNames(ex *Exchange) (fields, files []string) {
	mt, params, err := mime.ParseMediaType(ex.ReqHdr.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return nil, nil
	}
	mr := multipart.NewReader(bytes.NewReader(ex.ReqBody), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err != nil {
			return fields, files
		}
		if fn := part.FileName(); fn != "" {
			files = append(files, fn)
		}
		if name := part.FormName(); name != "" {
			fields = append(fields, name)
		}
	}
}
