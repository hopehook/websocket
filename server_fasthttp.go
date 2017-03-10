package websocket

import (
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type HandshakeErrorFs struct {
	message string
}

func (e HandshakeErrorFs) Error() string { return e.message }

type UpgraderFs struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes. If a buffer
	// size is zero, then buffers allocated by the HTTP server are used. The
	// I/O buffer sizes do not limit the size of the messages that can be sent
	// or received.
	ReadBufferSize, WriteBufferSize int

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is set, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client.
	Subprotocols []string

	// Error specifies the function for generating HTTP error responses. If Error
	// is nil, then http.Error is used to generate the HTTP response.
	// Error func(w http.ResponseWriter, r *http.Request, status int, reason error)
	Error func(ctx *fasthttp.RequestCtx, status int, reason error)

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, the host in the Origin header must not be set or
	// must match the host of the request.
	// CheckOrigin func(r *http.Request) bool
	CheckOrigin func(ctx *fasthttp.RequestCtx) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool
}

func (u *UpgraderFs) returnError(ctx *fasthttp.RequestCtx, status int, reason string) error {
	err := HandshakeErrorFs{reason}
	if u.Error != nil {
		u.Error(ctx, status, err)
	} else {
		ctx.Response.Header.Set("Sec-Websocket-Version", "13")
		ctx.Error(fasthttp.StatusMessage(status), status)
	}
	return err
}

func checkSameOriginFs(ctx *fasthttp.RequestCtx) bool {
	origin := ctx.Request.Header.Peek("Origin")
	if len(origin) == 0 {
		return true
	}
	u, err := url.Parse(string(origin))
	if err != nil {
		return false
	}
	return u.Host == string(ctx.Host())
}

func (u *UpgraderFs) selectSubprotocol(ctx *fasthttp.RequestCtx, responseHeader fasthttp.ResponseHeader) string {
	if u.Subprotocols != nil {
		clientProtocols := SubprotocolsFs(ctx)
		for _, serverProtocol := range u.Subprotocols {
			for _, clientProtocol := range clientProtocols {
				if clientProtocol == serverProtocol {
					return clientProtocol
				}
			}
		}
	} else if responseHeader.Header() != nil {
		return string(responseHeader.Peek("Sec-Websocket-Protocol"))
	}
	return ""
}

func (u *UpgraderFs) Upgrade(ctx *fasthttp.RequestCtx, handler func(*Conn) error, responseHeader fasthttp.ResponseHeader) error {
	var requestHeaderMap = parseHttpHeader(string(ctx.Request.Header.Header()))
	var responseHeaderMap = parseHttpHeader(string(responseHeader.Header()))

	if string(ctx.Method()) != "GET" {
		return u.returnError(ctx, fasthttp.StatusMethodNotAllowed, "websocket: not a websocket handshake: request method is not GET")
	}

	if responseHeader.Peek("Sec-Websocket-Extensions") != nil {
		return u.returnError(ctx, fasthttp.StatusInternalServerError, "websocket: application specific 'Sec-Websocket-Extensions' headers are unsupported")
	}

	if !tokenListContainsValue(requestHeaderMap, "Connection", "upgrade") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: not a websocket handshake: 'upgrade' token not found in 'Connection' header")

	}

	if !tokenListContainsValue(requestHeaderMap, "Upgrade", "websocket") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: not a websocket handshake: 'websocket' token not found in 'Upgrade' header")
	}

	if !tokenListContainsValue(requestHeaderMap, "Sec-Websocket-Version", "13") {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOriginFs
	}

	if !checkOrigin(ctx) {
		return u.returnError(ctx, fasthttp.StatusForbidden, "websocket: 'Origin' header value not allowed")
	}

	challengeKey := string(ctx.Request.Header.Peek("Sec-Websocket-Key"))
	if challengeKey == "" {
		return u.returnError(ctx, fasthttp.StatusBadRequest, "websocket: not a websocket handshake: `Sec-Websocket-Key' header is missing or blank")
	}

	subprotocol := u.selectSubprotocol(ctx, responseHeader)

	var compress bool
	if u.EnableCompression {
		for _, ext := range parseExtensions(requestHeaderMap) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			compress = true
			break
		}
	}

	var err error

	ctx.Response.Header.Set("Upgrade", "websocket")
	ctx.Response.Header.Set("Connection", "Upgrade")
	ctx.Response.Header.Set("Sec-WebSocket-Accept", computeAcceptKey(challengeKey))

	if subprotocol == "" {
		// Find the best protocol, if any
		clientProtocols := SubprotocolsFs(ctx)
		if len(clientProtocols) != 0 {
			subprotocol = matchSubprotocol(clientProtocols, u.Subprotocols)
			if subprotocol != "" {
				ctx.Response.Header.Set("Sec-Websocket-Protocol", subprotocol)
			}
		}
	}

	if compress {
		ctx.Response.Header.Set("Sec-Websocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}
	for k, vs := range responseHeaderMap {
		if k == "Sec-Websocket-Protocol" {
			continue
		}
		ctx.Response.Header.Set(k, strings.Join(vs, "; "))
	}
	ctx.Response.Header.SetStatusCode(fasthttp.StatusSwitchingProtocols)

	ctx.Hijack(func(netConn net.Conn) {
		c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize)
		c.subprotocol = subprotocol
		if compress {
			c.newCompressionWriter = compressNoContextTakeover
			c.newDecompressionReader = decompressNoContextTakeover
		}

		// Clear deadlines set by HTTP server.
		netConn.SetDeadline(time.Time{})

		if u.HandshakeTimeout > 0 {
			netConn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout))
		}
		if u.HandshakeTimeout > 0 {
			netConn.SetWriteDeadline(time.Time{})
		}
		if handler != nil {
			err = handler(c)
		}
	})
	return err
}

func UpgradeFs(ctx *fasthttp.RequestCtx, responseHeader fasthttp.ResponseHeader, handler func(*Conn) error, readBufSize, writeBufSize int) error {
	u := UpgraderFs{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(ctx *fasthttp.RequestCtx, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(ctx *fasthttp.RequestCtx) bool {
		// allow all connections by default
		return true
	}
	return u.Upgrade(ctx, handler, responseHeader)
}

func SubprotocolsFs(ctx *fasthttp.RequestCtx) []string {
	h := strings.TrimSpace(string(ctx.Request.Header.Peek("Sec-Websocket-Protocol")))
	if h == "" {
		return nil
	}
	protocols := strings.Split(h, ",")
	for i := range protocols {
		protocols[i] = strings.TrimSpace(protocols[i])
	}
	return protocols
}

func IsWebSocketUpgradeFs(ctx *fasthttp.RequestCtx) bool {
	var requestHeaderMap = parseHttpHeader(string(ctx.Request.Header.Header()))

	return tokenListContainsValue(requestHeaderMap, "Connection", "upgrade") &&
		tokenListContainsValue(requestHeaderMap, "Upgrade", "websocket")
}

// a new func added to parse http raw content
func parseHttpHeader(content string) map[string][]string {
	headers := make(map[string][]string, 10)
	lines := strings.Split(content, "\r\n")
	for _, line := range lines {
		if len(line) >= 0 {
			words := strings.Split(line, ":")
			if len(words) == 2 {
				key := strings.Trim(words[0], " ")
				value := strings.Trim(words[1], " ")
				headers[key] = append(headers[key], value)
			}
		}
	}
	return headers
}

// a new func added
func matchSubprotocol(clientProtocols, serverProtocols []string) string {
	for _, serverProtocol := range serverProtocols {
		for _, clientProtocol := range clientProtocols {
			if clientProtocol == serverProtocol {
				return clientProtocol
			}
		}
	}

	return ""
}
