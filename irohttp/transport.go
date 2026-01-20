package irohttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/yixinin/iroh-go/common"
	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/endpoint"

	"github.com/quic-go/quic-go"
)

const (
	defaultALPN         = "iroh3"
	defaultTimeout      = 30 * time.Second
	defaultDialTimeout  = 10 * time.Second
	maxIdleConns        = 100
	idleConnTimeout     = 90 * time.Second
	responseHeaderLimit = 1 << 20
)

type connCache struct {
	mu     sync.Mutex
	conns  map[string]quic.Connection
	timers map[string]*time.Timer
}

func newConnCache() *connCache {
	return &connCache{
		conns:  make(map[string]quic.Connection),
		timers: make(map[string]*time.Timer),
	}
}

func (c *connCache) get(key string) (quic.Connection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, ok := c.conns[key]
	return conn, ok
}

func (c *connCache) set(key string, conn quic.Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if oldConn, exists := c.conns[key]; exists {
		oldConn.CloseWithError(0, "")
	}
	if timer, exists := c.timers[key]; exists {
		timer.Stop()
		delete(c.timers, key)
	}

	c.conns[key] = conn

	timer := time.AfterFunc(idleConnTimeout, func() {
		c.remove(key)
	})
	c.timers[key] = timer
}

func (c *connCache) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if conn, exists := c.conns[key]; exists {
		conn.CloseWithError(0, "")
		delete(c.conns, key)
	}
	if timer, exists := c.timers[key]; exists {
		timer.Stop()
		delete(c.timers, key)
	}
}

func (c *connCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, conn := range c.conns {
		conn.CloseWithError(0, "")
		delete(c.conns, key)
	}
	for key, timer := range c.timers {
		timer.Stop()
		delete(c.timers, key)
	}
}

type Transport struct {
	endpoint        *endpoint.Endpoint
	alpn            []byte
	dialTimeout     time.Duration
	timeout         time.Duration
	connCache       *connCache
	maxIdleConns    int
	idleConnTimeout time.Duration
}

func NewTransport(ep *endpoint.Endpoint, opts ...Option) *Transport {
	t := &Transport{
		endpoint:        ep,
		alpn:            []byte(defaultALPN),
		dialTimeout:     defaultDialTimeout,
		timeout:         defaultTimeout,
		connCache:       newConnCache(),
		maxIdleConns:    maxIdleConns,
		idleConnTimeout: idleConnTimeout,
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

type Option func(*Transport)

func WithALPN(alpn string) Option {
	return func(t *Transport) {
		t.alpn = []byte(alpn)
	}
}

func WithDialTimeout(timeout time.Duration) Option {
	return func(t *Transport) {
		t.dialTimeout = timeout
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(t *Transport) {
		t.timeout = timeout
	}
}

func WithMaxIdleConns(max int) Option {
	return func(t *Transport) {
		t.maxIdleConns = max
	}
}

func WithIdleConnTimeout(timeout time.Duration) Option {
	return func(t *Transport) {
		t.idleConnTimeout = timeout
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("[irohttp] Request URL cannot be nil")
	}

	ctx := req.Context()
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}

	remoteId, path, err := parseIrohURL(req.URL)
	if err != nil {
		return nil, fmt.Errorf("[irohttp] Failed to parse iroh URL: %w", err)
	}

	conn, err := t.getOrCreateConnection(ctx, remoteId)
	if err != nil {
		return nil, fmt.Errorf("[irohttp] Failed to establish connection: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("[irohttp] Failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := writeHTTPRequest(req, path, stream); err != nil {
		return nil, fmt.Errorf("[irohttp] Failed to write request: %w", err)
	}

	resp, err := readHTTPResponse(req, stream)
	if err != nil {
		return nil, fmt.Errorf("[irohttp] Failed to read response: %w", err)
	}

	return resp, nil
}

func parseIrohURL(u *url.URL) (*crypto.EndpointId, string, error) {
	if u.Scheme != "iroh" {
		return nil, "", fmt.Errorf("[irohttp] Unsupported scheme: %s (expected 'iroh')", u.Scheme)
	}

	host := u.Host
	if host == "" {
		return nil, "", fmt.Errorf("[irohttp] Host cannot be empty")
	}

	id, err := crypto.ParseEndpointId(host)
	if err != nil {
		return nil, "", fmt.Errorf("[irohttp] Invalid endpoint ID: %w", err)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	return id, path, nil
}

func (t *Transport) getOrCreateConnection(ctx context.Context, remoteId *crypto.EndpointId) (quic.Connection, error) {
	cacheKey := remoteId.String()

	if conn, ok := t.connCache.get(cacheKey); ok {
		return conn, nil
	}

	remoteAddr := endpoint.EndpointAddr{
		Id:    remoteId,
		Addrs: []common.TransportAddr{},
	}

	conn, err := t.endpoint.Connect(ctx, remoteAddr, t.alpn)
	if err != nil {
		return nil, err
	}

	quicConn := conn.Conn()
	if quicConn == nil {
		return nil, fmt.Errorf("relay connections are not yet supported for HTTP over iroh")
	}
	t.connCache.set(cacheKey, quicConn)

	return quicConn, nil
}

func writeHTTPRequest(req *http.Request, path string, stream quic.Stream) error {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, path)

	if req.Host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	}

	for key, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, value)
		}
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(&buf, "\r\n")
		buf.Write(body)
	} else {
		fmt.Fprintf(&buf, "\r\n")
	}

	_, err := stream.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func readHTTPResponse(req *http.Request, stream quic.Stream) (*http.Response, error) {
	limitReader := io.LimitReader(stream, responseHeaderLimit)
	bufReader := bufio.NewReader(limitReader)

	resp, err := http.ReadResponse(bufReader, req)
	if err != nil {
		return nil, err
	}

	resp.Body = &streamReadCloser{stream: stream, reader: io.MultiReader(bufReader, stream)}

	return resp, nil
}

type streamReadCloser struct {
	stream quic.Stream
	reader io.Reader
}

func (s *streamReadCloser) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

func (s *streamReadCloser) Close() error {
	return s.stream.Close()
}

func (t *Transport) CloseIdleConnections() {
	t.connCache.close()
}

func (t *Transport) CancelRequest(req *http.Request) {
}
