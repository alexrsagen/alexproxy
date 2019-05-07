// Parts from httputil are copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Modifications to aforementioned parts and the rest of the source
// is Copyright 2019 Alexander Sagen.

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// proxyApp contains the global state of the proxy
type proxyApp struct {
	// AllowedNetworks specifies a list of networks
	// that are allowed to use the proxy
	AllowedNetworks []*net.IPNet

	// Timeout specifies a global proxy request timeout
	Timeout time.Duration

	// Transport specifies the proxy HTTP transport
	Transport http.RoundTripper

	// Client specifies the proxy HTTP client
	Client *http.Client

	// Server specifies the proxy HTTP server
	Server *http.Server

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	// A negative value means to flush immediately
	// after each write to the client.
	// The FlushInterval is ignored when ReverseProxy
	// recognizes a response as a streaming response;
	// for such responses, writes are flushed to the client
	// immediately.
	FlushInterval time.Duration

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool httputil.BufferPool

	flags struct {
		listen       string
		cidrFile     string
		timeout      string
		debug        bool
		printVersion bool
		printHelp    bool
		printHelp2   bool
	}

	listener net.Listener
	err      error
}

// hijackCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type hijackCopier struct {
	client, server io.ReadWriter
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

type bufferPool struct {
	pool *sync.Pool
}

func (bp *bufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

func (bp *bufferPool) Put(b []byte) {
	bp.pool.Put(b)
}

var app *proxyApp
var version = "unknown"
var osarch = "unknown"

// Hop-by-hop headers. These are removed when sent to the server.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func main() {
	app = &proxyApp{
		BufferPool: newBufferPool(),
	}
	var f *os.File
	var scanner *bufio.Scanner
	var cidrNet *net.IPNet
	var laddr *net.TCPAddr

	// Tell systemd that we're getting ready
	systemdNotify("STATUS=alexproxy starting")

	flag.StringVar(&app.flags.listen, "listen", "", "Listen address in the format of <ip>:<port>")
	flag.StringVar(&app.flags.cidrFile, "cidrfile", "", "Path to file containing newline-separated CIDR prefixes that are allowed access, 0.0.0.0/0 / ::/0 is allowed if not specified")
	flag.StringVar(&app.flags.timeout, "timeout", "30s", "Request timeout")
	flag.BoolVar(&app.flags.debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&app.flags.printVersion, "version", false, "Print version and exit")
	flag.BoolVar(&app.flags.printHelp, "h", false, "Show this help menu")
	flag.BoolVar(&app.flags.printHelp2, "help", false, "Show this help menu")
	flag.Parse()

	// Handle immediately closing flags
	if app.flags.printHelp || app.flags.printHelp2 {
		flag.Usage()
		goto END
	}
	if app.flags.printVersion {
		fmt.Printf("alexproxy version %s (%s)\n", version, osarch)
		goto END
	}

	// Parse timeout
	if app.Timeout, app.err = time.ParseDuration(app.flags.timeout); app.err != nil {
		goto END
	}

	if app.flags.cidrFile != "" {
		// Parse cidr access list
		if f, app.err = os.Open(app.flags.cidrFile); app.err != nil {
			f.Close()
			goto END
		}
		scanner = bufio.NewScanner(f)
		for scanner.Scan() {
			if _, cidrNet, app.err = net.ParseCIDR(scanner.Text()); app.err != nil {
				f.Close()
				goto END
			}
			app.AllowedNetworks = append(app.AllowedNetworks, cidrNet)
		}
		if app.err = scanner.Err(); app.err != nil {
			f.Close()
			goto END
		}
		f.Close()
	} else {
		// Give access to 0.0.0.0/0, ::/0 if no cidr list is specified
		app.AllowedNetworks = append(app.AllowedNetworks, &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPMask(net.IPv4zero),
		})
		app.AllowedNetworks = append(app.AllowedNetworks, &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.IPMask(net.IPv6zero),
		})
	}

	// Parse listen address
	if laddr, app.err = net.ResolveTCPAddr("tcp", app.flags.listen); app.err != nil {
		goto END
	}

	// Create listener
	if app.listener, app.err = net.ListenTCP("tcp", laddr); app.err != nil {
		goto END
	}

	// Set up HTTP client
	app.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   app.Timeout,
			KeepAlive: app.Timeout,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	app.Client = &http.Client{
		Transport: app.Transport,
		Timeout:   app.Timeout,
	}

	// Tell systemd that we're up and ready
	systemdNotify("READY=1")
	systemdNotify("STATUS=alexproxy started")

	// Run proxy listener, blocking main thread until a fatal error occurs
	app.err = http.Serve(app.listener, app)

	// Tell systemd that we're outta here
END:
	systemdNotify("STOPPING=1")
	if app.err != nil {
		systemdNotify("STATUS=alexproxy errored, exiting")
		app.logf("[error] %v", app.err)
	} else {
		systemdNotify("STATUS=alexproxy stopping")
	}
}

func (app *proxyApp) logf(format string, v ...interface{}) {
	v = append([]interface{}{time.Now().Format(time.RFC3339)}, v...)
	fmt.Printf("%s "+format+"\n", v...)
}

func (app *proxyApp) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if app.flags.debug {
		app.logf("[debug] client %s request \"%s %v %s\"",
			req.RemoteAddr, req.Method, req.URL, req.Proto)
	}

	// Parse client IP
	clientIPStr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		app.handleRequestError(rw, req, err)
		return
	}
	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		app.handleRequestError(rw, req, fmt.Errorf("invalid client IP address"))
		return
	}

	// Check client access
	allowed := false
	for _, cidrNet := range app.AllowedNetworks {
		if cidrNet.Contains(clientIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	transport := app.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	// Create context with cancel method in case client closes request
	ctx := req.Context()
	if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	// Handle CONNECT request
	if req.Method == http.MethodConnect {
		conn, err := net.DialTimeout("tcp", req.Host, app.Timeout)
		if err != nil {
			app.handleRequestError(rw, req, err)
			return
		}
		app.handleHijack(rw, req, nil, conn)
		return
	}

	// Create new outgoing request from client request
	outreq := req.WithContext(ctx)
	if req.ContentLength == 0 {
		outreq.Body = nil
	}
	outreq.Header = cloneHeader(req.Header)
	outreq.Close = false

	// Remove hop-by-hop and other connection headers to the server,
	// keeping a copy of any connection upgrade header.
	reqUpType := upgradeType(outreq.Header)
	removeConnectionHeaders(outreq.Header)
	for _, h := range hopHeaders {
		hv := outreq.Header.Get(h)
		if hv == "" {
			continue
		}
		if h == "Te" && hv == "trailers" {
			// Allow client to specify that we support trailers
			continue
		}
		outreq.Header.Del(h)
	}

	// After removing all the hop-by-hop connection headers above, add back any
	// necessary for protocol upgrades, such as for websockets.
	if reqUpType != "" {
		outreq.Header.Set("Connection", "Upgrade")
		outreq.Header.Set("Upgrade", reqUpType)
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		app.handleRequestError(rw, outreq, err)
		return
	}

	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		app.handleUpgradeResponse(rw, outreq, res)
		return
	}

	// Remove hop-by-hop and other connection headers from the server response
	removeConnectionHeaders(res.Header)
	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	// Copy server response headers to our response
	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	// Copy server response code to our response
	rw.WriteHeader(res.StatusCode)

	err = app.copyResponse(rw, res.Body, app.flushInterval(req, res))
	if err != nil {
		defer res.Body.Close()
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request.
		app.logf("[error] copyResponse copy error: %v", err)
		return
	}
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
}

func (app *proxyApp) handleRequestError(rw http.ResponseWriter, req *http.Request, err error) {
	app.logf("[error] client %s request \"%s %v %s\" error: %v",
		req.RemoteAddr, req.Method, req.URL, req.Proto, err)
	rw.WriteHeader(http.StatusBadGateway)
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (app *proxyApp) flushInterval(req *http.Request, res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// TODO: more specific cases? e.g. res.ContentLength == -1?
	return app.FlushInterval
}

func (app *proxyApp) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	var buf []byte
	if app.BufferPool != nil {
		buf = app.BufferPool.Get()
		defer app.BufferPool.Put(buf)
	}
	_, err := app.copyBuffer(dst, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (app *proxyApp) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			app.logf("[error] read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (app *proxyApp) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if reqUpType != resUpType {
		app.handleRequestError(rw, req, fmt.Errorf("server tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}

	app.handleHijack(rw, req, res, nil)
}

func (app *proxyApp) handleHijack(rw http.ResponseWriter, req *http.Request, res *http.Response, backConn io.ReadWriteCloser) {
	if res != nil {
		copyHeader(res.Header, rw.Header())
	}

	rw.WriteHeader(http.StatusOK)
	hj, ok := rw.(http.Hijacker)
	if !ok {
		app.handleRequestError(rw, req, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw))
		return
	}
	if backConn == nil {
		backConn, ok = res.Body.(io.ReadWriteCloser)
		if !ok {
			app.handleRequestError(rw, req, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
			return
		}
	}
	defer backConn.Close()
	conn, brw, err := hj.Hijack()
	if err != nil {
		app.handleRequestError(rw, req, fmt.Errorf("Hijack failed on protocol switch: %v", err))
		return
	}
	defer conn.Close()
	if res != nil {
		res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
		if err := res.Write(brw); err != nil {
			app.handleRequestError(rw, req, fmt.Errorf("response write: %v", err))
			return
		}
		if err := brw.Flush(); err != nil {
			app.handleRequestError(rw, req, fmt.Errorf("response flush: %v", err))
			return
		}
	}
	errc := make(chan error, 1)
	spc := hijackCopier{client: conn, server: backConn}
	go spc.copyToServer(errc)
	go spc.copyFromServer(errc)
	if err := <-errc; err != nil {
		app.logf("[error] hijack copy error: %v", err)
	}
	return
}

func (c hijackCopier) copyFromServer(errc chan<- error) {
	_, err := io.Copy(c.client, c.server)
	errc <- err
}

func (c hijackCopier) copyToServer(errc chan<- error) {
	_, err := io.Copy(c.server, c.client)
	errc <- err
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

func newBufferPool() *bufferPool {
	return &bufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func systemdNotify(message string) error {
	var err error
	var conn *net.UnixConn

	var sock = &net.UnixAddr{
		Name: os.Getenv("NOTIFY_SOCKET"),
		Net:  "unixgram",
	}

	if sock.Name == "" {
		return errors.New("NOTIFY_SOCKET environment variable not set")
	}

	conn, err = net.DialUnix(sock.Net, nil, sock)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte(message))
	if err != nil {
		conn.Close()
		return err
	}

	conn.Close()
	return nil
}
