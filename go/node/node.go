// Package node is a BoneMesh v3 mesh node (protocol.md §3, §5) over TCP: one
// authenticated, encrypted session per neighbor, each served by a goroutine.
// It routes — distance-vector discovery over a 1 s heartbeat (probe/echo for
// link latency, disco for route advertisement with poisoned reverse), relays
// data toward a next hop with TTL, and delivers payloads addressed to itself,
// deduping by message id. Wire-compatible with the Java, Elixir, Rust, JS, and
// PHP implementations.
package node

import (
	"bufio"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/routing"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

const heartbeatInterval = time.Second

// Config is a node's identity and mesh membership.
type Config struct {
	Label      string
	Mesh       string
	RootPublic []byte
	Cert       map[string]any
	IDPrivate  []byte
}

type link struct {
	conn      net.Conn
	transport *transport.Transport
	mu        sync.Mutex
}

// Node is a running mesh node.
type Node struct {
	cfg       Config
	listener  net.Listener
	links     map[string]*link
	mu        sync.Mutex
	listeners []chan map[string]any
	table     *routing.Table
	dedup     *routing.Dedup
	done      chan struct{}
}

// Start starts a node listening on port (0 for ephemeral).
func Start(cfg Config, port int) (*Node, error) {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		listener: l,
		links:    make(map[string]*link),
		table:    routing.NewTable(cfg.Label),
		dedup:    routing.NewDedup(4096),
		done:     make(chan struct{}),
	}
	go n.acceptLoop()
	go n.heartbeatLoop()
	return n, nil
}

// Port is the port the node listens on.
func (n *Node) Port() int { return n.listener.Addr().(*net.TCPAddr).Port }

// AddListener returns a channel that receives delivered application payloads.
func (n *Node) AddListener() <-chan map[string]any {
	ch := make(chan map[string]any, 16)
	n.mu.Lock()
	n.listeners = append(n.listeners, ch)
	n.mu.Unlock()
	return ch
}

// RouteTable is a snapshot of learned destinations to their next hop.
func (n *Node) RouteTable() map[string]string { return n.table.RouteTable() }

// Connect dials a peer and completes the handshake as initiator.
func (n *Node) Connect(host string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	hs := handshake.Initiator(n.cfg.Mesh, n.cfg.RootPublic, now(), n.cfg.Cert, n.cfg.IDPrivate)
	if _, err := conn.Write(hs.WriteMessage1()); err != nil {
		return "", err
	}
	m2, err := frame.ReadFrame(r, frame.HandshakeCap)
	if err != nil {
		return "", err
	}
	m3, err := hs.ReadMessage2WriteMessage3(frame.Encode(m2))
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(m3); err != nil {
		return "", err
	}
	peer, _ := hs.SessionResult().PeerCert["label"].(string)
	n.register(peer, conn, r, transport.New(hs.SessionResult()))
	return peer, nil
}

// Send routes an application payload toward any reachable destination.
func (n *Node) Send(to string, payload any) bool {
	msg := message.Data(message.NewMID(), n.cfg.Label, to, message.DefaultTTL, payload)
	nh, ok := n.table.NextHop(to)
	if !ok {
		return false
	}
	return n.sendToLink(nh, msg)
}

func (n *Node) acceptLoop() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			return
		}
		go n.respond(conn)
	}
}

func (n *Node) respond(conn net.Conn) {
	r := bufio.NewReader(conn)
	hs := handshake.Responder(n.cfg.Mesh, n.cfg.RootPublic, now(), n.cfg.Cert, n.cfg.IDPrivate)
	m1, err := frame.ReadFrame(r, frame.HandshakeCap)
	if err != nil {
		conn.Close()
		return
	}
	m2, err := hs.ReadMessage1WriteMessage2(frame.Encode(m1))
	if err != nil {
		conn.Close()
		return
	}
	if _, err := conn.Write(m2); err != nil {
		conn.Close()
		return
	}
	m3, err := frame.ReadFrame(r, frame.HandshakeCap)
	if err != nil {
		conn.Close()
		return
	}
	if err := hs.ReadMessage3(frame.Encode(m3)); err != nil {
		conn.Close()
		return
	}
	peer, _ := hs.SessionResult().PeerCert["label"].(string)
	n.register(peer, conn, r, transport.New(hs.SessionResult()))
}

func (n *Node) register(peer string, conn net.Conn, r *bufio.Reader, t *transport.Transport) {
	lk := &link{conn: conn, transport: t}
	n.mu.Lock()
	n.links[lower(peer)] = lk
	n.mu.Unlock()
	n.table.ObserveNeighbor(peer, 1) // optimistic seed so it is immediately routable
	go n.readLoop(peer, r, lk)
}

func (n *Node) readLoop(peer string, r *bufio.Reader, lk *link) {
	for {
		carrier, err := frame.ReadFrame(r, frame.TransportCap)
		if err != nil {
			n.deregister(peer, lk)
			return
		}
		lk.mu.Lock()
		inner, err := lk.transport.Open(carrier)
		lk.mu.Unlock()
		if err != nil {
			continue
		}
		n.handleInner(peer, inner)
	}
}

// deregister removes a dropped link and withdraws routes through it — but only
// if this is still the current link for peer (a reconnect may have replaced it).
func (n *Node) deregister(peer string, lk *link) {
	lk.conn.Close()
	n.mu.Lock()
	if n.links[lower(peer)] == lk {
		delete(n.links, lower(peer))
	}
	n.mu.Unlock()
	n.table.RemoveNeighbor(peer)
}

func (n *Node) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			n.mu.Lock()
			peers := make([]string, 0, len(n.links))
			for label := range n.links {
				peers = append(peers, label)
			}
			n.mu.Unlock()
			for _, peer := range peers {
				n.sendToLink(peer, message.Probe(nowMillis()))
				n.sendToLink(peer, message.Disco(n.table.AdvertiseTo(peer)))
			}
		}
	}
}

func (n *Node) handleInner(peer string, msg map[string]any) {
	switch msg["type"] {
	case "probe":
		n.sendToLink(peer, message.Echo(asInt64(msg["token"])))
	case "echo":
		rtt := nowMillis() - asInt64(msg["token"])
		if rtt < 0 {
			rtt = 0
		}
		n.table.ObserveNeighbor(peer, rtt)
	case "disco":
		if routes, ok := msg["routes"].(map[string]any); ok {
			for dest, cost := range routes {
				n.table.LearnRoute(dest, peer, asInt64(cost))
			}
		}
	case "data":
		n.handleData(msg)
	}
}

func (n *Node) handleData(msg map[string]any) {
	mid, _ := msg["mid"].(string)
	chunkIdx := -1
	if ch, ok := msg["chunk"].(map[string]any); ok {
		chunkIdx = asInt(ch["i"])
	}
	if n.dedup.Seen(mid + ":" + strconv.Itoa(chunkIdx)) {
		return
	}
	to, _ := msg["to"].(string)
	if lower(to) == lower(n.cfg.Label) {
		n.deliver(msg)
		return
	}
	ttl := asInt(msg["ttl"]) - 1
	if ttl <= 0 {
		return // DROP_TTL, silently
	}
	nh, ok := n.table.NextHop(to)
	if !ok {
		return // UNREACHABLE, silently
	}
	fwd := make(map[string]any, len(msg))
	for k, v := range msg {
		fwd[k] = v
	}
	fwd["ttl"] = ttl
	n.sendToLink(nh, fwd)
}

func (n *Node) deliver(msg map[string]any) {
	payload, _ := msg["payload"].(map[string]any)
	n.mu.Lock()
	listeners := append([]chan map[string]any{}, n.listeners...)
	n.mu.Unlock()
	for _, ch := range listeners {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (n *Node) sendToLink(label string, inner map[string]any) bool {
	n.mu.Lock()
	lk := n.links[lower(label)]
	n.mu.Unlock()
	if lk == nil {
		return false
	}
	lk.mu.Lock()
	defer lk.mu.Unlock()
	carrier := lk.transport.Seal(inner)
	_, err := lk.conn.Write(frame.Encode(carrier))
	return err == nil
}

// Kill stops the node.
func (n *Node) Kill() error {
	err := n.listener.Close()
	close(n.done)
	n.mu.Lock()
	for _, lk := range n.links {
		lk.conn.Close()
	}
	n.mu.Unlock()
	return err
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case json.Number:
		i, _ := t.Int64()
		return i
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	}
	return 0
}

func asInt(v any) int { return int(asInt64(v)) }

func now() int64       { return time.Now().Unix() }
func nowMillis() int64 { return time.Now().UnixMilli() }
