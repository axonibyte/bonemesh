// Package node is a BoneMesh v3 mesh node (protocol.md §3) over TCP: one
// authenticated, encrypted session per neighbor, each served by a goroutine,
// with application payloads delivered on a channel. Wire-compatible with the
// Java, Elixir, and Rust implementations. Does direct neighbor delivery, which
// is what two-party interop needs; relay/discovery/heartbeat are shared parity
// work tracked elsewhere.
package node

import (
	"bufio"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

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
}

// Start starts a node listening on port (0 for ephemeral).
func Start(cfg Config, port int) (*Node, error) {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, listener: l, links: make(map[string]*link)}
	go n.acceptLoop()
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

// Send sends an application payload to a direct neighbor.
func (n *Node) Send(to string, payload any) bool {
	msg := message.Data(message.NewMID(), n.cfg.Label, to, message.DefaultTTL, payload)
	return n.sendToLink(to, msg)
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
	go n.readLoop(peer, r, lk)
}

func (n *Node) readLoop(peer string, r *bufio.Reader, lk *link) {
	for {
		carrier, err := frame.ReadFrame(r, frame.TransportCap)
		if err != nil {
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

func (n *Node) handleInner(_ string, msg map[string]any) {
	if msg["type"] != "data" {
		return
	}
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

func now() int64 { return time.Now().Unix() }
