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
	"sync/atomic"
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
	// initiator records whether this node dialed the connection this link
	// runs over (protocol.md §3: the simultaneous-dial tiebreak needs to
	// know who initiated each competing session).
	initiator bool
	// establishedAt is when the handshake completed, in unix millis.
	establishedAt int64
	// lastInbound is the unix-millis time of the last successfully opened
	// inbound frame — any authenticated frame proves the peer is alive.
	lastInbound atomic.Int64
	// lastData is the unix-millis time of the last data frame sent over or
	// received on this link (probe/echo/disco never count as activity).
	lastData atomic.Int64
}

// Node is a running mesh node.
type Node struct {
	cfg       Config
	tun       tunables
	listener  net.Listener
	links        map[string]*link
	mu           sync.Mutex
	listeners    []chan map[string]any
	ackListeners []chan map[string]any
	table        *routing.Table
	dedup        *routing.Dedup
	done         chan struct{}
}

// Start starts a node listening on port (0 for ephemeral).
func Start(cfg Config, port int) (*Node, error) {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		tun:      loadTunables(),
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
	n.register(peer, conn, r, transport.New(hs.SessionResult()), true)
	return peer, nil
}

// Send routes an application payload toward any reachable destination. Returns
// true if the message was handed to a next hop.
func (n *Node) Send(to string, payload any) bool {
	_, ok := n.SendM(to, payload)
	return ok
}

// SendM is Send that also returns the message id, so a caller can correlate the
// ack/nak delivered to AckListener (protocol.md §7).
func (n *Node) SendM(to string, payload any) (string, bool) {
	mid := message.NewMID()
	msg := message.Data(mid, n.cfg.Label, to, message.DefaultTTL, payload)
	nh, ok := n.table.NextHop(to)
	if !ok {
		return mid, false
	}
	return mid, n.sendToLink(nh, msg)
}

// sendWithTTL is Send with an explicit initial TTL, used by tests to force a
// relay to exhaust the hop limit and emit a NAK.
func (n *Node) sendWithTTL(to string, payload any, ttl int) (string, bool) {
	mid := message.NewMID()
	msg := message.Data(mid, n.cfg.Label, to, ttl, payload)
	nh, ok := n.table.NextHop(to)
	if !ok {
		return mid, false
	}
	return mid, n.sendToLink(nh, msg)
}

// AckListener returns a channel that receives ack and nak messages addressed to
// this node (the origin), each as the raw inner map.
func (n *Node) AckListener() <-chan map[string]any {
	ch := make(chan map[string]any, 16)
	n.mu.Lock()
	n.ackListeners = append(n.ackListeners, ch)
	n.mu.Unlock()
	return ch
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
	n.register(peer, conn, r, transport.New(hs.SessionResult()), false)
}

// register installs a new link for peer and starts its reader. It returns true
// if the new link was kept. On a collision with an existing link it applies the
// simultaneous-dial tiebreak (protocol.md §3): if the two links were initiated
// by the same side it is a reconnect (last writer wins); if by opposite sides
// it is a genuine dial collision, and both ends deterministically keep the
// session initiated by the lexicographically-lower label, so the pair converges
// on exactly one session.
func (n *Node) register(peer string, conn net.Conn, r *bufio.Reader, t *transport.Transport, initiator bool) bool {
	now := nowMillis()
	lk := &link{conn: conn, transport: t, initiator: initiator, establishedAt: now}
	lk.lastInbound.Store(now)
	lk.lastData.Store(now)

	n.mu.Lock()
	prev := n.links[lower(peer)]
	keepNew := true
	if prev != nil && prev.initiator != initiator {
		// Dial collision: keep the session the lower-labelled node initiated.
		// Both ends compute the same winner, so they agree on which to drop.
		selfWins := lower(n.cfg.Label) < lower(peer)
		keepNew = initiator == selfWins
	}
	if keepNew {
		n.links[lower(peer)] = lk
	}
	n.mu.Unlock()

	if !keepNew {
		// This new link lost the tiebreak; drop it and keep the existing one.
		conn.Close()
		return false
	}
	if prev != nil && prev != lk {
		// Displaced an existing link (reconnect, or collision the new link won):
		// close it so its socket and reader goroutine do not linger. Its
		// deregister is identity-guarded, so its death cannot withdraw this
		// new link's routes.
		prev.conn.Close()
	}
	n.table.ObserveNeighbor(peer, 1) // optimistic seed so it is immediately routable
	go n.readLoop(peer, r, lk)
	return true
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
		lk.lastInbound.Store(nowMillis())
		if inner["type"] == "data" {
			lk.lastData.Store(nowMillis())
		}
		if inner["type"] == "bye" {
			// Peer is closing this session gracefully; tear it down and stop.
			n.deregister(peer, lk)
			return
		}
		n.handleInner(peer, inner)
	}
}

// deregister removes a dropped link and withdraws routes through it — but only
// if this is still the current link for peer (a reconnect may have replaced it,
// in which case the stale link's death must not withdraw the live link's routes).
func (n *Node) deregister(peer string, lk *link) {
	lk.conn.Close()
	n.mu.Lock()
	wasCurrent := n.links[lower(peer)] == lk
	if wasCurrent {
		delete(n.links, lower(peer))
	}
	n.mu.Unlock()
	if wasCurrent {
		n.table.RemoveNeighbor(peer)
	}
}

func (n *Node) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			now := nowMillis()
			type pl struct {
				peer string
				lk   *link
			}
			n.mu.Lock()
			pairs := make([]pl, 0, len(n.links))
			for label, lk := range n.links {
				pairs = append(pairs, pl{label, lk})
			}
			n.mu.Unlock()
			for _, p := range pairs {
				n.sweepLink(now, p.peer, p.lk)
			}
		}
	}
}

// sweepLink runs the once-per-heartbeat maintenance for one link: tear it down
// if it is probe-timeout dead (F3) or data-idle past the idle timeout (F4,
// disabled at idleMS==0), otherwise send it a probe and a route advertisement.
func (n *Node) sweepLink(now int64, peer string, lk *link) {
	if now-lk.lastInbound.Load() > n.tun.probeTimeoutMS {
		n.deregister(peer, lk)
		return
	}
	if n.tun.idleMS > 0 && now-lk.lastData.Load() > n.tun.idleMS {
		n.sendToLink(peer, message.Bye("idle"))
		n.deregister(peer, lk)
		return
	}
	n.sendToLink(peer, message.Probe(now))
	n.sendToLink(peer, message.Disco(n.table.AdvertiseTo(peer)))
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
	case "ack":
		n.handleControl(msg, "a:")
	case "nak":
		n.handleControl(msg, "n:")
	}
}

func (n *Node) handleData(msg map[string]any) {
	mid, _ := msg["mid"].(string)
	chunkIdx := -1
	if ch, ok := msg["chunk"].(map[string]any); ok {
		chunkIdx = asInt(ch["i"])
	}
	if n.dedup.Seen("d:" + mid + ":" + strconv.Itoa(chunkIdx)) {
		return
	}
	to, _ := msg["to"].(string)
	from, _ := msg["from"].(string)
	if lower(to) == lower(n.cfg.Label) {
		n.deliver(msg)
		// F6: acknowledge receipt back toward the origin.
		if from != "" && lower(from) != lower(n.cfg.Label) {
			n.routeControl(message.AckTo(mid, n.cfg.Label, from, message.DefaultTTL))
		}
		return
	}
	ttl := asInt(msg["ttl"]) - 1
	if ttl <= 0 {
		// F6/D4: the relay that dropped it names itself as the failing hop.
		n.emitNak(mid, from, "ttl")
		return
	}
	nh, ok := n.table.NextHop(to)
	if !ok {
		n.emitNak(mid, from, "no-route")
		return
	}
	fwd := make(map[string]any, len(msg))
	for k, v := range msg {
		fwd[k] = v
	}
	fwd["ttl"] = ttl
	n.sendToLink(nh, fwd)
}

// handleControl relays or delivers an ack/nak (routed back toward the origin
// like data). A type-prefixed dedup key keeps a relayed ack from colliding with
// the data it answers (same mid). ack/nak are never themselves ack'd or nak'd.
func (n *Node) handleControl(msg map[string]any, prefix string) {
	mid, _ := msg["mid"].(string)
	if n.dedup.Seen(prefix + mid) {
		return
	}
	to, _ := msg["to"].(string)
	if lower(to) == lower(n.cfg.Label) {
		n.deliverAck(msg)
		return
	}
	ttl := asInt(msg["ttl"]) - 1
	if ttl <= 0 {
		return // drop silently; no nak-of-nak
	}
	nh, ok := n.table.NextHop(to)
	if !ok {
		return
	}
	fwd := make(map[string]any, len(msg))
	for k, v := range msg {
		fwd[k] = v
	}
	fwd["ttl"] = ttl
	n.sendToLink(nh, fwd)
}

// emitNak sends a NAK back toward the origin naming this node as the failing
// hop. Best-effort: if the NAK itself cannot be routed it is dropped (no
// recursion).
func (n *Node) emitNak(mid, origin, reason string) {
	if origin == "" || lower(origin) == lower(n.cfg.Label) {
		return
	}
	n.routeControl(message.Nak(mid, n.cfg.Label, origin, n.cfg.Label, reason, message.DefaultTTL))
}

// routeControl sends a freshly-built ack/nak toward its destination, dropping
// silently if there is no route (never producing a control-of-control).
func (n *Node) routeControl(msg map[string]any) {
	to, _ := msg["to"].(string)
	nh, ok := n.table.NextHop(to)
	if !ok {
		return
	}
	n.sendToLink(nh, msg)
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

// deliverAck hands an ack/nak addressed to this node to the ack listeners.
func (n *Node) deliverAck(msg map[string]any) {
	n.mu.Lock()
	listeners := append([]chan map[string]any{}, n.ackListeners...)
	n.mu.Unlock()
	for _, ch := range listeners {
		select {
		case ch <- msg:
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
	if inner["type"] == "data" {
		lk.lastData.Store(nowMillis())
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
