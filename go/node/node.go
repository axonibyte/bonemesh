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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	// CapturePath, when set, tees every transport carrier this node sends or
	// receives to a newline-delimited JSON file as {"dir","frame"} — the
	// capture bonemesh-inspect reads. A debugging aid, off unless set.
	CapturePath string
}

type link struct {
	conn      net.Conn
	transport *transport.Transport
	mu        sync.Mutex
	// initiator records whether this node dialed the connection this link
	// runs over (protocol.md §3: the simultaneous-dial tiebreak needs to
	// know who initiated each competing session).
	initiator bool
	// th is a short hex prefix of the session's transcript hash — a session
	// identifier both ends agree on, surfaced for the interop harness.
	th string
	// establishedAt is when the handshake completed, in unix millis.
	establishedAt int64
	// lastInbound is the unix-millis time of the last successfully opened
	// inbound frame — any authenticated frame proves the peer is alive.
	lastInbound atomic.Int64
	// lastData is the unix-millis time of the last data frame sent over or
	// received on this link (probe/echo/disco never count as activity).
	lastData atomic.Int64
	// Rekey state (F5), all guarded by mu. rekeyHS is the in-flight handshake
	// before any key swap has happened (abandonable, keeping the old keys);
	// rekeySession is the initiator's new session between swapping its send key
	// (after phase 2) and swapping its receive key (on phase 4).
	rekeyHS        *handshake.Handshake
	rekeySession   *handshake.Session
	rekeyMID       string
	rekeyStartedAt int64
	rekeyEpoch     int
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
	pending      map[string][]*pendingSend
	table        *routing.Table
	dedup        *routing.Dedup
	keylogMu     sync.Mutex
	done         chan struct{}
}

// pendingSend is an origin data message awaiting a retry: it could not be
// handed to a next hop yet (no route, or the write failed). It is re-tried on
// each heartbeat with exponential backoff until it lands or its lifetime is
// spent (F2, protocol.md §7).
type pendingSend struct {
	inner      map[string]any
	enqueuedAt int64
	nextAt     int64
	delay      int64
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
		pending:  make(map[string][]*pendingSend),
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
	sess := hs.SessionResult()
	peer, _ := sess.PeerCert["label"].(string)
	if n.register(peer, conn, r, sess, true) {
		n.writeKeylog(0, true, sess)
	}
	return peer, nil
}

// Send routes an application payload toward any reachable destination. Returns
// true if the message was handed to a next hop.
func (n *Node) Send(to string, payload any) bool {
	_, ok := n.SendM(to, payload)
	return ok
}

// SendM is Send that also returns the message id, so a caller can correlate the
// ack/nak delivered to AckListener (protocol.md §7). If the destination is not
// routable now (or the first-hop write fails) the message is queued for bounded
// retry (F2) when retry is enabled; the boolean reports whether it was handed to
// a next hop this instant, unchanged from before.
func (n *Node) SendM(to string, payload any) (string, bool) {
	mid := message.NewMID()
	msg := message.Data(mid, n.cfg.Label, to, message.DefaultTTL, payload)
	nh, ok := n.table.NextHop(to)
	if !ok || !n.sendToLink(nh, msg) {
		n.enqueueRetry(msg)
		return mid, false
	}
	return mid, true
}

// enqueueRetry queues an origin data message for later retry, bounded to 64 per
// destination. A no-op when retry is disabled (retryMaxMS == 0).
func (n *Node) enqueueRetry(inner map[string]any) {
	if n.tun.retryMaxMS <= 0 {
		return
	}
	to, _ := inner["to"].(string)
	now := nowMillis()
	n.mu.Lock()
	defer n.mu.Unlock()
	q := n.pending[lower(to)]
	if len(q) >= 64 {
		return // bounded: one unreachable destination cannot grow without limit
	}
	n.pending[lower(to)] = append(q, &pendingSend{
		inner:      inner,
		enqueuedAt: now,
		nextAt:     now + n.tun.retryBaseMS,
		delay:      n.tun.retryBaseMS,
	})
}

// drainRetries re-attempts due pending sends once per heartbeat: a landed
// message is dropped, a still-stuck one backs off (delay doubles to the cap),
// and one past its lifetime is dropped and reported to the origin's ack
// listener as a synthesized nak{reason:"expired"} (never on the wire).
func (n *Node) drainRetries(now int64) {
	n.mu.Lock()
	type due struct {
		dest string
		p    *pendingSend
	}
	var dues []due
	for dest, q := range n.pending {
		for _, p := range q {
			if now >= p.nextAt {
				dues = append(dues, due{dest, p})
			}
		}
	}
	n.mu.Unlock()

	for _, d := range dues {
		to, _ := d.p.inner["to"].(string)
		delivered := false
		if nh, ok := n.table.NextHop(to); ok {
			delivered = n.sendToLink(nh, d.p.inner)
		}
		expired := now-d.p.enqueuedAt > n.tun.retryMaxMS
		if delivered || expired {
			n.removePending(d.dest, d.p)
			if !delivered && expired {
				mid, _ := d.p.inner["mid"].(string)
				n.deliverAck(map[string]any{
					"type": "nak", "mid": mid, "hop": n.cfg.Label,
					"reason": "expired", "to": n.cfg.Label, "from": n.cfg.Label,
					"ttl": message.DefaultTTL,
				})
			}
			continue
		}
		d.p.delay = min64(d.p.delay*2, n.tun.retryCapMS)
		d.p.nextAt = now + d.p.delay
	}
}

func (n *Node) removePending(dest string, p *pendingSend) {
	n.mu.Lock()
	defer n.mu.Unlock()
	q := n.pending[dest]
	for i, e := range q {
		if e == p {
			n.pending[dest] = append(q[:i], q[i+1:]...)
			break
		}
	}
	if len(n.pending[dest]) == 0 {
		delete(n.pending, dest)
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
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
	sess := hs.SessionResult()
	peer, _ := sess.PeerCert["label"].(string)
	if n.register(peer, conn, r, sess, false) {
		n.writeKeylog(0, false, sess)
	}
}

// register installs a new link for peer and starts its reader. It returns true
// if the new link was kept. On a collision with an existing link it applies the
// simultaneous-dial tiebreak (protocol.md §3): if the two links were initiated
// by the same side it is a reconnect (last writer wins); if by opposite sides
// it is a genuine dial collision, and both ends deterministically keep the
// session initiated by the lexicographically-lower label, so the pair converges
// on exactly one session.
func (n *Node) register(peer string, conn net.Conn, r *bufio.Reader, sess *handshake.Session, initiator bool) bool {
	now := nowMillis()
	lk := &link{conn: conn, transport: transport.New(sess), initiator: initiator, establishedAt: now, th: thPrefix(sess)}
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
		n.capture(lk.initiator, false, carrier)
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
		n.handleInner(peer, lk, inner)
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
				if n.sweepLink(now, p.peer, p.lk) {
					n.maybeRekey(p.lk, now)
				}
			}
			n.drainRetries(now)
		}
	}
}

// sweepLink runs the once-per-heartbeat maintenance for one link: tear it down
// if it is probe-timeout dead (F3) or data-idle past the idle timeout (F4,
// disabled at idleMS==0), otherwise send it a probe and a route advertisement.
// Returns true if the link was kept.
func (n *Node) sweepLink(now int64, peer string, lk *link) bool {
	if now-lk.lastInbound.Load() > n.tun.probeTimeoutMS {
		n.deregister(peer, lk)
		return false
	}
	if n.tun.idleMS > 0 && now-lk.lastData.Load() > n.tun.idleMS {
		n.sendToLink(peer, message.Bye("idle"))
		n.deregister(peer, lk)
		return false
	}
	n.sendToLink(peer, message.Probe(now))
	n.sendToLink(peer, message.Disco(n.table.AdvertiseTo(peer)))
	return true
}

func (n *Node) handleInner(peer string, lk *link, msg map[string]any) {
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
	case "rekey":
		n.handleRekey(lk, msg)
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
	if !n.sendToLink(nh, fwd) {
		// The next-hop link died between routing and writing; name it as the
		// failing hop so the origin learns which hop broke (F2/D4).
		n.emitNakHop(mid, from, nh, "link-dead")
	}
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
	n.emitNakHop(mid, origin, n.cfg.Label, reason)
}

// emitNakHop sends a NAK naming an explicit failing hop (this node for a local
// drop, the next-hop label for a dead onward link).
func (n *Node) emitNakHop(mid, origin, hop, reason string) {
	if origin == "" || lower(origin) == lower(n.cfg.Label) {
		return
	}
	n.routeControl(message.Nak(mid, n.cfg.Label, origin, hop, reason, message.DefaultTTL))
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

// maybeRekey drives the initiator side of a periodic rekey (F5). It abandons a
// stalled pre-swap handshake at the rekey timeout (keeping the old keys — the
// safe degrade against a peer that does not understand rekey), and otherwise,
// on the session initiator only, starts a fresh BMX when the frame count or
// session age crosses the threshold. Runs under the link lock so the phase-1
// frame is sealed with the current keys without racing another sender.
func (n *Node) maybeRekey(lk *link, nowMs int64) {
	lk.mu.Lock()
	defer lk.mu.Unlock()
	if lk.rekeyHS != nil {
		if nowMs-lk.rekeyStartedAt > n.tun.rekeyTimeoutMS {
			lk.rekeyHS = nil // no swap has happened yet; the old keys stand
		}
		return
	}
	if lk.rekeySession != nil {
		return // initiator has swapped its send key and is awaiting phase 4
	}
	if !lk.initiator {
		return // only the session's original initiator drives rekey
	}
	due := lk.transport.SendSeq() >= uint64(n.tun.rekeyFrames) ||
		lk.transport.ReceiveSeq() >= uint64(n.tun.rekeyFrames) ||
		nowMs-lk.establishedAt >= n.tun.rekeyMS
	if !due {
		return
	}
	hs := handshake.Initiator(n.cfg.Mesh, n.cfg.RootPublic, now(), n.cfg.Cert, n.cfg.IDPrivate)
	mid := message.NewMID()
	n.writeLocked(lk, map[string]any{"type": "rekey", "mid": mid, "phase": 1, "body": b64(hs.WriteMessage1())})
	lk.rekeyHS = hs
	lk.rekeyMID = mid
	lk.rekeyStartedAt = nowMs
}

// handleRekey advances the tunneled-BMX rekey state machine for one link. The
// BMX messages ride inside transport frames, so they arrive through the normal
// reader with no raw-stream race; the key swaps happen at exact frame
// boundaries (protocol.md §5 / security.md §6): each side swaps its send key
// immediately after sealing its last old-key frame, and its receive key
// immediately after opening the peer's.
func (n *Node) handleRekey(lk *link, msg map[string]any) {
	phase := asInt(msg["phase"])
	mid, _ := msg["mid"].(string)
	bodyStr, _ := msg["body"].(string)
	body, _ := base64.StdEncoding.DecodeString(bodyStr)

	lk.mu.Lock()
	defer lk.mu.Unlock()
	switch phase {
	case 1: // responder: accept the fresh bmx1 and reply bmx2
		hs := handshake.Responder(n.cfg.Mesh, n.cfg.RootPublic, now(), n.cfg.Cert, n.cfg.IDPrivate)
		m2, err := hs.ReadMessage1WriteMessage2(body)
		if err != nil {
			return
		}
		lk.rekeyHS = hs
		lk.rekeyMID = mid
		lk.rekeyStartedAt = nowMillis()
		n.writeLocked(lk, map[string]any{"type": "rekey", "mid": mid, "phase": 2, "body": b64(m2)})
	case 2: // initiator: finish with bmx3, then swap its send key
		if lk.rekeyHS == nil {
			return
		}
		m3, err := lk.rekeyHS.ReadMessage2WriteMessage3(body)
		if err != nil {
			lk.rekeyHS = nil
			return
		}
		sess := lk.rekeyHS.SessionResult()
		n.writeLocked(lk, map[string]any{"type": "rekey", "mid": mid, "phase": 3, "body": b64(m3)})
		lk.transport.SwapSend(sess.SendKey) // last old-key frame sent above
		lk.rekeySession = sess
		lk.rekeyHS = nil
	case 3: // responder: verify bmx3, swap receive, send phase 4, swap send
		if lk.rekeyHS == nil {
			return
		}
		if err := lk.rekeyHS.ReadMessage3(body); err != nil {
			lk.rekeyHS = nil
			return
		}
		sess := lk.rekeyHS.SessionResult()
		lk.transport.SwapReceive(sess.ReceiveKey) // phase-3 frame was the last old-key inbound
		n.writeLocked(lk, map[string]any{"type": "rekey", "mid": mid, "phase": 4})
		lk.transport.SwapSend(sess.SendKey)
		lk.rekeyHS = nil
		lk.rekeyEpoch++
		n.writeKeylog(lk.rekeyEpoch, lk.initiator, sess)
		lk.th = thPrefix(sess)
	case 4: // initiator: swap receive; rekey complete
		if lk.rekeySession == nil {
			return
		}
		lk.transport.SwapReceive(lk.rekeySession.ReceiveKey)
		lk.rekeyEpoch++
		n.writeKeylog(lk.rekeyEpoch, lk.initiator, lk.rekeySession)
		lk.th = thPrefix(lk.rekeySession)
		lk.rekeySession = nil
	}
}

// writeLocked seals and writes an inner message on a link the caller already
// holds the lock for — used inside the rekey machine so a seal-then-swap is
// atomic against other senders.
func (n *Node) writeLocked(lk *link, inner map[string]any) {
	if inner["type"] == "data" {
		lk.lastData.Store(nowMillis())
	}
	carrier := lk.transport.Seal(inner)
	n.capture(lk.initiator, true, carrier)
	_, _ = lk.conn.Write(frame.Encode(carrier))
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// thPrefix is the first 16 hex chars of a session's transcript hash, a compact
// session label for the harness's --sessions dump.
func thPrefix(sess *handshake.Session) string {
	h := hex.EncodeToString(sess.H)
	if len(h) > 16 {
		h = h[:16]
	}
	return h
}

// SessionInfo reports, per neighbor, its rekey epoch and transcript-hash label
// — the observability the interop harness dumps via --sessions (both ends of a
// session agree on th, and epoch advances on rekey).
func (n *Node) SessionInfo() map[string]map[string]any {
	n.mu.Lock()
	pairs := make(map[string]*link, len(n.links))
	for peer, lk := range n.links {
		pairs[peer] = lk
	}
	n.mu.Unlock()
	out := map[string]map[string]any{}
	for peer, lk := range pairs {
		lk.mu.Lock()
		out[peer] = map[string]any{"epoch": lk.rekeyEpoch, "th": lk.th}
		lk.mu.Unlock()
	}
	return out
}

// capture tees a transport carrier to the capture file, tagged with the
// absolute wire direction (i2r/r2i) derived from this node's role on the link.
func (n *Node) capture(initiator, sending bool, carrier map[string]any) {
	if n.cfg.CapturePath == "" {
		return
	}
	// The initiator's send is i2r and its receive is r2i; the responder is the
	// mirror.
	i2r := initiator == sending
	dir := "r2i"
	if i2r {
		dir = "i2r"
	}
	n.keylogMu.Lock()
	defer n.keylogMu.Unlock()
	f, err := os.OpenFile(n.cfg.CapturePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]any{"dir": dir, "frame": carrier})
	_, _ = f.Write(append(b, '\n'))
}

// writeKeylog appends this session's directional transport keys to the file
// named by BONEMESH_KEYLOG, in the pinned format (security.md §8):
//
//	BMX3_I2R_TRAFFIC_<epoch> <hex transcript-hash> <hex key>
//	BMX3_R2I_TRAFFIC_<epoch> <hex transcript-hash> <hex key>
//
// It is a no-op unless the env var is set, and it logs a loud warning per
// session because it defeats forward secrecy for anyone holding the file. The
// node maps its role-relative send/receive keys onto the absolute I2R/R2I
// directions so one inspector reads logs from either end.
func (n *Node) writeKeylog(epoch int, initiator bool, sess *handshake.Session) {
	if n.tun.keylogPath == "" || sess == nil {
		return
	}
	i2r, r2i := sess.SendKey, sess.ReceiveKey
	if !initiator {
		i2r, r2i = sess.ReceiveKey, sess.SendKey
	}
	th := hex.EncodeToString(sess.H)
	line := func(dir string, key []byte) string {
		return fmt.Sprintf("BMX3_%s_TRAFFIC_%d %s %s\n", dir, epoch, th, hex.EncodeToString(key))
	}
	n.keylogMu.Lock()
	defer n.keylogMu.Unlock()
	f, err := os.OpenFile(n.tun.keylogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line("I2R", i2r) + line("R2I", r2i))
	if epoch == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: BONEMESH_KEYLOG is on; transport keys written to %s — forward secrecy is defeated for anyone holding that file\n", n.tun.keylogPath)
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
	n.capture(lk.initiator, true, carrier)
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
