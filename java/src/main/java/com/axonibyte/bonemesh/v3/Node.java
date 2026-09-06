/*
 * Copyright (c) 2026 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.axonibyte.bonemesh.v3;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;
import com.axonibyte.bonemesh.v3.handshake.Handshake;
import com.axonibyte.bonemesh.v3.message.Chunker;
import com.axonibyte.bonemesh.v3.message.Dedup;
import com.axonibyte.bonemesh.v3.message.Messages;
import com.axonibyte.bonemesh.v3.message.Reassembler;
import com.axonibyte.bonemesh.v3.routing.Router;
import com.axonibyte.bonemesh.v3.routing.RoutingTable;
import com.axonibyte.bonemesh.v3.transport.FrameCodec;
import com.axonibyte.bonemesh.v3.transport.TransportSession;

/**
 * A BoneMesh v3 mesh node: the facade that ties the handshake, transport,
 * message, and routing layers together over real TCP sockets (protocol.md
 * &sect;3). A node holds one authenticated, encrypted session per neighbor,
 * reuses it for all traffic, delivers messages addressed to itself to its data
 * listeners, and relays the rest toward the next hop.
 *
 * <p>This is the v3 reference node. It is deliberately straightforward — one
 * reader thread per neighbor link — and favors clarity over throughput.</p>
 *
 * @author Caleb L. Power
 */
public final class Node {

  private final String label;
  private final String mesh;
  private final byte[] rootPublicKey;
  private final Certificate certificate;
  private final Signer identity;
  private final SecureRandom rng = new SecureRandom();

  private Tunables tunables = Tunables.load();
  private final RoutingTable routing;
  private final Router router;
  private final Dedup dedup = new Dedup(4096);
  private final Reassembler reassembler = new Reassembler();
  private final Map<String, PeerLink> links = new ConcurrentHashMap<>();
  private final CopyOnWriteArrayList<Consumer<JSONObject>> dataListeners = new CopyOnWriteArrayList<>();
  private final CopyOnWriteArrayList<Consumer<JSONObject>> ackListeners = new CopyOnWriteArrayList<>();

  private final ServerSocket serverSocket;
  private final Thread acceptThread;
  private volatile boolean running = true;

  private Node(String label, String mesh, byte[] rootPublicKey, Certificate certificate,
      Signer identity, int port) throws IOException {
    this.label = label;
    this.mesh = mesh;
    this.rootPublicKey = rootPublicKey;
    this.certificate = certificate;
    this.identity = identity;
    this.routing = new RoutingTable(label);
    this.router = new Router(label, routing);
    this.serverSocket = new ServerSocket(port);
    this.acceptThread = new Thread(this::acceptLoop, "bonemesh-accept-" + label);
    this.acceptThread.setDaemon(true);
    this.acceptThread.start();
    this.heartbeatThread = new Thread(this::heartbeatLoop, "bonemesh-heartbeat-" + label);
    this.heartbeatThread.setDaemon(true);
    this.heartbeatThread.start();
  }

  private final Thread heartbeatThread;
  private static final long HEARTBEAT_INTERVAL_MILLIS = 1000L;

  /**
   * Builds and starts a node listening on the given port.
   *
   * @param label this node's label
   * @param mesh the mesh identifier
   * @param rootPublicKey the pinned raw ML-DSA-87 root public key
   * @param certificate this node's membership certificate
   * @param identity this node's ML-DSA-65 identity (with private key)
   * @param port the listening port (0 for an ephemeral port)
   * @return the started node
   * @throws IOException if the server socket cannot be opened
   */
  public static Node start(String label, String mesh, byte[] rootPublicKey,
      Certificate certificate, Signer identity, int port) throws IOException {
    return new Node(label, mesh, rootPublicKey, certificate, identity, port);
  }

  // Package-visible test seam: swap in tunables with explicit values so the
  // liveness/idle sweep can be exercised without setting process environment.
  void useTunablesForTest(Tunables t) {
    this.tunables = t;
  }

  /** @return the port this node is listening on */
  public int port() {
    return serverSocket.getLocalPort();
  }

  /** @return this node's label */
  public String label() {
    return label;
  }

  /**
   * A snapshot of the distance-vector routing table: each learned destination
   * mapped to the next-hop neighbor it is reached through. Used by the interop
   * convergence tier to assert no route runs through a downed node.
   *
   * @return an immutable-enough copy of destination to next-hop
   */
  public java.util.Map<String, String> routeTable() {
    java.util.Map<String, String> table = new java.util.LinkedHashMap<>();
    for(String dest : routing.knownRouteDestinations())
      table.put(dest, routing.nextHop(dest));
    return table;
  }

  /**
   * Registers a listener for application payloads delivered to this node.
   *
   * @param listener the listener
   */
  public void addDataListener(Consumer<JSONObject> listener) {
    dataListeners.add(listener);
  }

  /**
   * Dials a peer, completes the BMX handshake as initiator, and keeps the
   * resulting session as a neighbor link.
   *
   * @param host the peer's host
   * @param port the peer's port
   * @return the peer's authenticated label
   * @throws IOException on a network error
   * @throws Handshake.HandshakeException if the handshake fails
   */
  public String connect(String host, int port)
      throws IOException, Handshake.HandshakeException {
    Socket socket = new Socket();
    socket.connect(new InetSocketAddress(host, port), 5000);
    long now = System.currentTimeMillis() / 1000L;
    Handshake hs = Handshake.initiator(mesh, rootPublicKey, now, certificate, identity, rng);
    OutputStream out = socket.getOutputStream();
    InputStream in = socket.getInputStream();

    writeRaw(out, hs.writeMessage1());
    byte[] m2 = readRawLine(in, FrameCodec.HANDSHAKE_CAP);
    writeRaw(out, hs.readMessage2WriteMessage3(m2));

    String peer = hs.session().peerCertificate().label();
    PeerLink link = new PeerLink(peer, socket, new TransportSession(hs.session()), true);
    if(registerLink(peer, link)) {
      Thread reader = new Thread(link::readLoop, "bonemesh-read-" + label + "-" + peer);
      reader.setDaemon(true);
      reader.start();
    }
    return peer;
  }

  /**
   * Sends an application payload toward a destination.
   *
   * @param to the destination label
   * @param payload the application payload
   * @return <code>true</code> if the message was handed to a next hop
   */
  public boolean send(String to, JSONObject payload) {
    return sendInternal(to, payload, Messages.DEFAULT_TTL).ok;
  }

  /**
   * Sends an application payload and returns its message id, so a caller can
   * correlate the ack or nak later delivered to {@link #addAckListener} against
   * the message it answers (protocol.md &sect;7).
   *
   * @param to the destination label
   * @param payload the application payload
   * @return the message id
   */
  public String sendMid(String to, JSONObject payload) {
    return sendInternal(to, payload, Messages.DEFAULT_TTL).mid;
  }

  // Package-visible: send with an explicit initial TTL so a test can force a
  // relay to exhaust the hop limit and emit a NAK. Returns the message id.
  String sendWithTtl(String to, JSONObject payload, int ttl) {
    return sendInternal(to, payload, ttl).mid;
  }

  private SendResult sendInternal(String to, JSONObject payload, int ttl) {
    String mid = Messages.newMid(rng);
    boolean all = true;
    for(JSONObject msg : Chunker.split(mid, label, to, ttl, payload))
      all = forward(msg) && all;
    return new SendResult(mid, all);
  }

  private record SendResult(String mid, boolean ok) { }

  /**
   * Registers a listener for ack and nak messages addressed to this node (the
   * origin), each delivered as the raw inner JSON.
   *
   * @param listener the listener
   */
  public void addAckListener(Consumer<JSONObject> listener) {
    ackListeners.add(listener);
  }

  private boolean forward(JSONObject dataMessage) {
    String next = routing.nextHop(dataMessage.getString("to"));
    if(next == null) return false;
    PeerLink link = links.get(key(next));
    if(link == null) return false;
    link.send(dataMessage);
    return true;
  }

  /**
   * Stops the node: closes the server and every neighbor link.
   */
  public void kill() {
    running = false;
    acceptThread.interrupt();
    heartbeatThread.interrupt();
    closeQuietly(serverSocket);
    for(PeerLink link : links.values()) link.close();
    links.clear();
  }

  // Periodically probes each neighbor (for RTT) and advertises reachability
  // (for route learning), and runs the per-link liveness/idle sweep. Keeps the
  // mesh's routing tables converging.
  private void heartbeatLoop() {
    try {
      while(running) {
        Thread.sleep(HEARTBEAT_INTERVAL_MILLIS);
        long now = System.currentTimeMillis();
        for(Map.Entry<String, PeerLink> e : links.entrySet())
          sweepLink(now, e.getValue());
      }
    } catch(InterruptedException ignored) { }
  }

  // Once-per-heartbeat maintenance for one link: tear it down if it is
  // probe-timeout dead (F3) or data-idle past the idle timeout (F4, disabled at
  // idleMillis==0), otherwise send it a probe and a route advertisement.
  private void sweepLink(long now, PeerLink link) {
    if(now - link.lastInboundMillis > tunables.probeTimeoutMillis) {
      link.close();
      return;
    }
    if(tunables.idleMillis > 0 && now - link.lastDataMillis > tunables.idleMillis) {
      link.send(Messages.bye("idle"));
      link.close();
      return;
    }
    link.send(Messages.probe(now));
    link.send(Messages.disco(routing.advertiseTo(link.peer)));
  }

  private void acceptLoop() {
    while(running) {
      try {
        Socket socket = serverSocket.accept();
        Thread t = new Thread(() -> respondAndServe(socket), "bonemesh-conn-" + label);
        t.setDaemon(true);
        t.start();
      } catch(IOException e) {
        if(running) continue;
        return;
      }
    }
  }

  private void respondAndServe(Socket socket) {
    try {
      long now = System.currentTimeMillis() / 1000L;
      Handshake hs = Handshake.responder(mesh, rootPublicKey, now, certificate, identity, rng);
      InputStream in = socket.getInputStream();
      OutputStream out = socket.getOutputStream();

      byte[] m1 = readRawLine(in, FrameCodec.HANDSHAKE_CAP);
      writeRaw(out, hs.readMessage1WriteMessage2(m1));
      byte[] m3 = readRawLine(in, FrameCodec.HANDSHAKE_CAP);
      hs.readMessage3(m3);

      String peer = hs.session().peerCertificate().label();
      PeerLink link = new PeerLink(peer, socket, new TransportSession(hs.session()), false);
      if(registerLink(peer, link)) link.readLoop();
    } catch(Exception e) {
      closeQuietly(socket);
    }
  }

  // Installs a new link for peer, returning true if it was kept. On a collision
  // with an existing link (protocol.md §3): if the two links were initiated by
  // the same side it is a reconnect (last writer wins); if by opposite sides it
  // is a genuine dial collision, and both ends deterministically keep the
  // session initiated by the lexicographically-lower label, so the pair
  // converges on exactly one session.
  private boolean registerLink(String peer, PeerLink link) {
    PeerLink toClose = null;
    boolean keepNew = true;
    synchronized(links) {
      PeerLink previous = links.get(key(peer));
      if(previous != null && previous.initiator != link.initiator) {
        boolean selfWins = key(label).compareTo(key(peer)) < 0;
        keepNew = link.initiator == selfWins;
      }
      if(keepNew) {
        links.put(key(peer), link);
        if(previous != null && previous != link) toClose = previous;
      }
    }
    if(!keepNew) {
      // This new link lost the tiebreak; drop it and keep the existing one. Its
      // close() is identity-guarded (it was never in the map), so it cannot
      // withdraw the surviving link's routes.
      link.close();
      return false;
    }
    if(toClose != null) toClose.close();
    // A fresh neighbor starts with an optimistic small latency until probes
    // refine it; that is enough for it to be a routable next hop.
    routing.observeNeighbor(peer, 1);
    return true;
  }

  // Handles one decrypted inner message.
  private void handleInner(String peer, JSONObject inner) {
    String type = inner.optString("type", "");
    switch(type) {
      case "data": {
        int chunkIndex = inner.has("chunk") ? inner.getJSONObject("chunk").getInt("i") : -1;
        String mid = inner.getString("mid");
        // Dedup per (mid, chunk) with a type prefix so a relayed ack, which
        // carries the same mid as the data it answers, cannot be mistaken for a
        // duplicate of that data.
        if(dedup.seenBefore("d:" + mid + ":" + chunkIndex)) return;
        String from = inner.optString("from", "");
        Router.Decision d = router.route(inner);
        switch(d.action()) {
          case DELIVER:
            // Ack once the full message is reassembled (one ack per completed
            // application message), routed back toward the origin.
            reassembler.offer(inner).ifPresent(payload -> {
              for(Consumer<JSONObject> l : dataListeners) l.accept(payload);
              if(!from.isEmpty() && !from.equalsIgnoreCase(label))
                routeControl(Messages.ackTo(mid, label, from, Messages.DEFAULT_TTL));
            });
            break;
          case FORWARD:
            forward(d.message());
            break;
          case DROP_TTL:
            // F6/D4: the relay that dropped it names ITSELF as the failing hop.
            emitNak(mid, from, "ttl");
            break;
          case UNREACHABLE:
            emitNak(mid, from, "no-route");
            break;
          default:
            break;
        }
        break;
      }
      case "ack":
        handleControl(inner, "a:");
        break;
      case "nak":
        handleControl(inner, "n:");
        break;
      case "probe":
        PeerLink link = links.get(key(peer));
        if(link != null) link.send(Messages.echo(inner.getLong("token")));
        break;
      case "echo":
        long rtt = System.currentTimeMillis() - inner.getLong("token");
        routing.observeNeighbor(peer, Math.max(0, rtt));
        break;
      case "disco":
        JSONObject routes = inner.getJSONObject("routes");
        for(String dest : routes.keySet())
          routing.learnRoute(dest, peer, routes.getLong(dest));
        break;
      default:
        break;
    }
  }

  // Relays or delivers an ack/nak (routed back toward the origin like data). A
  // type-prefixed dedup key keeps a relayed ack from colliding with the data it
  // answers. ack/nak are never themselves ack'd or nak'd.
  private void handleControl(JSONObject msg, String prefix) {
    String mid = msg.getString("mid");
    if(dedup.seenBefore(prefix + mid)) return;
    String to = msg.optString("to", "");
    if(to.equalsIgnoreCase(label)) {
      deliverAck(msg);
      return;
    }
    int ttl = msg.getInt("ttl") - 1;
    if(ttl <= 0) return; // drop silently; no nak-of-nak
    String nh = routing.nextHop(to);
    if(nh == null) return;
    PeerLink link = links.get(key(nh));
    if(link != null) link.send(new JSONObject(msg.toString()).put("ttl", ttl));
  }

  // Sends a NAK back toward the origin naming this node as the failing hop.
  // Best-effort: if the NAK itself cannot be routed it is dropped (no recursion).
  private void emitNak(String mid, String origin, String reason) {
    if(origin == null || origin.isEmpty() || origin.equalsIgnoreCase(label)) return;
    routeControl(Messages.nak(mid, label, origin, label, reason, Messages.DEFAULT_TTL));
  }

  // Sends a freshly-built ack/nak toward its destination, dropping silently if
  // there is no route (never producing a control-of-control).
  private void routeControl(JSONObject msg) {
    String to = msg.getString("to");
    String nh = routing.nextHop(to);
    if(nh == null) return;
    PeerLink link = links.get(key(nh));
    if(link != null) link.send(msg);
  }

  // Hands an ack/nak addressed to this node to the ack listeners.
  private void deliverAck(JSONObject msg) {
    for(Consumer<JSONObject> l : ackListeners) l.accept(msg);
  }

  private static void writeRaw(OutputStream out, byte[] bytes) throws IOException {
    out.write(bytes);
    out.flush();
  }

  // Reads one newline-terminated line (including the newline), bounded by cap.
  private static byte[] readRawLine(InputStream in, int cap) throws IOException {
    byte[] buffer = new byte[cap];
    int len = 0;
    for(;;) {
      int b = in.read();
      if(b < 0) throw new IOException("stream ended before a line newline");
      if(len >= cap) throw new IOException("line exceeded cap");
      buffer[len++] = (byte) b;
      if(b == '\n') break;
    }
    byte[] line = new byte[len];
    System.arraycopy(buffer, 0, line, 0, len);
    return line;
  }

  private static void closeQuietly(java.io.Closeable c) {
    try {
      if(c != null) c.close();
    } catch(IOException ignored) { }
  }

  private static String key(String label) {
    return label.toLowerCase(java.util.Locale.ROOT);
  }

  /** One authenticated, encrypted link to a neighbor. */
  private final class PeerLink {
    private final String peer;
    private final Socket socket;
    private final TransportSession session;
    private final InputStream in;
    private final OutputStream out;
    // Whether this node dialed the connection this link runs over (protocol.md
    // §3: the simultaneous-dial tiebreak needs to know who initiated each
    // competing session).
    private final boolean initiator;
    // When the handshake completed.
    private final long establishedAtMillis;
    // The last successfully opened inbound frame — any authenticated frame
    // proves the peer is alive.
    private volatile long lastInboundMillis;
    // The last data frame sent over or received on this link; probe/echo/disco
    // never count as activity.
    private volatile long lastDataMillis;

    PeerLink(String peer, Socket socket, TransportSession session, boolean initiator)
        throws IOException {
      this.peer = peer;
      this.socket = socket;
      this.session = session;
      this.in = socket.getInputStream();
      this.out = socket.getOutputStream();
      this.initiator = initiator;
      long now = System.currentTimeMillis();
      this.establishedAtMillis = now;
      this.lastInboundMillis = now;
      this.lastDataMillis = now;
    }

    synchronized void send(JSONObject inner) {
      try {
        if("data".equals(inner.optString("type", ""))) lastDataMillis = System.currentTimeMillis();
        FrameCodec.writeFrame(out, session.seal(inner), FrameCodec.TRANSPORT_CAP);
      } catch(Exception e) {
        close();
      }
    }

    void readLoop() {
      try {
        while(running && !socket.isClosed()) {
          JSONObject carrier = FrameCodec.readFrame(in, FrameCodec.TRANSPORT_CAP);
          JSONObject inner = session.open(carrier);
          lastInboundMillis = System.currentTimeMillis();
          String t = inner.optString("type", "");
          if("data".equals(t)) lastDataMillis = System.currentTimeMillis();
          if("bye".equals(t)) {
            // Peer is closing this session gracefully; tear it down and stop.
            close();
            return;
          }
          handleInner(peer, inner);
        }
      } catch(Exception e) {
        close();
      }
    }

    // Closes the link and withdraws its routes — but the route withdrawal only
    // fires if this link is still the registered one for peer. A reconnect may
    // have displaced it, and a stale link's death must not withdraw the live
    // link's routes. The map mutation shares the links monitor with
    // registerLink so a register/close race cannot resurrect a removed peer.
    void close() {
      boolean wasCurrent;
      synchronized(links) {
        wasCurrent = links.remove(key(peer), this);
      }
      if(wasCurrent) routing.removeNeighbor(peer);
      closeQuietly(socket);
    }
  }
}
