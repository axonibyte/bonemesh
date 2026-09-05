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

  private final RoutingTable routing;
  private final Router router;
  private final Dedup dedup = new Dedup(4096);
  private final Reassembler reassembler = new Reassembler();
  private final Map<String, PeerLink> links = new ConcurrentHashMap<>();
  private final CopyOnWriteArrayList<Consumer<JSONObject>> dataListeners = new CopyOnWriteArrayList<>();

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

  /** @return the port this node is listening on */
  public int port() {
    return serverSocket.getLocalPort();
  }

  /** @return this node's label */
  public String label() {
    return label;
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
    PeerLink link = new PeerLink(peer, socket, new TransportSession(hs.session()));
    registerLink(peer, link);
    Thread reader = new Thread(link::readLoop, "bonemesh-read-" + label + "-" + peer);
    reader.setDaemon(true);
    reader.start();
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
    String mid = Messages.newMid(rng);
    boolean all = true;
    for(JSONObject msg : Chunker.split(mid, label, to, Messages.DEFAULT_TTL, payload))
      all = forward(msg) && all;
    return all;
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
  // (for route learning). Keeps the mesh's routing tables converging.
  private void heartbeatLoop() {
    try {
      while(running) {
        Thread.sleep(HEARTBEAT_INTERVAL_MILLIS);
        for(Map.Entry<String, PeerLink> e : links.entrySet()) {
          PeerLink link = e.getValue();
          link.send(Messages.probe(System.currentTimeMillis()));
          link.send(Messages.disco(routing.advertiseTo(link.peer)));
        }
      }
    } catch(InterruptedException ignored) { }
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
      PeerLink link = new PeerLink(peer, socket, new TransportSession(hs.session()));
      registerLink(peer, link);
      link.readLoop();
    } catch(Exception e) {
      closeQuietly(socket);
    }
  }

  private void registerLink(String peer, PeerLink link) {
    PeerLink previous = links.put(key(peer), link);
    if(previous != null && previous != link) previous.close();
    // A fresh neighbor starts with an optimistic small latency until probes
    // refine it; that is enough for it to be a routable next hop.
    routing.observeNeighbor(peer, 1);
  }

  // Handles one decrypted inner message.
  private void handleInner(String peer, JSONObject inner) {
    String type = inner.optString("type", "");
    switch(type) {
      case "data": {
        int chunkIndex = inner.has("chunk") ? inner.getJSONObject("chunk").getInt("i") : -1;
        // Dedup per (mid, chunk) so the chunks of one message are not mistaken
        // for duplicates of each other.
        if(dedup.seenBefore(inner.getString("mid") + ":" + chunkIndex)) return;
        Router.Decision d = router.route(inner);
        switch(d.action()) {
          case DELIVER:
            reassembler.offer(inner).ifPresent(payload -> {
              for(Consumer<JSONObject> l : dataListeners) l.accept(payload);
            });
            break;
          case FORWARD:
            forward(d.message());
            break;
          default:
            // DROP_TTL / UNREACHABLE: the origin learns via the absence of an
            // ack; explicit NAK routing is a refinement.
            break;
        }
        break;
      }
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

    PeerLink(String peer, Socket socket, TransportSession session) throws IOException {
      this.peer = peer;
      this.socket = socket;
      this.session = session;
      this.in = socket.getInputStream();
      this.out = socket.getOutputStream();
    }

    synchronized void send(JSONObject inner) {
      try {
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
          handleInner(peer, inner);
        }
      } catch(Exception e) {
        close();
      }
    }

    void close() {
      links.remove(key(peer), this);
      routing.removeNeighbor(peer);
      closeQuietly(socket);
    }
  }
}
