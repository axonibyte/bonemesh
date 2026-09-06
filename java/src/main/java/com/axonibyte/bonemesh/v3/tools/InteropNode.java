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

package com.axonibyte.bonemesh.v3.tools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.Node;
import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * The Java driver for the language-agnostic interop harness (interop/). It
 * implements the neutral driver contract (interop/README.md) — a
 * {@code listen} mode and a {@code connect} mode over shared, implementation-
 * independent key and certificate files — so the harness can pair it with any
 * other implementation's driver without knowing or caring which is which.
 *
 * @author Caleb L. Power
 */
public final class InteropNode {

  private InteropNode() { }

  /**
   * @param args the mode and its flags
   * @throws Exception on any error
   */
  public static void main(String[] args) throws Exception {
    if(args.length < 1) {
      System.err.println("usage: InteropNode <listen|connect> [--flag value ...]");
      System.exit(2);
    }
    Map<String, String> f = flags(args);

    // caps advertises the feature tokens this implementation supports, so a
    // tier can health-probe and skip a driver that lacks what it exercises.
    // (No --capture: that transport-stream tee is Go-only.)
    if(args[0].equals("caps")) {
      System.out.println("ack nak rekey idle probe-death dial-tiebreak keylog sessions acks");
      return;
    }

    // keygen needs no mesh/cert: generate an identity, write pub (standard raw)
    // and priv (this implementation's own format). The private key never leaves.
    if(args[0].equals("keygen")) {
      Signer id = Signer.generate(Signer.Level.DSA65, new java.security.SecureRandom());
      Files.writeString(Paths.get(f.get("id-pub")), Base64.getEncoder().encodeToString(id.publicKey()));
      Files.writeString(Paths.get(f.get("id-priv")), Base64.getEncoder().encodeToString(id.privateKey()));
      return;
    }

    byte[] rootPub = readBase64(f.get("root-pub"));
    Certificate cert = Certificate.fromJSON(new JSONObject(readString(f.get("cert"))));
    Signer identity = Signer.fromKeys(Signer.Level.DSA65, readBase64(f.get("id-pub")), readBase64(f.get("id-priv")));
    String mesh = f.get("mesh");
    String label = cert.label();
    long seconds = Long.parseLong(f.getOrDefault("seconds", "10"));

    switch(args[0]) {
      case "listen": {
        Node node = Node.start(label, mesh, rootPub, cert, identity, Integer.parseInt(f.get("port")));
        java.nio.file.Path out = Paths.get(f.get("out"));
        node.addDataListener(payload -> appendLine(out, payload.toString()));
        wireAcks(node, f);
        long deadline = System.currentTimeMillis() + seconds * 1000L;
        while(System.currentTimeMillis() < deadline) {
          dumpSessions(node, f);
          Thread.sleep(200);
        }
        node.kill();
        break;
      }
      case "connect": {
        Node node = Node.start(label, mesh, rootPub, cert, identity, 0);
        wireAcks(node, f);
        node.connect(f.get("host"), Integer.parseInt(f.get("port")));
        JSONObject payload = new JSONObject(readString(f.get("message")));
        String to = f.get("to");
        long deadline = System.currentTimeMillis() + seconds * 1000L;
        while(System.currentTimeMillis() < deadline) {
          if(node.send(to, payload)) break;
          Thread.sleep(200);
        }
        // Stay up briefly so acks/naks and the session dump can be observed.
        long end = System.currentTimeMillis() + 1500L;
        while(System.currentTimeMillis() < end) {
          dumpSessions(node, f);
          Thread.sleep(200);
        }
        node.kill();
        break;
      }
      // A multi-link node for the convergence tier: dials several peers
      // (--peers host:port,host:port), optionally records delivered payloads
      // (--out), repeatedly sends toward a routed destination (--send-to with
      // --message), and periodically dumps its routing table (--routes). Stays
      // up for --seconds. Relay nodes need no special mode — a plain listener
      // already forwards.
      case "mesh": {
        Node node = Node.start(label, mesh, rootPub, cert, identity,
            Integer.parseInt(f.getOrDefault("port", "0")));
        if(f.containsKey("out")) {
          java.nio.file.Path out = Paths.get(f.get("out"));
          node.addDataListener(payload -> appendLine(out, payload.toString()));
        }
        wireAcks(node, f);
        for(String peer : f.getOrDefault("peers", "").split(",")) {
          if(peer.isBlank()) continue;
          int c = peer.lastIndexOf(':');
          node.connect(peer.substring(0, c), Integer.parseInt(peer.substring(c + 1)));
        }
        JSONObject payload = f.containsKey("message")
            ? new JSONObject(readString(f.get("message"))) : null;
        String sendTo = f.get("send-to");
        java.nio.file.Path routes = f.containsKey("routes") ? Paths.get(f.get("routes")) : null;
        long deadline = System.currentTimeMillis() + seconds * 1000L;
        while(System.currentTimeMillis() < deadline) {
          if(sendTo != null && payload != null) node.send(sendTo, payload);
          if(routes != null)
            Files.writeString(routes, new JSONObject(node.routeTable()).toString());
          dumpSessions(node, f);
          Thread.sleep(500);
        }
        node.kill();
        break;
      }
      default:
        System.err.println("unknown mode: " + args[0]);
        System.exit(2);
    }
  }

  // --acks: append each received ack/nak inner message as one JSON line.
  private static void wireAcks(Node node, Map<String, String> f) {
    if(f.containsKey("acks")) {
      java.nio.file.Path acks = Paths.get(f.get("acks"));
      node.addAckListener(inner -> appendLine(acks, inner.toString()));
    }
  }

  // --sessions: rewrite the per-peer {epoch, th} dump as sessions change.
  private static void dumpSessions(Node node, Map<String, String> f) {
    if(!f.containsKey("sessions")) return;
    try {
      Files.writeString(Paths.get(f.get("sessions")),
          new JSONObject(node.sessionInfo()).toString(), StandardCharsets.UTF_8);
    } catch(Exception ignored) { }
  }

  private static synchronized void appendLine(java.nio.file.Path out, String line) {
    try {
      Files.writeString(out, line + "\n", StandardCharsets.UTF_8,
          StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    } catch(Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] readBase64(String path) throws Exception {
    return Base64.getDecoder().decode(readString(path).trim());
  }

  private static String readString(String path) throws Exception {
    return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
  }

  private static Map<String, String> flags(String[] args) {
    Map<String, String> f = new HashMap<>();
    for(int i = 1; i + 1 < args.length; i += 2)
      if(args[i].startsWith("--")) f.put(args[i].substring(2), args[i + 1]);
    return f;
  }
}
