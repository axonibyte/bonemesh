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

package com.axonibyte.bonemesh.v3.routing;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

/**
 * A concurrency harness for {@link RoutingTable} (methodology tier 8): the v3
 * {@code Node} drives one routing table from a heartbeat thread and one reader
 * thread per neighbor at once. This test hammers the table from many threads —
 * learning routes, observing neighbors, advertising, and removing neighbors —
 * and asserts no thread throws. It exists because a single-run test (local or
 * reaper) cannot see a data race; this one reliably surfaced the
 * {@link java.util.ConcurrentModificationException} that reached CI, and now
 * proves the table is safe under concurrent access.
 */
public class RoutingConcurrencyTest {

  @Test void tableSurvivesConcurrentMutationAndRemoval() throws Exception {
    RoutingTable table = new RoutingTable("self");
    int neighbors = 8;
    for(int i = 0; i < neighbors; i++) table.observeNeighbor("n" + i, 10);

    int workers = 12;
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(workers);
    AtomicBoolean stop = new AtomicBoolean(false);
    ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();

    for(int w = 0; w < workers; w++) {
      final int id = w;
      new Thread(() -> {
        try {
          start.await();
          for(int iter = 0; iter < 20_000 && !stop.get(); iter++) {
            String neighbor = "n" + (iter % neighbors);
            switch(id % 4) {
              case 0 -> table.learnRoute("dest" + (iter % 50), neighbor, iter % 100);
              case 1 -> table.observeNeighbor(neighbor, iter % 30);
              case 2 -> table.advertiseTo(neighbor);
              default -> {
                table.removeNeighbor(neighbor);
                table.observeNeighbor(neighbor, 5); // re-add so routes keep churning
              }
            }
            table.nextHop("dest" + (iter % 50));
          }
        } catch(Throwable t) {
          errors.add(t);
          stop.set(true);
        } finally {
          done.countDown();
        }
      }, "routing-worker-" + w).start();
    }

    start.countDown();
    assertTrue(done.await(30, TimeUnit.SECONDS), "workers did not finish");
    if(!errors.isEmpty()) {
      Throwable first = errors.peek();
      fail("concurrent access threw " + first.getClass().getName() + ": " + first.getMessage());
    }
  }
}
