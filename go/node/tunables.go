package node

import (
	"os"
	"strconv"
)

// tunables are the node's operational knobs (protocol.md §0): local behavior,
// never part of the wire contract, read once from the environment at node
// start. Two nodes with different values still interoperate.
type tunables struct {
	probeTimeoutMS int64  // link dead after this long with no opened inbound frame
	idleMS         int64  // data-idle teardown; 0 disables
	retryBaseMS    int64  // initial retry delay
	retryCapMS     int64  // retry delay cap
	retryMaxMS     int64  // total retry-queue lifetime; 0 disables retry
	rekeyMS        int64  // rekey on session age
	rekeyFrames    int64  // rekey when either direction's seq reaches this
	rekeyTimeoutMS int64  // abandon an in-flight rekey (keep old keys)
	keylogPath     string // key-log file; empty disables (security.md §8)
}

func loadTunables() tunables {
	return tunables{
		probeTimeoutMS: envInt64("BONEMESH_PROBE_TIMEOUT_MS", 15000),
		idleMS:         envInt64("BONEMESH_IDLE_MS", 0),
		retryBaseMS:    envInt64("BONEMESH_RETRY_BASE_MS", 500),
		retryCapMS:     envInt64("BONEMESH_RETRY_CAP_MS", 30000),
		retryMaxMS:     envInt64("BONEMESH_RETRY_MAX_MS", 60000),
		rekeyMS:        envInt64("BONEMESH_REKEY_MS", 3600000),
		rekeyFrames:    envInt64("BONEMESH_REKEY_FRAMES", 65536),
		rekeyTimeoutMS: envInt64("BONEMESH_REKEY_TIMEOUT_MS", 10000),
		keylogPath:     os.Getenv("BONEMESH_KEYLOG"),
	}
}

func envInt64(name string, fallback int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return i
}
