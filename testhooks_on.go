//go:build testhooks

package main

import (
	"os"
	"strconv"
)

// Built ONLY for test_agent.py (go build -tags testhooks). Test mode re-allows what the stub
// machines need — loopback machine IPs, an http://127.0.0.1 site or download link, and the
// machinePort / discovery overrides — none of which the real admin page ever sends. Release
// binaries are built without this file, so none of it can be switched on in the field.
const testMode = true

func init() {
	if v, err := strconv.Atoi(os.Getenv("ODD_TEST_MACHINE_PORT")); err == nil {
		tcpListPort = v
	}
	if v, err := strconv.Atoi(os.Getenv("ODD_TEST_RELAY_MAX_READ_BYTES")); err == nil {
		relayMaxReadBytes = v
	}
	dataDirOverride = os.Getenv("ODD_TEST_DATA_DIR")
}
