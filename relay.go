package main

// Relay mode: instead of waiting for a browser on THIS computer, connect OUT to the site and ask
// "anything for me?". Lets a phone or tablet (which can't reach a LAN address, nor 127.0.0.1 on
// another device) drive the machines. Jobs live on the site for ~2 minutes only; this side also
// refuses a job older than that, so nothing is ever sent to a machine late.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	jobMaxAge           = 120 * time.Second
	relayMaxBackoff     = 300 // seconds
	relayHTTPTimeout    = 20 * time.Second
	relayMinTokenLength = 32
)

// The site keeps a relay result under 1.5 MB (functions/api/agent.js); base64 grows a file by a third.
var relayMaxReadBytes = 1_000_000

var relayClient = noRedirectClient(relayHTTPTimeout)

// lanIPGuess is this computer's LAN address (the interface used to reach the internet); "" if
// unknown. A UDP "connect" sends nothing — it only makes the OS pick the outgoing interface.
func lanIPGuess() string {
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// runJob runs one relay job and returns (httpStatus, body) — the same shape the loopback API
// answers with, so the browser code treats both paths alike.
func runJob(job map[string]any) (status int, body map[string]any) {
	jtype := str(job, "type")
	defer func() { // never let one bad job kill the loop
		if v := recover(); v != nil {
			logf("%s unexpected error: %v", jtype, v)
			status, body = 500, errBody(fmt.Sprintf("Unexpected error: %v", v))
		}
	}()
	if jtype == "discover" {
		machines, err := discoverMachines(udpTargetPort, udpListenPort, discoveryWindow, udpBroadcastIP)
		if err != nil {
			logf("discover error: %v", err)
			return failure(err)
		}
		return 200, map[string]any{"status": "ok", "machines": machines}
	}
	machineIP := str(job, "machineIp")
	if problem := validateMachineIP(machineIP); problem != "" {
		return 400, errBody(problem)
	}
	switch jtype {
	case "list", "send", "read", "delete":
		status, body = runOp(jtype, machineIP, tcpListPort, job, relayMaxReadBytes)
		if jtype == "list" && (status == 500 || status == 502) {
			logf("list error: %v", body["message"])
		}
		return status, body
	}
	return 400, errBody("Unknown job type.")
}

type relayHTTPError struct{ code int }

func (e *relayHTTPError) Error() string { return "HTTP " + strconv.Itoa(e.code) }

func relayPost(ctx context.Context, relayURL, token, op string, payload any) (map[string]any, error) {
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(relayURL, "/")+"/api/agent?op="+op, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", token)
	req.Header.Set("User-Agent", agentName+"/"+agentVersion)
	resp, err := relayClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &relayHTTPError{resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // the site's answers are small
	if err != nil {
		return nil, err
	}
	reply := map[string]any{}
	if len(bytes.TrimSpace(data)) == 0 {
		return reply, nil
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, err
	}
	if reply == nil {
		reply = map[string]any{}
	}
	return reply, nil
}

func number(v any, def float64) (float64, bool) {
	switch n := v.(type) {
	case nil:
		return def, true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// relayLoop polls → runs → answers until ctx ends. The site says how long to wait between polls
// (about a minute when idle, ~2 s while someone is using the machine screens). Errors back off.
// relayOrigin must already be checked with siteOrigin.
func relayLoop(ctx context.Context, relayOrigin, token string) {
	host, _ := os.Hostname()
	hello := map[string]any{"ip": lanIPGuess(), "host": host, "version": agentVersion}
	ipShown := hello["ip"].(string)
	if ipShown == "" {
		ipShown = "unknown ip"
	}
	logf("Relay mode: polling %s as %s (%s)", relayOrigin, host, ipShown)
	backoff := 0
	for ctx.Err() == nil {
		wait := 5
		reply, err := relayPost(ctx, relayOrigin, token, "poll", hello)
		if err == nil {
			backoff = 0
			secs, ok := number(reply["pollSeconds"], 60)
			if !ok {
				err = fmt.Errorf("bad pollSeconds %v", reply["pollSeconds"])
			} else {
				wait = max(1, min(int(secs), 300))
			}
		}
		if job, _ := reply["job"].(map[string]any); err == nil && len(job) > 0 {
			issued, _ := number(job["issuedAt"], 0)
			age := float64(time.Now().UnixMilli())/1000 - issued/1000
			if age > jobMaxAge.Seconds() || age < -30 {
				logf("Dropping stale job %v (age %.0fs)", job["id"], age)
			} else {
				status, body := runJob(job)
				_, err = relayPost(ctx, relayOrigin, token, "result", map[string]any{"id": job["id"], "httpStatus": status, "body": body})
			}
			wait = 0 // look for the next one straight away
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			backoff = min(max(backoff*2, 10), relayMaxBackoff)
			wait = backoff
			if he, ok := err.(*relayHTTPError); ok {
				if he.code == 401 {
					logf("Relay rejected the agent's token (check AGENT_TOKEN).")
				} else {
					logf("Relay error HTTP %d; retrying in %ds", he.code, wait)
				}
			} else {
				logf("Can't reach the relay (%v); retrying in %ds", err, wait)
			}
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(wait) * time.Second):
			}
		}
	}
}
