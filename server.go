package main

// The loopback API the admin page calls: http://127.0.0.1:8787, never reachable from another
// computer. Browsers treat localhost as "secure", so the HTTPS admin page may call it although
// it's plain HTTP; the site's Content-Security-Policy must allow connect-src http://127.0.0.1:8787.
//
//	GET  /ping                          -> 200 {"ok": true, "agent", "version"}
//	GET  /discover                      -> 200 {"status": "ok", "machines": [{"ip","mac","model","firmware"}]}
//	POST /list   body: {machineIp}      -> 200 {"status": "ok", "files": [{"name","size","modified"}]}
//	POST /send   body: {downloadUrl, machineIp, fileName}
//	                                    -> 200 {"status": "ok", "fileName", "bytes", "blocks"}
//	POST /read   body: {machineIp, fileName}   (fileName exactly as /list reports it)
//	                                    -> 200 {"status": "ok", "fileName", "bytes", "blocks", "ext": "DSB", "dataBase64"}
//	POST /delete                        -> 501 (the firmware refuses it; see PROTOCOL.md §6)

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func newHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				logf("unexpected error: %v", v)
				sendJSON(w, r, 500, errBody(fmt.Sprintf("Unexpected error: %v", v)))
			}
		}()
		if state.service && (r.URL.Path == "/" || r.URL.Path == "/setup" || strings.HasPrefix(r.URL.Path, "/setup/")) {
			serveSetup(w, r)
			return
		}
		switch r.Method {
		case "OPTIONS":
			if origin := r.Header.Get("Origin"); state.originAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(204)
		case "GET":
			handleGet(w, r)
		case "POST":
			handlePost(w, r)
		default:
			sendJSON(w, r, 405, errBody("Method not allowed"))
		}
	})
}

func errBody(msg string) map[string]any { return map[string]any{"status": "error", "message": msg} }

func sendJSON(w http.ResponseWriter, r *http.Request, status int, obj any) {
	body, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if origin := r.Header.Get("Origin"); state.originAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.WriteHeader(status)
	w.Write(body)
}

// refuseUntrusted sends a 403 and returns true unless the request is addressed to this agent by
// its loopback name (blocks DNS rebinding) and — when requireOrigin — comes from one of the admin
// sites. Browsers always attach Origin to a cross-origin fetch, so a page on any other site is
// refused here before the agent does anything on its behalf.
func refuseUntrusted(w http.ResponseWriter, r *http.Request, requireOrigin bool) bool {
	if !state.hostAllowed(r.Host) {
		sendJSON(w, r, 403, errBody("Forbidden"))
		return true
	}
	if requireOrigin && !state.anyAllowed() {
		sendJSON(w, r, 403, errBody(noSiteMessage()))
		return true
	}
	if requireOrigin && !state.originAllowed(r.Header.Get("Origin")) {
		sendJSON(w, r, 403, errBody("Forbidden: only the configured admin site may use this agent."))
		return true
	}
	return false
}

// failure turns an error from the machine code into the answer the page shows.
func failure(err error) (int, map[string]any) {
	if _, ok := err.(*opError); ok {
		return 502, errBody(err.Error())
	}
	return 500, errBody("Unexpected error: " + err.Error())
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	// /ping only says "the agent is running", so it needs no Origin (handy for checking the agent
	// by hand) — but still the Host check, like everything else.
	isPing := r.URL.Path == "/ping" && r.URL.RawQuery == ""
	if refuseUntrusted(w, r, !isPing) {
		return
	}
	switch {
	case isPing:
		sendJSON(w, r, 200, map[string]any{"ok": true, "agent": agentName, "version": version})
	case r.URL.Path == "/discover":
		// targetPort/listenPort/windowSeconds/broadcastIp are query-string overrides honored ONLY in
		// test mode — real discovery never needs them; they exist so tests can point this at a
		// throwaway stub on high ports.
		target, listen, window, bcast := udpTargetPort, udpListenPort, discoveryWindow, udpBroadcastIP
		if testMode {
			q := r.URL.Query()
			if v, err := strconv.Atoi(q.Get("targetPort")); err == nil {
				target = v
			}
			if v, err := strconv.Atoi(q.Get("listenPort")); err == nil {
				listen = v
			}
			if v, err := strconv.ParseFloat(q.Get("windowSeconds"), 64); err == nil {
				window = time.Duration(v * float64(time.Second))
			}
			if v := q.Get("broadcastIp"); v != "" {
				bcast = v
			}
		}
		machines, err := discoverMachines(target, listen, window, bcast)
		if err != nil {
			sendJSON(w, r, 502, errBody(err.Error()))
			return
		}
		sendJSON(w, r, 200, map[string]any{"status": "ok", "machines": machines})
	default:
		sendJSON(w, r, 404, errBody("Not found"))
	}
}

// str is Python's str(body.get(key, "")).strip() for a decoded JSON value.
func str(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func readJSONBody(r *http.Request) (map[string]any, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	body := map[string]any{}
	if len(raw) == 0 {
		return body, true
	}
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return nil, false
	}
	return body, true
}

func isJSON(r *http.Request) bool {
	ct := strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]
	return strings.ToLower(strings.TrimSpace(ct)) == "application/json"
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	if refuseUntrusted(w, r, true) {
		return
	}
	switch r.URL.Path {
	case "/send", "/list", "/read", "/delete":
	default:
		sendJSON(w, r, 404, errBody("Not found"))
		return
	}
	// JSON only: a cross-site page can POST text/plain without a CORS preflight, but not
	// application/json — so this is a second, independent barrier behind the Origin check.
	if !isJSON(r) {
		sendJSON(w, r, 415, errBody("Content-Type must be application/json"))
		return
	}
	body, ok := readJSONBody(r)
	if !ok {
		sendJSON(w, r, 400, errBody("Invalid request body"))
		return
	}
	machineIP := str(body, "machineIp")
	if machineIP == "" {
		sendJSON(w, r, 400, errBody("Missing machineIp"))
		return
	}
	if problem := validateMachineIP(machineIP); problem != "" {
		sendJSON(w, r, 400, errBody(problem))
		return
	}
	// machinePort is a test-only override (stub machines on high ports); the real machines always
	// listen on 6000.
	port := tcpListPort
	if testMode {
		if v, err := strconv.Atoi(str(body, "machinePort")); err == nil && v != 0 {
			port = v
		}
	}
	status, out := runOp(r.URL.Path[1:], machineIP, port, body, 0)
	sendJSON(w, r, status, out)
}

// runOp runs list/send/read/delete for the loopback API and relay jobs alike, so the browser code
// treats both paths the same. maxReadBytes > 0 refuses a bigger read (relay answers stay small).
func runOp(op, machineIP string, port int, body map[string]any, maxReadBytes int) (int, map[string]any) {
	switch op {
	case "list":
		files, err := listMachineDir(machineIP, port)
		if err != nil {
			return failure(err)
		}
		return 200, map[string]any{"status": "ok", "files": files}

	case "send":
		downloadURL, fileName := str(body, "downloadUrl"), str(body, "fileName")
		if downloadURL == "" || fileName == "" {
			return 400, errBody("Missing downloadUrl or fileName")
		}
		if problem := validateDownloadURL(downloadURL); problem != "" {
			return 400, errBody(problem)
		}
		data, err := fetchDesignFile(downloadURL)
		var res *sendResult
		if err == nil {
			res, err = sendDesignToMachine(machineIP, fileName, data, port)
		}
		if err != nil {
			logf("SEND error: %v", err)
			return failure(err)
		}
		return 200, map[string]any{"status": "ok", "message": "Sent " + fileName + " to the machine.",
			"fileName": res.FileName, "bytes": res.Bytes, "blocks": res.Blocks}

	case "read":
		fileName := str(body, "fileName")
		if fileName == "" {
			return 400, errBody("Missing fileName")
		}
		res, err := readFileFromMachine(machineIP, fileName, port)
		if err != nil {
			logf("READ error: %v", err)
			return failure(err)
		}
		if maxReadBytes > 0 && len(res.Data) > maxReadBytes {
			return 413, errBody(fileName + " is too big to copy from a phone or tablet " +
				"— use the computer the machine agent runs on.")
		}
		return 200, map[string]any{"status": "ok", "fileName": res.FileName, "blocks": res.Blocks, "ext": res.Ext,
			"bytes": len(res.Data), "dataBase64": base64.StdEncoding.EncodeToString(res.Data)}

	case "delete":
		// Probed: opcode cf24 is the file-management command the vendor app doesn't expose, but
		// this firmware stubs it — it returns error cf e0 for every argument, so it can't delete.
		// Refuse cleanly. If a firmware update ever enables cf24, send `01 00 CF 24 00 <stored
		// name>` here. See PROTOCOL.md §6.
		return 501, errBody(deleteUnsupportedMessage)
	}
	return 400, errBody("Unknown job type.")
}
