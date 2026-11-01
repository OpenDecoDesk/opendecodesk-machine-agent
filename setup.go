package main

// The setup page: http://127.0.0.1:8787/setup, opened when the app is double-clicked. The shop
// types its admin site there, checks the machines are found, turns on relay mode for phones and
// tablets, or removes the agent.
//
// Any web page the operator visits can send requests to 127.0.0.1 too, so the setup API only
// answers the setup page itself:
//   - the Host must be the agent's loopback name (blocks DNS rebinding);
//   - every call carries X-Setup-Token, a random value made at start-up and written only into the
//     page. Other sites can't read the page (no CORS headers here, ever), and a custom header
//     can't be sent cross-site without a CORS preflight, which is never approved;
//   - an Origin, when the browser sends one, must be the agent's own;
//   - the page can't be framed (X-Frame-Options, frame-ancestors), so it can't be clickjacked.

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"html"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

//go:embed setup.html
var setupHTML string

var setupToken = randomHex(32)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// sendSetupJSON is sendJSON without CORS headers: no other site may read these answers.
func sendSetupJSON(w http.ResponseWriter, status int, obj any) {
	w.Header().Set("Cache-Control", "no-store")
	sendJSON(w, &http.Request{Header: http.Header{}}, status, obj)
}

func serveSetup(w http.ResponseWriter, r *http.Request) {
	if !state.hostAllowed(r.Host) {
		sendSetupJSON(w, 403, errBody("Forbidden"))
		return
	}
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.URL.Path == "/setup" {
		if r.Method != "GET" {
			sendSetupJSON(w, 405, errBody("Method not allowed"))
			return
		}
		nonce := randomHex(16)
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+
			"'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		page := strings.NewReplacer("{{TOKEN}}", setupToken, "{{NONCE}}", nonce,
			"{{VERSION}}", html.EscapeString(version)).Replace(setupHTML)
		w.Write([]byte(page))
		return
	}

	// The setup API: POST /setup/api/<action>, JSON, from the setup page only.
	given := r.Header.Get("X-Setup-Token")
	origin := r.Header.Get("Origin")
	if r.Method != "POST" || subtle.ConstantTimeCompare([]byte(given), []byte(setupToken)) != 1 ||
		(origin != "" && !state.selfOrigin(origin)) {
		sendSetupJSON(w, 403, errBody("Forbidden: only the agent's own setup page may change its settings."))
		return
	}
	if !isJSON(r) {
		sendSetupJSON(w, 415, errBody("Content-Type must be application/json"))
		return
	}
	body, ok := readJSONBody(r)
	if !ok {
		sendSetupJSON(w, 400, errBody("Invalid request body"))
		return
	}
	status, out := setupAction(strings.TrimPrefix(r.URL.Path, "/setup/api/"), body)
	sendSetupJSON(w, status, out)
	if out["removed"] == true {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := uninstall(true); err != nil {
				logf("Remove failed: %v", err)
			}
			os.Exit(0)
		}()
	}
}

func setupState() map[string]any {
	cfg := svc.settings()
	return map[string]any{
		"status":    "ok",
		"version":   version,
		"os":        runtime.GOOS,
		"sites":     cfg.Sites,
		"relaySite": cfg.RelaySite,
		"relayOn":   state.anyRelay(),
		"logFile":   logFilePath(),
	}
}

func setupAction(action string, body map[string]any) (int, map[string]any) {
	cfg := svc.settings()
	switch action {
	case "state":
		return 200, setupState()

	case "add-site":
		origin, err := siteOrigin(str(body, "site"))
		if err != nil {
			return 400, errBody(err.Error())
		}
		cfg.addSite(origin)

	case "remove-site":
		site := str(body, "site")
		kept := []string{}
		for _, s := range cfg.Sites {
			if s != site {
				kept = append(kept, s)
			}
		}
		cfg.Sites = kept

	case "relay":
		site, token := str(body, "site"), str(body, "token")
		if site == "" { // turn relay mode off
			cfg.RelaySite, cfg.RelayToken = "", ""
			break
		}
		origin, err := siteOrigin(site)
		if err != nil {
			return 400, errBody(err.Error())
		}
		if token == "" && origin == cfg.RelaySite {
			token = cfg.RelayToken // keep the saved one
		}
		if len(token) < relayMinTokenLength {
			return 400, errBody("The token is the site's AGENT_TOKEN, 32 or more characters.")
		}
		cfg.RelaySite, cfg.RelayToken = origin, token

	case "discover":
		machines, err := discoverMachines(udpTargetPort, udpListenPort, discoveryWindow, udpBroadcastIP)
		if err != nil {
			return 502, errBody(err.Error())
		}
		return 200, map[string]any{"status": "ok", "machines": machines}

	case "remove":
		return 200, map[string]any{"status": "ok", "removed": true}

	default:
		return 404, errBody("Not found")
	}

	if err := saveSettings(cfg); err != nil {
		return 500, errBody("Couldn't save the settings: " + err.Error())
	}
	svc.apply(cfg)
	return 200, setupState()
}
