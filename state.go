package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultPort = 8787
	agentName   = "opendecodesk-machine-agent"
	// agentVersion is the relay protocol version the site sees in the poll "hello" (3: read jobs).
	// The app's own build version is `version` (main.go).
	agentVersion = "3"

	// Design files come only from the admin site's signed-link endpoint, <origin>/api/design.
	allowedDownloadPath = "/api/design"
)

// agentState is who may use the agent and where it listens. Any other web page the operator
// happens to visit can also reach 127.0.0.1 (a text/plain "no-cors" POST needs no preflight), so
// the origin list is an ACCESS check, not just a CORS-header choice: a request whose Origin isn't
// listed is refused before anything is fetched, listed or sent. The same origins are the only
// places a design file is downloaded from. Empty = nobody (only /ping answers).
//
// The setup page changes it while the agent runs, hence the lock.
type agentState struct {
	mu      sync.RWMutex
	sites   []string // admin-site origins, from --site or the setup page
	relay   string   // the relay site's origin when relay mode is on; it may hand out download links too
	port    int
	service bool // running as the installed service: the setup page is on
}

var state = &agentState{port: defaultPort}

func (s *agentState) setSites(origins []string) {
	s.mu.Lock()
	s.sites = append([]string(nil), origins...)
	s.mu.Unlock()
}

func (s *agentState) setRelay(origin string) {
	s.mu.Lock()
	s.relay = origin
	s.mu.Unlock()
}

func (s *agentState) originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if origin == s.relay {
		return true
	}
	for _, o := range s.sites {
		if o == origin {
			return true
		}
	}
	return false
}

func (s *agentState) anyAllowed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sites) > 0 || s.relay != ""
}

func (s *agentState) anyRelay() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.relay != ""
}

func (s *agentState) siteList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.sites...)
}

// hostAllowed checks the Host header. Answering only to our loopback names blocks DNS rebinding
// (an attacker's domain re-resolved to 127.0.0.1 arrives with its own name in Host, and as a
// same-origin request).
func (s *agentState) hostAllowed(host string) bool {
	p := strconv.Itoa(s.port)
	return host == "127.0.0.1:"+p || host == "localhost:"+p
}

// selfOrigins are the setup page's own origins: the only pages allowed to use the setup API.
func (s *agentState) selfOrigin(origin string) bool {
	p := strconv.Itoa(s.port)
	return origin == "http://127.0.0.1:"+p || origin == "http://localhost:"+p
}

func noSiteMessage() string {
	if state.service {
		return "This agent hasn't been told which admin site may use it — open OpenDecoDesk Machine Agent " +
			"again (or http://127.0.0.1:" + strconv.Itoa(state.port) + "/setup on this computer) and add your " +
			"admin site. (From the command line: --site https://admin.yourshop.example.)"
	}
	return "This agent hasn't been told which admin site may use it — start it with " +
		"--site https://admin.yourshop.example (or set ODD_AGENT_SITES)."
}

// siteOrigin is the origin of an admin-site address ("https://admin.x.example/" →
// "https://admin.x.example"). https only (an http loopback site is allowed in test mode); no
// path, user name or password. The error is a message for the operator.
func siteOrigin(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Not a site address: %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
			return "", fmt.Errorf("Not a site address: %q", raw)
		}
	}
	loopbackTest := testMode && u.Scheme == "http" && host == "127.0.0.1"
	if (u.Scheme != "https" && !loopbackTest) || host == "" {
		return "", fmt.Errorf("The admin site must be an https:// address: %q", raw)
	}
	if u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		strings.HasSuffix(s, "?") || strings.HasSuffix(s, "#") {
		return "", fmt.Errorf("Give just the site's address, e.g. https://admin.yourshop.example: %q", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	def := "443"
	if u.Scheme == "http" {
		def = "80"
	}
	if port != "" && port != def && port != "0" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}

// validateDownloadURL returns "" if downloadURL is a link this agent may fetch, else an
// operator-facing reason. Only the admin site's own https signed-link endpoint is allowed (plus a
// loopback http stub in test mode) — never file://, ftp://, or an arbitrary host.
func validateDownloadURL(downloadURL string) string {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return "Invalid download link."
	}
	if testMode && u.Scheme == "http" && u.Hostname() == "127.0.0.1" {
		return ""
	}
	const notTheSite = "Download link must come from the admin site."
	if u.User != nil {
		return notTheSite
	}
	origin, err := siteOrigin(u.Scheme + "://" + u.Host)
	if err != nil || u.Scheme != "https" || !state.originAllowed(origin) {
		return notTheSite
	}
	if u.Path != allowedDownloadPath {
		return notTheSite
	}
	return ""
}

// validateMachineIP returns "" if machineIP is a private-network IPv4 address (where embroidery
// machines live), else an operator-facing reason. Keeps the agent from being pointed at a host on
// the internet, or (outside test mode) at this computer itself.
func validateMachineIP(machineIP string) string {
	ip, err := netip.ParseAddr(machineIP)
	if err != nil || !ip.Is4() || ip.IsMulticast() || ip.IsUnspecified() {
		return "Machine IP must be an IPv4 address on the shop network."
	}
	if ip.IsLoopback() {
		if testMode {
			return ""
		}
		return "Machine IP must be an address on the shop network."
	}
	// Private ranges, plus link-local (169.254.x.x): a machine with no DHCP server gives itself one.
	if !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
		return "Machine IP must be an address on the shop network (a private LAN address)."
	}
	return ""
}
