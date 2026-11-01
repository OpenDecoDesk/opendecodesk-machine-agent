// OpenDecoDesk machine agent — lets a web admin (OpenDecoDesk's Run Order and Machine Files
// screens, or any site that speaks the same small API) find SmartStitch embroidery machines on the
// local network, list their files, send a design to one and copy a file back off it.
//
// WHY THIS EXISTS: a browser has no API to open a raw UDP/TCP socket, and a website's servers
// can't reach a machine's private LAN address either. This is a small program that runs on a
// computer on the SAME local network as the embroidery machines and speaks the machines' own
// protocol directly (protocol.go, PROTOCOL.md).
//
// How it runs:
//   - Double-clicked (no arguments): installs itself to start at login, then opens its setup page
//     (http://127.0.0.1:8787/setup) where the shop types its admin site. install.go.
//   - `run`: the installed service — the loopback API plus the setup page, and relay mode when
//     it's turned on there. Settings live in settings.json (settings.go).
//   - With options, from a terminal (the same options the original Python agent took):
//     agent --site https://admin.yourshop.example
//     agent --relay https://admin.yourshop.example --token <the site's AGENT_TOKEN>
//   - `install` / `uninstall`: the same as double-clicking / the setup page's Remove button.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// version is the app's build version, stamped by build.sh (-X main.version=...).
var version = "dev"

var (
	logMu  sync.Mutex
	logOut io.Writer = os.Stdout
)

// logf prints a timestamped line so sends/failures are visible in the field. Never fails.
func logf(format string, a ...any) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
	logMu.Lock()
	logOut.Write([]byte(line))
	logMu.Unlock()
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func envPort() int {
	if v := os.Getenv("ODD_AGENT_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			fail("ODD_AGENT_PORT must be a number.")
		}
		return p
	}
	return defaultPort
}

func main() {
	var args []string
	for _, a := range os.Args[1:] {
		if !strings.HasPrefix(a, "-psn_") { // older macOS adds a process serial number to a double-click
			args = append(args, a)
		}
	}
	prepareConsole(len(args) > 0 && args[0] != "run")
	if len(args) == 0 {
		doubleClick()
		return
	}
	switch args[0] {
	case "run":
		runService(args[1:])
	case "install":
		installCommand(args[1:])
	case "uninstall":
		uninstallCommand(args[1:])
	case "version", "--version":
		fmt.Println(version)
	default:
		runForeground(args)
	}
}

// runForeground is the command-line agent: settings from options and environment only.
func runForeground(args []string) {
	fs := flag.NewFlagSet(agentName, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "OpenDecoDesk machine agent %s: lets an admin site use SmartStitch embroidery machines on this network.\n\n", version)
		fmt.Fprintln(fs.Output(), "Double-click it (or run it with no options) to install it and open its setup page. Options:")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "\nAlso: run (the installed service), install, uninstall, version.")
	}
	var sites multiFlag
	fs.Var(&sites, "site", "an admin site allowed to use this agent, e.g. https://admin.yourshop.example\n(repeat for several; or set ODD_AGENT_SITES, comma-separated)")
	relay := fs.String("relay", os.Getenv("ODD_AGENT_RELAY"), "connect out to this admin site so phones/tablets can use the agent (or set ODD_AGENT_RELAY);\nwithout it the agent serves browsers on THIS computer via http://127.0.0.1:PORT")
	token := fs.String("token", os.Getenv("ODD_AGENT_TOKEN"), "relay mode: the site's AGENT_TOKEN, 32+ characters (or set ODD_AGENT_TOKEN)")
	port := fs.Int("port", envPort(), fmt.Sprintf("loopback port (the admin site expects %d)", defaultPort))
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fail("Unexpected argument: " + fs.Arg(0))
	}
	if len(sites) == 0 && !flagGiven(fs, "site") {
		for _, s := range strings.Split(os.Getenv("ODD_AGENT_SITES"), ",") {
			if strings.TrimSpace(s) != "" {
				sites = append(sites, s)
			}
		}
	}
	var origins []string
	for _, s := range sites {
		if strings.TrimSpace(s) == "" {
			continue
		}
		o, err := siteOrigin(s)
		if err != nil {
			fail("--site: " + err.Error())
		}
		origins = append(origins, o)
	}
	state.setSites(origins)
	state.port = *port

	if *relay != "" {
		if len(*token) < relayMinTokenLength {
			fail("Relay mode needs --token (or ODD_AGENT_TOKEN): the site's AGENT_TOKEN, 32+ characters.")
		}
		origin, err := siteOrigin(*relay)
		if err != nil {
			fail("--relay: " + err.Error())
		}
		state.setRelay(origin) // the relay's site may hand out download links
		relayLoop(context.Background(), origin, *token)
		return
	}
	if !state.anyAllowed() {
		logf("WARNING: %s", noSiteMessage())
	}
	ln, err := listenLoopback(state.port)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("Machine agent listening on http://127.0.0.1:%d for %s  (Ctrl+C to stop)\n", state.port, orNobody(origins))
	http.Serve(ln, newHandler())
}

func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

func orNobody(origins []string) string {
	if len(origins) == 0 {
		return "nobody"
	}
	return strings.Join(origins, ", ")
}

func listenLoopback(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("Can't listen on http://127.0.0.1:%d — is another copy of the machine agent already running? (%v)", port, err)
	}
	return ln, nil
}

// runService is the installed agent: the loopback API and setup page, plus relay mode when the
// setup page turned it on. Its settings come from settings.json and change while it runs.
func runService(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	port := fs.Int("port", envPort(), "loopback port")
	fs.Parse(args)
	state.port = *port
	state.service = true
	openServiceLog()

	cfg, err := loadSettings()
	if err != nil {
		logf("Can't read the settings (%v); starting with none.", err)
	}
	svc.apply(cfg)
	ln, err := listenLoopback(state.port)
	if err != nil {
		logf("%v", err)
		os.Exit(1)
	}
	logf("Machine agent %s listening on http://127.0.0.1:%d for %s (setup: http://127.0.0.1:%d/setup)",
		version, state.port, orNobody(state.siteList()), state.port)
	srv := &http.Server{Handler: newHandler(), ReadHeaderTimeout: 10 * time.Second}
	logf("%v", srv.Serve(ln))
	os.Exit(1)
}

// service holds the running relay loop so a settings change can restart it.
type service struct {
	mu          sync.Mutex
	cfg         settings // as saved
	relayOrigin string   // what the running relay loop uses ("" = off)
	relayToken  string
	relayCancel context.CancelFunc
}

var svc = &service{}

func (s *service) settings() settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.clone()
}

// apply puts settings into effect without a restart: the allowed sites at once, and the relay loop
// stopped and started again when its site or token changed.
func (s *service) apply(cfg settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var origins []string
	for _, site := range cfg.Sites {
		if o, err := siteOrigin(site); err == nil {
			origins = append(origins, o)
		} else {
			logf("Ignoring a saved site: %v", err)
		}
	}
	state.setSites(origins)
	relayOrigin := ""
	if cfg.RelaySite != "" {
		if o, err := siteOrigin(cfg.RelaySite); err == nil && len(cfg.RelayToken) >= relayMinTokenLength {
			relayOrigin = o
		} else {
			logf("Relay mode is off: the saved relay site or token isn't valid.")
		}
	}
	token := ""
	if relayOrigin != "" {
		token = cfg.RelayToken
	}
	if relayOrigin != s.relayOrigin || token != s.relayToken {
		if s.relayCancel != nil {
			s.relayCancel()
			s.relayCancel = nil
		}
		if relayOrigin != "" {
			ctx, cancel := context.WithCancel(context.Background())
			s.relayCancel = cancel
			go relayLoop(ctx, relayOrigin, token)
		}
	}
	state.setRelay(relayOrigin)
	s.relayOrigin, s.relayToken = relayOrigin, token
	s.cfg = cfg.clone()
}
