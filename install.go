package main

// Self-install. Double-clicking the app copies its program into the agent's per-user folder
// (dataDir), registers it to start at login (launchd on macOS, Task Scheduler on Windows, a
// systemd user unit on Linux — no admin rights anywhere), starts it and opens the setup page.
// Double-clicking a newer download does the same again: the program is replaced and restarted,
// settings kept. The platform halves are install_darwin.go, install_windows.go, install_other.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func setupURL() string { return "http://127.0.0.1:" + strconv.Itoa(defaultPort) + "/setup" }

func installedBinary() string { return filepath.Join(dataDir(), binaryName()) }

// testInstall: test builds pointed at a scratch folder never touch the real login service.
func testInstall() bool { return testMode && dataDirOverride != "" }

type installOptions struct {
	sites       []string
	relay       string
	token       string
	openBrowser bool
}

func doubleClick() {
	if err := install(installOptions{openBrowser: true}); err != nil {
		showMessage(appName, err.Error(), true)
		os.Exit(1)
	}
}

func installCommand(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var sites multiFlag
	fs.Var(&sites, "site", "admin site to allow (repeatable)")
	relay := fs.String("relay", "", "turn on relay mode for this admin site")
	token := fs.String("token", os.Getenv("ODD_AGENT_TOKEN"), "relay mode: the site's AGENT_TOKEN (or set ODD_AGENT_TOKEN)")
	noBrowser := fs.Bool("no-browser", false, "don't open the setup page")
	fs.Parse(args)
	err := install(installOptions{sites: sites, relay: *relay, token: *token, openBrowser: !*noBrowser})
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("Installed %s %s in %s; it's running on http://127.0.0.1:%d\n", appName, version, dataDir(), defaultPort)
}

func uninstallCommand(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "no message box")
	fs.Parse(args)
	err := uninstall(false)
	if err != nil {
		if !*quiet {
			showMessage(appName, "Couldn't remove everything: "+err.Error(), true)
		}
		fail(err.Error())
	}
	fmt.Println("Removed " + appName + ".")
	if !*quiet && runtime.GOOS == "windows" {
		showMessage(appName, appName+" has been removed from this computer.", false)
	}
}

func install(o installOptions) error {
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return fmt.Errorf("Couldn't create %s: %v", dataDir(), err)
	}
	before, err := loadSettings()
	if err != nil {
		logf("The saved settings couldn't be read (%v); starting again.", err)
	}
	cfg := before.clone()
	if !testInstall() {
		migrateOldInstall(&cfg)
	}
	for _, s := range o.sites {
		origin, err := siteOrigin(s)
		if err != nil {
			return fmt.Errorf("--site: %v", err)
		}
		cfg.addSite(origin)
	}
	if o.relay != "" {
		origin, err := siteOrigin(o.relay)
		if err != nil {
			return fmt.Errorf("--relay: %v", err)
		}
		if len(o.token) < relayMinTokenLength {
			return errors.New("Relay mode needs --token (or ODD_AGENT_TOKEN): the site's AGENT_TOKEN, 32+ characters.")
		}
		cfg.RelaySite, cfg.RelayToken = origin, o.token
	}
	settingsChanged := !reflect.DeepEqual(before, cfg)
	if settingsChanged {
		if err := saveSettings(cfg); err != nil {
			return fmt.Errorf("Couldn't save the settings: %v", err)
		}
	}

	self, err := executable()
	if err != nil {
		return err
	}
	target := installedBinary()
	binaryChanged := false
	if !samePath(self, target) && !sameContent(self, target) {
		if !testInstall() {
			stopService()
		}
		if err := copyExecutable(self, target); err != nil {
			return fmt.Errorf("Couldn't copy the agent to %s: %v", target, err)
		}
		binaryChanged = true
	}
	if testInstall() {
		return nil
	}

	running, foreign := pingAgent()
	if binaryChanged || settingsChanged || running != version {
		if foreign && !binaryChanged {
			stopService()
		}
		if err := registerService(target); err != nil {
			return fmt.Errorf("Couldn't set the agent to start at login: %v", err)
		}
		if err := waitForAgent(20 * time.Second); err != nil {
			return err
		}
	}
	if o.openBrowser {
		openBrowser(setupURL())
	}
	return nil
}

// uninstall removes the login service, the program, its settings and its log. fromService: this
// is the running agent itself (the setup page's Remove button), which stops last.
func uninstall(fromService bool) error {
	if testInstall() {
		return os.RemoveAll(dataDir())
	}
	if !fromService {
		stopService()
	}
	err := unregisterService()
	removeInstalledFiles(fromService)
	if fromService {
		stopService() // on macOS this ends this process too
	}
	return err
}

func executable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("Can't find this program's own file: %v", err)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p, nil
}

func samePath(a, b string) bool {
	if r, err := filepath.EvalSymlinks(b); err == nil {
		b = r
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func fileHash(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	return h.Sum(nil)
}

func sameContent(a, b string) bool {
	ha, hb := fileHash(a), fileHash(b)
	return ha != nil && bytes.Equal(ha, hb)
}

// copyExecutable writes a new file and renames it over the old one, so a program that's still
// running from the old file is never changed under it. Copying (not the original download's
// file) also leaves behind the download's quarantine mark.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Windows may hold the old file for a moment after the old agent stops.
	for i := 0; ; i++ {
		err = os.Rename(tmp, dst)
		if err == nil || i == 20 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// pingAgent asks whatever answers on the agent's port who it is: our version, or foreign = some
// other program (an older copy of the agent, say).
func pingAgent() (runningVersion string, foreign bool) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(defaultPort) + "/ping")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var p struct {
		OK      bool   `json:"ok"`
		Agent   string `json:"agent"`
		Version string `json:"version"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&p) != nil || p.Agent != agentName {
		return "", true
	}
	return p.Version, false
}

func waitForAgent(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	foreign := false
	for time.Now().Before(deadline) {
		var running string
		running, foreign = pingAgent()
		if running == version {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	if foreign {
		return fmt.Errorf("Another program is using port %d, which the machine agent needs — probably an older copy "+
			"of the machine agent. Stop or remove it, then open %s again.", defaultPort, appName)
	}
	return fmt.Errorf("The machine agent didn't start. Its log may say why: %s", logFilePath())
}

// truncateIfLarge keeps a log from growing without end: past 5 MB it starts again.
func truncateIfLarge(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		os.Truncate(path, 0)
	}
}
