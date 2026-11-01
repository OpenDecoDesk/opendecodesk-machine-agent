package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The same label the original Python agent's install-service.py used, so installing this replaces it.
const launchLabel = "org.opendecodesk.machine-agent"

func home() string { h, _ := os.UserHomeDir(); return h }

// macOS won't let a background service read files in ~/Documents, ~/Desktop or ~/Downloads, so the
// program lives here.
func platformDataDir() string {
	return filepath.Join(home(), "Library", "Application Support", appName)
}

func binaryName() string { return appName }

func logFilePath() string { return filepath.Join(home(), "Library", "Logs", appName+".log") }

func plistPath() string {
	return filepath.Join(home(), "Library", "LaunchAgents", launchLabel+".plist")
}

func domain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func prepareConsole(bool) {}

// launchd sends the service's output to the log file (see the plist); this only keeps it small.
func openServiceLog() { truncateIfLarge(logFilePath()) }

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func registerService(target string) error {
	os.MkdirAll(filepath.Dir(plistPath()), 0o755)
	os.MkdirAll(filepath.Dir(logFilePath()), 0o755)
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlText(target) + `</string>
		<string>run</string>
	</array>
	<key>WorkingDirectory</key>
	<string>` + xmlText(dataDir()) + `</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardOutPath</key>
	<string>` + xmlText(logFilePath()) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlText(logFilePath()) + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(plistPath(), []byte(plist), 0o644); err != nil {
		return err
	}
	exec.Command("launchctl", "bootout", domain()+"/"+launchLabel).Run()
	// Right after a bootout launchd can still be tearing the old one down ("Input/output error").
	var out []byte
	var err error
	for i := 0; i < 20; i++ {
		out, err = exec.Command("launchctl", "bootstrap", domain(), plistPath()).CombinedOutput()
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("launchctl bootstrap: %v %s", err, strings.TrimSpace(string(out)))
}

func stopService() {
	exec.Command("launchctl", "bootout", domain()+"/"+launchLabel).Run()
}

func unregisterService() error {
	if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeInstalledFiles(bool) {
	os.RemoveAll(dataDir())
	os.Remove(logFilePath())
}

// migrateOldInstall takes over a service installed by the original Python agent's
// install-service.py: its sites, and its relay site and token, move into settings, and its
// services are removed (the main one shares our label and is replaced by registerService).
func migrateOldInstall(cfg *settings) {
	plists, _ := filepath.Glob(filepath.Join(home(), "Library", "LaunchAgents", launchLabel+"*.plist"))
	for _, p := range plists {
		raw, err := exec.Command("plutil", "-convert", "json", "-o", "-", p).Output()
		if err != nil {
			continue
		}
		var old struct {
			Label                string            `json:"Label"`
			ProgramArguments     []string          `json:"ProgramArguments"`
			EnvironmentVariables map[string]string `json:"EnvironmentVariables"`
		}
		if json.Unmarshal(raw, &old) != nil || len(old.ProgramArguments) < 2 || old.ProgramArguments[1] == "run" {
			continue // ours already
		}
		args := old.ProgramArguments
		for i := 0; i+1 < len(args); i++ {
			switch args[i] {
			case "--site":
				if o, err := siteOrigin(args[i+1]); err == nil {
					cfg.addSite(o)
				}
			case "--relay":
				token := old.EnvironmentVariables["ODD_AGENT_TOKEN"]
				if o, err := siteOrigin(args[i+1]); err == nil && cfg.RelaySite == "" && len(token) >= relayMinTokenLength {
					cfg.RelaySite, cfg.RelayToken = o, token
				}
			}
		}
		label := old.Label
		if label == "" {
			label = strings.TrimSuffix(filepath.Base(p), ".plist")
		}
		exec.Command("launchctl", "bootout", domain()+"/"+label).Run()
		os.Remove(p)
		logf("Took over the earlier machine agent service %s.", label)
	}
	// The Python agent's copy of itself.
	os.RemoveAll(filepath.Join(home(), "Library", "Application Support", "opendecodesk-machine-agent"))
}

func openBrowser(url string) { exec.Command("open", url).Run() }

func showMessage(title, msg string, isError bool) {
	icon := "note"
	if isError {
		icon = "caution"
	}
	script := []string{
		"-e", "on run argv",
		"-e", `display dialog (item 1 of argv) with title (item 2 of argv) buttons {"OK"} default button 1 with icon ` + icon,
		"-e", "end run",
		msg, title,
	}
	exec.Command("osascript", script...).Run()
}
