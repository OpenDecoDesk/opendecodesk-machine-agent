//go:build !darwin && !windows

package main

// Linux and the rest: a systemd user service when systemd is there. Mostly for an always-on
// computer (a Raspberry Pi, say) running relay mode for phones and tablets.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const unitName = "opendecodesk-machine-agent.service"

func platformDataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, agentName)
}

func binaryName() string { return agentName }

func logFilePath() string { return "journalctl --user -u " + unitName }

func unitPath() string {
	base, _ := os.UserConfigDir()
	return filepath.Join(base, "systemd", "user", unitName)
}

func prepareConsole(bool) {}

func openServiceLog() {} // systemd keeps the output in its journal

func registerService(target string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("there's no systemd here: start %q run at login some other way", target)
	}
	unit := "[Unit]\nDescription=OpenDecoDesk machine agent\nAfter=network-online.target\n\n" +
		"[Service]\nExecStart=\"" + target + "\" run\nRestart=always\nRestartSec=5\n\n" +
		"[Install]\nWantedBy=default.target\n"
	os.MkdirAll(filepath.Dir(unitPath()), 0o755)
	if err := os.WriteFile(unitPath(), []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", unitName}, {"restart", unitName}} {
		if out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl --user %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func stopService() { exec.Command("systemctl", "--user", "stop", unitName).Run() }

func unregisterService() error {
	exec.Command("systemctl", "--user", "disable", unitName).Run()
	if err := os.Remove(unitPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

func removeInstalledFiles(bool) { os.RemoveAll(dataDir()) }

func migrateOldInstall(*settings) {}

func openBrowser(url string) { exec.Command("xdg-open", url).Start() }

func showMessage(title, msg string, isError bool) { fmt.Fprintln(os.Stderr, title+": "+msg) }
