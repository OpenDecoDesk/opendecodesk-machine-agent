package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const appName = "OpenDecoDesk Machine Agent"

// settings are what the setup page saves: settings.json in the agent's folder, readable only by
// this user (it can hold the relay token).
type settings struct {
	Sites      []string `json:"sites"`
	RelaySite  string   `json:"relaySite,omitempty"`
	RelayToken string   `json:"relayToken,omitempty"`
}

func (s settings) clone() settings {
	s.Sites = append([]string{}, s.Sites...)
	return s
}

func (s *settings) addSite(origin string) bool {
	for _, have := range s.Sites {
		if have == origin {
			return false
		}
	}
	s.Sites = append(s.Sites, origin)
	return true
}

// dataDirOverride is set only by test builds (testhooks_on.go), so tests never touch real settings.
var dataDirOverride string

// dataDir is where the agent installs itself and keeps its settings (per user; no admin needed).
func dataDir() string {
	if dataDirOverride != "" {
		return dataDirOverride
	}
	return platformDataDir()
}

func settingsPath() string { return filepath.Join(dataDir(), "settings.json") }

func loadSettings() (settings, error) {
	var s settings
	raw, err := os.ReadFile(settingsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return settings{Sites: []string{}}, nil
	}
	if err == nil {
		err = json.Unmarshal(raw, &s)
	}
	if s.Sites == nil {
		s.Sites = []string{}
	}
	return s, err
}

// saveSettings writes the file whole (a temp file renamed over it), mode 0600.
func saveSettings(s settings) error {
	if err := os.MkdirAll(dataDir(), 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(s.clone(), "", "  ")
	tmp := settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	os.Chmod(tmp, 0o600)
	return os.Rename(tmp, settingsPath())
}
