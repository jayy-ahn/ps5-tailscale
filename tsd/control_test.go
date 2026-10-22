package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanControlURL(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"   ", "", false},
		{"https://hs.example.com", "https://hs.example.com", false},
		{"  https://hs.example.com/  ", "https://hs.example.com", false},
		{"http://192.168.1.5:8080", "http://192.168.1.5:8080", false},
		{"https://hs.example.com/headscale/", "https://hs.example.com/headscale", false},
		{"https://hs.example.com:8443", "https://hs.example.com:8443", false},
		{"https://[fd00::5]:8080", "https://[fd00::5]:8080", false},
		// Tailscale's own server, spelled out, is the default.
		{"https://controlplane.tailscale.com", "", false},
		{"https://login.tailscale.com", "", false},
		{"https://login.tailscale.com:443/", "", false},
		{"HTTPS://LOGIN.Tailscale.com", "", false},
		// What a user has to get right.
		{"hs.example.com", "", true}, // no scheme: Tailscale would guess
		{"ftp://hs.example.com", "", true},
		{"https://", "", true},
		{"https://user:pw@hs.example.com", "", true},
		{"https://hs.example.com/?next=1", "", true},
		{"https://hs.example.com/#frag", "", true},
		{"not a url", "", true},
	} {
		got, err := cleanControlURL(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("cleanControlURL(%q): err = %v, wantErr = %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("cleanControlURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if err != nil && !strings.Contains(err.Error(), "coordination server") {
			t.Errorf("cleanControlURL(%q): the error should name the setting: %v", tt.in, err)
		}
	}
}

func TestCoordinationServerSwitch(t *testing.T) {
	d := newTestDaemon(t)
	restarted := make(chan string, 4)
	d.restartTailnet = func(reason string) { restarted <- reason }
	h := d.webHandler()
	const console = "127.0.0.1:5000"

	// The settings form starts out on the default server.
	var s settings
	w := request(t, h, "GET", "/api/config", console, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.ControlURL != "" {
		t.Fatalf("default coordination server: %q", s.ControlURL)
	}

	// A bad address is refused and restarts nothing.
	s.ControlURL = "hs.example.com"
	if w := request(t, h, "POST", "/api/config", console, s, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("address without a scheme: %d %s", w.Code, w.Body)
	}
	select {
	case reason := <-restarted:
		t.Fatalf("a refused change restarted Tailscale: %s", reason)
	default:
	}

	// A server of your own is saved as given (minus the trailing slash)
	// and Tailscale is started again with it.
	s.ControlURL = "https://hs.example.com:8080/"
	w = request(t, h, "POST", "/api/config", console, s, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("saving a coordination server: %d %s", w.Code, w.Body)
	}
	var reply struct {
		Restart    []string
		Restarting string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Restarting == "" {
		t.Error("the reply should say Tailscale is starting again")
	}
	for _, item := range reply.Restart {
		if item == "coordination server" {
			t.Error("the coordination server should not need a manual restart")
		}
	}
	select {
	case reason := <-restarted:
		if !strings.Contains(reason, "https://hs.example.com:8080") {
			t.Errorf("restart reason: %s", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Tailscale was not started again after the switch")
	}
	if d.cfg.ControlURL != "https://hs.example.com:8080" {
		t.Errorf("saved as %q", d.cfg.ControlURL)
	}
	saved, _ := loadConfig(d.cfgPath)
	if saved.ControlURL != "https://hs.example.com:8080" {
		t.Errorf("on disk: %q", saved.ControlURL)
	}
	if b, _ := os.ReadFile(d.cfgPath); !strings.Contains(string(b), "controlURL") {
		t.Errorf("the config file should name the setting:\n%s", b)
	}

	// Naming Tailscale's own server means the default; it is stored empty,
	// and the switch back also restarts Tailscale.
	s.ControlURL = "https://controlplane.tailscale.com"
	if w := request(t, h, "POST", "/api/config", console, s, nil); w.Code != http.StatusOK {
		t.Fatalf("switching back: %d %s", w.Code, w.Body)
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Fatal("switching back did not restart Tailscale")
	}
	if d.cfg.ControlURL != "" {
		t.Errorf("Tailscale's own server should be stored as the empty default, got %q", d.cfg.ControlURL)
	}

	// Saving the same server again changes nothing and restarts nothing.
	done := make(chan struct{})
	go func() {
		select {
		case reason := <-restarted:
			t.Errorf("nothing changed, yet Tailscale restarted: %s", reason)
		case <-time.After(300 * time.Millisecond):
		}
		close(done)
	}()
	if w := request(t, h, "POST", "/api/config", console, s, nil); w.Code != http.StatusOK {
		t.Fatalf("saving again: %d %s", w.Code, w.Body)
	}
	<-done
}

// A config written by hand with a coordination server must reach the
// status page and the running Tailscale alike.
func TestControlURLFromConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"hostname":"ps5","webAddr":":8090","controlURL":"https://hs.example.com:8080"}`), 0o600)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlURL != "https://hs.example.com:8080" {
		t.Fatalf("config file controlURL lost: %+v", cfg)
	}
	if s := settingsFromConfig(cfg); s.ControlURL != cfg.ControlURL {
		t.Errorf("the page does not show the file's server: %q", s.ControlURL)
	}
}
