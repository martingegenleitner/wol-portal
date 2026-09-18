package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseHosts(t *testing.T) {
	key := writeKey(t)
	yml := `
hosts:
  - name: "Build Server #1"
    ip: 192.168.1.20
    mac: "AA:BB:CC:DD:EE:FF"
    shutdown_command: "sudo poweroff"
    ssh_key: ` + key + `
  - name: NAS
    ip: 192.168.1.30
    mac: aa-bb-cc-dd-ee-00
    shutdown_command: "poweroff"
    ssh_key: ` + key + `
    ssh_user: admin
    ssh_port: 2222
    allowed_groups: [ops]
`
	hs, err := parseHosts(strings.NewReader(yml), "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 2 {
		t.Fatalf("got %d hosts", len(hs))
	}
	if hs[0].ID != "build-server-1" || hs[0].SSHUser != "root" || hs[0].SSHPort != 22 {
		t.Errorf("defaults wrong: %+v", hs[0])
	}
	if hs[0].Addr() != "192.168.1.20:22" || hs[1].Addr() != "192.168.1.30:2222" {
		t.Errorf("addr wrong: %s %s", hs[0].Addr(), hs[1].Addr())
	}
	if hs[1].SSHUser != "admin" || len(hs[1].AllowedGroups) != 1 {
		t.Errorf("explicit values lost: %+v", hs[1])
	}
	if len(hs[0].HardwareAddr) != 6 {
		t.Errorf("MAC not parsed")
	}
}

func TestParseHostsErrors(t *testing.T) {
	key := writeKey(t)
	yml := `
hosts:
  - name: A
    ip: not-an-ip
    mac: nope
    ssh_key: /does/not/exist
  - name: a
    ip: 10.0.0.1
    mac: "aa:bb:cc:dd:ee:ff"
    shutdown_command: x
    ssh_key: ` + key + `
    bogus: 1
`
	_, err := parseHosts(strings.NewReader(yml), "root")
	if err == nil {
		t.Fatal("expected error (unknown field)")
	}
	yml = strings.Replace(yml, "    bogus: 1\n", "", 1)
	_, err = parseHosts(strings.NewReader(yml), "root")
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"not a valid IP", "not a valid 6-byte MAC", "shutdown_command is required", "ssh_key", "collides"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadSettings(t *testing.T) {
	base := map[string]string{
		"WOLP_BASE_URL":           "https://wol.example.com/",
		"WOLP_OIDC_ISSUER":        "https://idp.example.com",
		"WOLP_OIDC_CLIENT_ID":     "id",
		"WOLP_OIDC_CLIENT_SECRET": "secret",
		"WOLP_SESSION_SECRET":     strings.Repeat("s", 32),
		"WOLP_ALLOWED_GROUPS":     "wol-users, wol-admins",
		"WOLP_KNOWN_HOSTS":        "/kh",
	}
	s, err := loadSettings(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if s.RedirectURL() != "https://wol.example.com/auth/callback" || !s.SecureCookies() {
		t.Errorf("redirect/secure wrong: %s", s.RedirectURL())
	}
	if len(s.AllowedGroups) != 2 || s.AllowedGroups[1] != "wol-admins" {
		t.Errorf("groups: %v", s.AllowedGroups)
	}
	if s.GroupsClaim != "groups" || s.WOLBroadcast != "255.255.255.255:9" {
		t.Errorf("defaults wrong: %+v", s)
	}

	for _, drop := range []string{"WOLP_BASE_URL", "WOLP_OIDC_ISSUER", "WOLP_SESSION_SECRET", "WOLP_ALLOWED_GROUPS", "WOLP_KNOWN_HOSTS"} {
		m := map[string]string{}
		for k, v := range base {
			if k != drop {
				m[k] = v
			}
		}
		if _, err := loadSettings(env(m)); err == nil {
			t.Errorf("expected error without %s", drop)
		}
	}
	m := map[string]string{"WOLP_SSH_INSECURE_HOSTKEY": "true"}
	for k, v := range base {
		if k != "WOLP_KNOWN_HOSTS" {
			m[k] = v
		}
	}
	if _, err := loadSettings(env(m)); err != nil {
		t.Errorf("insecure host key opt-in should work: %v", err)
	}
}
