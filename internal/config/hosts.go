package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Host is one entry of hosts.yaml.
type Host struct {
	ID              string           `yaml:"-"`
	Name            string           `yaml:"name"`
	IP              string           `yaml:"ip"`
	MAC             string           `yaml:"mac"`
	ShutdownCommand string           `yaml:"shutdown_command"`
	SSHKey          string           `yaml:"ssh_key"`
	SSHUser         string           `yaml:"ssh_user"`
	SSHPort         int              `yaml:"ssh_port"`
	AllowedGroups   []string         `yaml:"allowed_groups"`
	HardwareAddr    net.HardwareAddr `yaml:"-"`
}

// Addr is the host:port used for the reachability probe and the SSH connection.
func (h Host) Addr() string {
	return net.JoinHostPort(h.IP, fmt.Sprint(h.SSHPort))
}

type hostsFile struct {
	Hosts []Host `yaml:"hosts"`
}

// LoadHosts reads and validates the host list. Every problem is reported at once.
func LoadHosts(path, defaultUser string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hosts, err := parseHosts(f, defaultUser)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return hosts, nil
}

func parseHosts(r io.Reader, defaultUser string) ([]Host, error) {
	var file hostsFile
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	if len(file.Hosts) == 0 {
		return nil, errors.New("no hosts configured")
	}

	var errs []error
	seen := map[string]string{}
	for i := range file.Hosts {
		h := &file.Hosts[i]
		label := fmt.Sprintf("hosts[%d] (%q)", i, h.Name)
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", label, fmt.Sprintf(format, args...)))
		}

		h.Name = strings.TrimSpace(h.Name)
		if h.Name == "" {
			fail("name is required")
		}
		h.ID = slug(h.Name)
		if h.ID == "" {
			fail("name must contain at least one letter or digit")
		} else if other, dup := seen[h.ID]; dup {
			fail("name collides with %q", other)
		} else {
			seen[h.ID] = h.Name
		}

		if ip := net.ParseIP(h.IP); ip == nil {
			fail("ip %q is not a valid IP address", h.IP)
		}
		if mac, err := net.ParseMAC(h.MAC); err != nil || len(mac) != 6 {
			fail("mac %q is not a valid 6-byte MAC address", h.MAC)
		} else {
			h.HardwareAddr = mac
		}
		if strings.TrimSpace(h.ShutdownCommand) == "" {
			fail("shutdown_command is required")
		}
		if h.SSHKey == "" {
			fail("ssh_key is required")
		} else if f, err := os.Open(h.SSHKey); err != nil {
			fail("ssh_key: %v", err)
		} else {
			f.Close()
		}
		if h.SSHUser == "" {
			h.SSHUser = defaultUser
		}
		if h.SSHPort == 0 {
			h.SSHPort = 22
		}
		if h.SSHPort < 1 || h.SSHPort > 65535 {
			fail("ssh_port %d is out of range", h.SSHPort)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return file.Hosts, nil
}

// slug turns a display name into a URL-safe identifier.
func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	return b.String()
}
