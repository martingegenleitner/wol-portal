// Package config loads the portal settings (environment) and the host list (YAML).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Settings holds everything that is configured through environment variables.
type Settings struct {
	Listen    string
	BaseURL   *url.URL
	HostsFile string

	SessionSecret []byte
	SessionTTL    time.Duration

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCScopes       []string
	GroupsClaim      string
	AllowedGroups    []string
	AdminGroups      []string

	WOLBroadcast string

	KnownHostsFile  string
	InsecureHostKey bool
	DefaultSSHUser  string
	SSHTimeout      time.Duration

	ProbeInterval  time.Duration
	PendingTimeout time.Duration
}

// LoadSettings reads the WOLP_* environment variables and validates them.
func LoadSettings() (*Settings, error) {
	return loadSettings(os.Getenv)
}

func loadSettings(env func(string) string) (*Settings, error) {
	var errs []error
	str := func(key, def string) string {
		if v := strings.TrimSpace(env(key)); v != "" {
			return v
		}
		return def
	}
	list := func(key string, def ...string) []string {
		v := strings.TrimSpace(env(key))
		if v == "" {
			return def
		}
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	dur := func(key string, def time.Duration) time.Duration {
		v := strings.TrimSpace(env(key))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: %q is not a positive duration", key, v))
			return def
		}
		return d
	}
	boolean := func(key string) bool {
		v := strings.TrimSpace(env(key))
		if v == "" {
			return false
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %q is not a boolean", key, v))
		}
		return b
	}
	required := func(key string) string {
		v := str(key, "")
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
		}
		return v
	}

	s := &Settings{
		Listen:           str("WOLP_LISTEN", ":8080"),
		HostsFile:        str("WOLP_HOSTS_FILE", "hosts.yaml"),
		SessionSecret:    []byte(env("WOLP_SESSION_SECRET")),
		SessionTTL:       dur("WOLP_SESSION_TTL", 8*time.Hour),
		OIDCIssuer:       required("WOLP_OIDC_ISSUER"),
		OIDCClientID:     required("WOLP_OIDC_CLIENT_ID"),
		OIDCClientSecret: required("WOLP_OIDC_CLIENT_SECRET"),
		OIDCScopes:       list("WOLP_OIDC_SCOPES", "openid", "profile", "email"),
		GroupsClaim:      str("WOLP_GROUPS_CLAIM", "groups"),
		AllowedGroups:    list("WOLP_ALLOWED_GROUPS"),
		AdminGroups:      list("WOLP_ADMIN_GROUPS"),
		WOLBroadcast:     str("WOLP_WOL_BROADCAST", "255.255.255.255:9"),
		KnownHostsFile:   str("WOLP_KNOWN_HOSTS", ""),
		InsecureHostKey:  boolean("WOLP_SSH_INSECURE_HOSTKEY"),
		DefaultSSHUser:   str("WOLP_SSH_DEFAULT_USER", "wol-portal"),
		SSHTimeout:       dur("WOLP_SSH_TIMEOUT", 15*time.Second),
		ProbeInterval:    dur("WOLP_PROBE_INTERVAL", 5*time.Second),
		PendingTimeout:   dur("WOLP_PENDING_TIMEOUT", 10*time.Minute),
	}

	if len(s.SessionSecret) < 32 {
		errs = append(errs, errors.New("WOLP_SESSION_SECRET is required and must be at least 32 bytes"))
	}
	if len(s.AllowedGroups) == 0 && len(s.AdminGroups) == 0 {
		errs = append(errs, errors.New("WOLP_ALLOWED_GROUPS (or WOLP_ADMIN_GROUPS) must name at least one group"))
	}
	if s.KnownHostsFile == "" && !s.InsecureHostKey {
		errs = append(errs, errors.New("WOLP_KNOWN_HOSTS is required (or set WOLP_SSH_INSECURE_HOSTKEY=true for testing only)"))
	}
	if raw := required("WOLP_BASE_URL"); raw != "" {
		u, err := url.Parse(raw)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			errs = append(errs, fmt.Errorf("WOLP_BASE_URL: %q is not an absolute http(s) URL", raw))
		default:
			u.Path = strings.TrimRight(u.Path, "/")
			s.BaseURL = u
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return s, nil
}

// RedirectURL is the OIDC redirect URI that must be registered at the provider.
func (s *Settings) RedirectURL() string {
	return s.BaseURL.String() + "/auth/callback"
}

// SecureCookies reports whether cookies should carry the Secure attribute.
func (s *Settings) SecureCookies() bool {
	return s.BaseURL.Scheme == "https"
}
