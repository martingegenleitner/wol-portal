package web

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/martingegenleitner/wol-portal/internal/auth"
	"github.com/martingegenleitner/wol-portal/internal/config"
	"github.com/martingegenleitner/wol-portal/internal/hosts"
)

type noopWaker struct{ n int }

func (w *noopWaker) Wake(net.HardwareAddr) error { w.n++; return nil }

type noopShut struct{}

func (noopShut) Shutdown(context.Context, config.Host) error { return nil }

type fixture struct {
	srv   http.Handler
	sess  *auth.Sessions
	waker *noopWaker
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sess, err := auth.NewSessions([]byte(strings.Repeat("k", 32)), false, 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	w := &noopWaker{}
	m := hosts.NewManager([]config.Host{
		{ID: "a", Name: "A", IP: "10.0.0.1", SSHPort: 22, HardwareAddr: mac},
		{ID: "b", Name: "B", IP: "10.0.0.2", SSHPort: 22, HardwareAddr: mac, AllowedGroups: []string{"ops"}},
	}, hosts.Options{
		Waker: w, Shutdowner: noopShut{},
		Probe:  func(context.Context, config.Host) bool { return false },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	s := &Server{Hosts: m, Sessions: sess, Policy: auth.Policy{Access: []string{"users"}, Admin: []string{"admins"}}}
	return &fixture{srv: s.Handler(), sess: sess, waker: w}
}

// login returns a request modifier that carries a session for the given groups.
func (f *fixture) login(t *testing.T, groups ...string) (cookie *http.Cookie, csrf string) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := f.sess.Issue(rec, auth.User{Subject: "u", Name: "U", Groups: groups}); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	u, _ := f.sess.Get(req)
	return c, u.CSRF
}

func (f *fixture) do(method, path string, c *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

func TestUnauthenticated(t *testing.T) {
	f := newFixture(t)
	if r := f.do("GET", "/", nil, ""); r.Code != http.StatusFound || r.Header().Get("Location") != "/login" {
		t.Errorf("index: %d %s", r.Code, r.Header().Get("Location"))
	}
	if r := f.do("GET", "/api/hosts", nil, ""); r.Code != http.StatusUnauthorized {
		t.Errorf("api: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/a/start", nil, ""); r.Code != http.StatusUnauthorized {
		t.Errorf("start: %d", r.Code)
	}
	if r := f.do("GET", "/healthz", nil, ""); r.Code != http.StatusOK {
		t.Errorf("healthz: %d", r.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	f := newFixture(t)
	r := f.do("GET", "/healthz", nil, "")
	if !strings.Contains(r.Header().Get("Content-Security-Policy"), "default-src 'none'") || r.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", r.Header())
	}
}

func TestOutsiderCannotUseSession(t *testing.T) {
	f := newFixture(t)
	c, _ := f.login(t, "nobody")
	if r := f.do("GET", "/api/hosts", c, ""); r.Code != http.StatusUnauthorized {
		t.Errorf("code %d", r.Code)
	}
}

func TestCSRFRequired(t *testing.T) {
	f := newFixture(t)
	c, csrf := f.login(t, "users", "admins")
	if r := f.do("POST", "/api/hosts/a/start", c, ""); r.Code != http.StatusForbidden {
		t.Errorf("missing token: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/a/start", c, "wrong"); r.Code != http.StatusForbidden {
		t.Errorf("wrong token: %d", r.Code)
	}
	if f.waker.n != 0 {
		t.Error("WoL sent without valid CSRF token")
	}
	if r := f.do("POST", "/api/hosts/a/start", c, csrf); r.Code != http.StatusAccepted {
		t.Errorf("valid token: %d %s", r.Code, r.Body)
	}
	if f.waker.n != 1 {
		t.Errorf("wol count %d", f.waker.n)
	}
	if r := f.do("POST", "/logout", c, ""); r.Code != http.StatusForbidden {
		t.Errorf("logout without token: %d", r.Code)
	}
}

func TestAuthorization(t *testing.T) {
	f := newFixture(t)
	viewer, vcsrf := f.login(t, "users")
	if r := f.do("POST", "/api/hosts/a/start", viewer, vcsrf); r.Code != http.StatusForbidden {
		t.Errorf("viewer start: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/nope/start", viewer, vcsrf); r.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", r.Code)
	}

	admin, acsrf := f.login(t, "users", "admins")
	if r := f.do("POST", "/api/hosts/a/start", admin, acsrf); r.Code != http.StatusAccepted {
		t.Errorf("admin start: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/a/start", admin, acsrf); r.Code != http.StatusConflict {
		t.Errorf("repeat start: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/a/stop", admin, acsrf); r.Code != http.StatusConflict {
		t.Errorf("stop while pending: %d", r.Code)
	}

	ops, ocsrf := f.login(t, "users", "ops")
	if r := f.do("POST", "/api/hosts/a/stop", ops, ocsrf); r.Code != http.StatusForbidden {
		t.Errorf("ops on host without group: %d", r.Code)
	}
	if r := f.do("POST", "/api/hosts/b/start", ops, ocsrf); r.Code != http.StatusAccepted {
		t.Errorf("ops on own host: %d", r.Code)
	}
}

func TestListShowsCanControl(t *testing.T) {
	f := newFixture(t)
	c, _ := f.login(t, "users")
	r := f.do("GET", "/api/hosts", c, "")
	if r.Code != http.StatusOK {
		t.Fatalf("code %d", r.Code)
	}
	body := r.Body.String()
	if !strings.Contains(body, `"can_control":false`) || strings.Contains(body, `"can_control":true`) || !strings.Contains(body, `"csrf"`) {
		t.Errorf("body: %s", body)
	}
	if strings.Contains(body, "aa:bb") {
		t.Error("MAC must not be exposed")
	}
}
