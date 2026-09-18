package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSessions(t *testing.T) *Sessions {
	t.Helper()
	s, err := NewSessions([]byte(strings.Repeat("k", 32)), true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cookieRequest(w *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestSessionRoundTrip(t *testing.T) {
	s := newSessions(t)
	w := httptest.NewRecorder()
	if err := s.Issue(w, User{Subject: "u1", Name: "Ann", Groups: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: %+v", c)
	}
	u, ok := s.Get(cookieRequest(w))
	if !ok || u.Subject != "u1" || len(u.Groups) != 2 || u.CSRF == "" {
		t.Fatalf("got %+v ok=%v", u, ok)
	}
}

func TestSessionRejectsTamperingExpiryAndOtherSecret(t *testing.T) {
	s := newSessions(t)
	w := httptest.NewRecorder()
	s.Issue(w, User{Subject: "u1"})

	r := cookieRequest(w)
	c, _ := r.Cookie(sessionCookie)
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.Value[:len(c.Value)-2] + "AA"})
	if _, ok := s.Get(bad); ok {
		t.Error("tampered cookie accepted")
	}

	other, _ := NewSessions([]byte(strings.Repeat("z", 32)), true, time.Hour)
	if _, ok := other.Get(r); ok {
		t.Error("cookie accepted under a different secret")
	}

	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok := s.Get(r); ok {
		t.Error("expired session accepted")
	}

	// A login-state cookie must not be usable as a session.
	w2 := httptest.NewRecorder()
	s2 := newSessions(t)
	s2.setLoginState(w2, loginState{State: "x"})
	st := w2.Result().Cookies()[0]
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.AddCookie(&http.Cookie{Name: sessionCookie, Value: st.Value})
	if _, ok := s2.Get(r3); ok {
		t.Error("state cookie accepted as session")
	}
}

func TestLoginStateIsSingleUse(t *testing.T) {
	s := newSessions(t)
	w := httptest.NewRecorder()
	s.setLoginState(w, loginState{State: "st", Nonce: "n", Verifier: "v"})
	r := cookieRequest(w)
	r.Header = http.Header{"Cookie": []string{w.Result().Cookies()[0].Name + "=" + w.Result().Cookies()[0].Value}}
	out := httptest.NewRecorder()
	ls, ok := s.takeLoginState(out, r)
	if !ok || ls.State != "st" || ls.Nonce != "n" {
		t.Fatalf("got %+v", ls)
	}
	if c := out.Result().Cookies(); len(c) == 0 || c[0].MaxAge >= 0 {
		t.Error("state cookie not cleared")
	}
}

func TestPolicy(t *testing.T) {
	user := &User{Groups: []string{"users"}}
	admin := &User{Groups: []string{"admins"}}
	ops := &User{Groups: []string{"users", "ops"}}
	outsider := &User{Groups: []string{"other"}}

	open := Policy{Access: []string{"users"}}
	if !open.CanAccess(user) || open.CanAccess(outsider) {
		t.Error("access wrong")
	}
	if !open.CanControl(user, nil) || open.CanControl(outsider, nil) {
		t.Error("open control wrong")
	}

	p := Policy{Access: []string{"users"}, Admin: []string{"admins"}}
	if !p.CanAccess(admin) {
		t.Error("admin should have access")
	}
	if p.CanControl(user, nil) || !p.CanControl(admin, nil) {
		t.Error("admin-only control wrong")
	}
	if !p.CanControl(ops, []string{"ops"}) || p.CanControl(user, []string{"ops"}) || !p.CanControl(admin, []string{"ops"}) {
		t.Error("per-host groups wrong")
	}
	if open.CanControl(user, []string{"ops"}) {
		t.Error("per-host groups must restrict")
	}
}

func TestStringList(t *testing.T) {
	if got := stringList([]any{"a", 1, "b"}); len(got) != 2 || got[1] != "b" {
		t.Errorf("%v", got)
	}
	if got := stringList("solo"); len(got) != 1 {
		t.Errorf("%v", got)
	}
	if stringList(nil) != nil || stringList(42) != nil {
		t.Error("expected nil")
	}
}
