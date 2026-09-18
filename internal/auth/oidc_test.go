package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS and a token endpoint that
// enforces PKCE and issues signed ID tokens for whatever the test configured.
type fakeIdP struct {
	srv        *httptest.Server
	key        *rsa.PrivateKey
	groups     any
	nonceOver  string // if set, put this nonce in the ID token instead of the real one
	authNonce  string
	challenge  string
	pkceFailed bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			f.pkceFailed = true
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce := f.authNonce
		if f.nonceOver != "" {
			nonce = f.nonceOver
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		claims := map[string]any{"nonce": nonce, "name": "Ann Example", "email": "ann@example.com"}
		if f.groups != nil {
			claims["groups"] = f.groups
		}
		raw, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer: f.srv.URL, Subject: "user-1", Audience: jwt.Audience{"wol"},
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
		}).Claims(claims).Serialize()
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newAuthn(t *testing.T, f *fakeIdP, policy Policy) (*Authenticator, *Sessions) {
	t.Helper()
	sess := newSessions(t)
	a, err := NewAuthenticator(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "wol", ClientSecret: "s",
		RedirectURL: "https://wol.example.com/auth/callback",
		Scopes:      []string{"openid", "profile"}, GroupsClaim: "groups",
	}, sess, policy)
	if err != nil {
		t.Fatal(err)
	}
	return a, sess
}

// startLogin runs /login and returns the state cookie plus the `state` the IdP would echo back.
func startLogin(t *testing.T, a *Authenticator, f *fakeIdP) (cookies []*http.Cookie, state string) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Login(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), f.srv.URL+"/authorize") || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("bad authorization URL: %s", loc)
	}
	f.authNonce, f.challenge = q.Get("nonce"), q.Get("code_challenge")
	return rec.Result().Cookies(), q.Get("state")
}

func callback(a *Authenticator, cookies []*http.Cookie, state string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/auth/callback?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.Callback(rec, req)
	return rec
}

func TestOIDCLoginSuccess(t *testing.T) {
	f := newFakeIdP(t)
	f.groups = []string{"wol-users", "other"}
	a, sess := newAuthn(t, f, Policy{Access: []string{"wol-users"}})

	cookies, state := startLogin(t, a, f)
	rec := callback(a, cookies, state)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	u, ok := sess.Get(req)
	if !ok || u.Subject != "user-1" || u.Name != "Ann Example" || len(u.Groups) != 2 {
		t.Fatalf("session user: %+v ok=%v", u, ok)
	}
	if f.pkceFailed {
		t.Error("PKCE verifier did not match")
	}
}

func TestOIDCLoginDeniedWithoutGroup(t *testing.T) {
	f := newFakeIdP(t)
	f.groups = []string{"strangers"}
	a, _ := newAuthn(t, f, Policy{Access: []string{"wol-users"}})

	cookies, state := startLogin(t, a, f)
	rec := callback(a, cookies, state)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge >= 0 {
			t.Error("session issued to user without an allowed group")
		}
	}
}

func TestOIDCLoginDeniedWhenClaimMissing(t *testing.T) {
	f := newFakeIdP(t) // no groups claim at all
	a, _ := newAuthn(t, f, Policy{Access: []string{"wol-users"}})
	cookies, state := startLogin(t, a, f)
	if rec := callback(a, cookies, state); rec.Code != http.StatusForbidden {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestOIDCRejectsBadStateAndNonce(t *testing.T) {
	f := newFakeIdP(t)
	f.groups = []string{"wol-users"}
	a, _ := newAuthn(t, f, Policy{Access: []string{"wol-users"}})

	cookies, _ := startLogin(t, a, f)
	if rec := callback(a, cookies, "forged-state"); rec.Code != http.StatusBadRequest {
		t.Errorf("forged state: %d", rec.Code)
	}
	if rec := callback(a, nil, "x"); rec.Code != http.StatusBadRequest {
		t.Errorf("no state cookie: %d", rec.Code)
	}

	cookies, state := startLogin(t, a, f)
	f.nonceOver = "attacker-nonce"
	if rec := callback(a, cookies, state); rec.Code != http.StatusBadRequest {
		t.Errorf("nonce mismatch: %d", rec.Code)
	}
}
