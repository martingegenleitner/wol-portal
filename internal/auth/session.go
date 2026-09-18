// Package auth implements the OIDC login, the session cookie and the group policy.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	sessionCookie = "wolp_session"
	stateCookie   = "wolp_oidc"
)

// User is the identity stored in the session cookie.
type User struct {
	Subject string   `json:"sub"`
	Name    string   `json:"name"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups"`
	CSRF    string   `json:"csrf"`
	Expires int64    `json:"exp"`
}

// Sessions issues and reads encrypted, authenticated cookies. Nothing is stored
// on the server, so sessions survive restarts as long as the secret is unchanged.
type Sessions struct {
	aead   cipher.AEAD
	secure bool
	ttl    time.Duration
	now    func() time.Time
}

func NewSessions(secret []byte, secure bool, ttl time.Duration) (*Sessions, error) {
	if len(secret) < 32 {
		return nil, errors.New("session secret must be at least 32 bytes")
	}
	key := sha256.Sum256(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sessions{aead: aead, secure: secure, ttl: ttl, now: time.Now}, nil
}

// seal encrypts v; the cookie name is bound as additional data so one cookie
// cannot be replayed as another.
func (s *Sessions) seal(name string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte(name))), nil
}

func (s *Sessions) open(name, value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return errors.New("malformed cookie")
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return errors.New("invalid cookie")
	}
	return json.Unmarshal(plain, v)
}

func (s *Sessions) set(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Sessions) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	})
}

// Issue starts a session for u.
func (s *Sessions) Issue(w http.ResponseWriter, u User) error {
	csrf := make([]byte, 24)
	if _, err := rand.Read(csrf); err != nil {
		return err
	}
	u.CSRF = base64.RawURLEncoding.EncodeToString(csrf)
	u.Expires = s.now().Add(s.ttl).Unix()
	value, err := s.seal(sessionCookie, u)
	if err != nil {
		return err
	}
	s.set(w, sessionCookie, value, s.ttl)
	return nil
}

// Get returns the logged-in user, if the request carries a valid session.
func (s *Sessions) Get(r *http.Request) (*User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	var u User
	if err := s.open(sessionCookie, c.Value, &u); err != nil || u.Expires < s.now().Unix() {
		return nil, false
	}
	return &u, true
}

// Clear ends the session.
func (s *Sessions) Clear(w http.ResponseWriter) { s.clear(w, sessionCookie) }

// loginState is kept in a short-lived cookie between /login and /auth/callback.
type loginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"exp"`
}

func (s *Sessions) setLoginState(w http.ResponseWriter, ls loginState) error {
	ls.Expires = s.now().Add(10 * time.Minute).Unix()
	value, err := s.seal(stateCookie, ls)
	if err != nil {
		return err
	}
	s.set(w, stateCookie, value, 10*time.Minute)
	return nil
}

func (s *Sessions) takeLoginState(w http.ResponseWriter, r *http.Request) (loginState, bool) {
	var ls loginState
	c, err := r.Cookie(stateCookie)
	if err != nil {
		return ls, false
	}
	s.clear(w, stateCookie)
	if err := s.open(stateCookie, c.Value, &ls); err != nil || ls.Expires < s.now().Unix() {
		return loginState{}, false
	}
	return ls, true
}
