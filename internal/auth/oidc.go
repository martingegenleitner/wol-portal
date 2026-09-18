package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig describes the relying party registration.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	GroupsClaim  string
}

// Authenticator runs the authorization code flow (with PKCE and nonce).
type Authenticator struct {
	oauth    *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	sessions *Sessions
	policy   Policy
	claim    string
}

// NewAuthenticator performs OIDC discovery against the issuer.
func NewAuthenticator(ctx context.Context, cfg OIDCConfig, sessions *Sessions, policy Policy) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
	}
	return &Authenticator{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		sessions: sessions,
		policy:   policy,
		claim:    cfg.GroupsClaim,
	}, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Login redirects the browser to the identity provider.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	state, err1 := randomString(24)
	nonce, err2 := randomString(24)
	if err := errors.Join(err1, err2); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := a.sessions.setLoginState(w, loginState{State: state, Nonce: nonce, Verifier: verifier}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	url := a.oauth.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

// Callback completes the login: validates state and ID token, applies the group
// policy and starts the session.
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	ls, ok := a.sessions.takeLoginState(w, r)
	got := r.URL.Query().Get("state")
	if !ok || subtle.ConstantTimeCompare([]byte(ls.State), []byte(got)) != 1 {
		http.Error(w, "login session expired or invalid, please try again", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		slog.Warn("oidc provider returned an error", "error", e, "description", r.URL.Query().Get("error_description"))
		http.Error(w, "login was rejected by the identity provider", http.StatusForbidden)
		return
	}

	ctx := r.Context()
	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		slog.Warn("oidc code exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		slog.Warn("oidc id token rejected", "err", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ls.Nonce)) != 1 {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	if _, has := claims[a.claim]; !has {
		// Some providers only release group claims at the userinfo endpoint.
		if ui, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			var extra map[string]any
			if ui.Claims(&extra) == nil {
				for k, v := range extra {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}

	u := User{
		Subject: idToken.Subject,
		Name:    firstString(claims, "name", "preferred_username", "email"),
		Email:   firstString(claims, "email"),
		Groups:  stringList(claims[a.claim]),
	}
	if u.Name == "" {
		u.Name = u.Subject
	}
	if !a.policy.CanAccess(&u) {
		slog.Info("login denied: no allowed group", "sub", u.Subject)
		http.Error(w, "Access denied: your account is not a member of a group that may use this portal.", http.StatusForbidden)
		return
	}
	if err := a.sessions.Issue(w, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	slog.Info("login", "sub", u.Subject, "name", u.Name)
	http.Redirect(w, r, "/", http.StatusFound)
}

func firstString(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := claims[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// stringList reads a claim that is either a string or an array of strings.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
