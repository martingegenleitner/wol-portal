// Package web serves the UI and the JSON API.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/martingegenleitner/wol-portal/internal/auth"
	"github.com/martingegenleitner/wol-portal/internal/hosts"
)

//go:embed static templates
var assets embed.FS

// Server wires the HTTP routes.
type Server struct {
	Hosts    *hosts.Manager
	Sessions *auth.Sessions
	Policy   auth.Policy

	// LoginHandler and CallbackHandler run the OIDC flow.
	LoginHandler    http.HandlerFunc
	CallbackHandler http.HandlerFunc
}

type hostJSON struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	IP         string      `json:"ip"`
	State      hosts.State `json:"state"`
	Error      string      `json:"error,omitempty"`
	CanControl bool        `json:"can_control"`
}

type listJSON struct {
	User struct {
		Name string `json:"name"`
		CSRF string `json:"csrf"`
	} `json:"user"`
	Hosts []hostJSON `json:"hosts"`
}

// Handler returns the routed and hardened handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	if s.LoginHandler != nil {
		mux.HandleFunc("GET /login", s.LoginHandler)
	}
	if s.CallbackHandler != nil {
		mux.HandleFunc("GET /auth/callback", s.CallbackHandler)
	}
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /logged-out", s.loggedOut)
	mux.HandleFunc("GET /api/hosts", s.listHosts)
	mux.HandleFunc("POST /api/hosts/{id}/start", s.power("start"))
	mux.HandleFunc("POST /api/hosts/{id}/stop", s.power("stop"))
	mux.HandleFunc("POST /logout", s.logout)
	return secureHeaders(mux)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Sessions.Get(r); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	page, err := assets.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(page)
}

func (s *Server) loggedOut(w http.ResponseWriter, _ *http.Request) {
	page, err := assets.ReadFile("templates/logged-out.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}

// currentUser returns the session user or writes a 401.
func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	u, ok := s.Sessions.Get(r)
	if !ok || !s.Policy.CanAccess(u) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
		return nil, false
	}
	return u, true
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	var out listJSON
	out.User.Name, out.User.CSRF = u.Name, u.CSRF
	out.Hosts = []hostJSON{}
	for _, h := range s.Hosts.List() {
		out.Hosts = append(out.Hosts, hostJSON{
			ID: h.ID, Name: h.Name, IP: h.IP, State: h.State, Error: h.Error,
			CanControl: s.Policy.CanControl(u, h.AllowedGroups),
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func csrfOK(u *auth.User, r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(u.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) == 1
}

func (s *Server) power(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.currentUser(w, r)
		if !ok {
			return
		}
		if !csrfOK(u, r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		id := r.PathValue("id")
		h, err := s.Hosts.Get(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown host"})
			return
		}
		if !s.Policy.CanControl(u, h.AllowedGroups) {
			slog.Warn("power action denied", "user", u.Subject, "host", id, "action", action)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "you may not control this host"})
			return
		}

		slog.Info("power action", "user", u.Subject, "host", id, "action", action)
		if action == "start" {
			err = s.Hosts.Start(id)
		} else {
			err = s.Hosts.Stop(id)
		}
		switch {
		case errors.Is(err, hosts.ErrBadState):
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		}
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.Sessions.Get(r); !ok || !csrfOK(u, r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return
	}
	s.Sessions.Clear(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
