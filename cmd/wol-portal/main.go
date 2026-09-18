package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/martingegenleitner/wol-portal/internal/auth"
	"github.com/martingegenleitner/wol-portal/internal/config"
	"github.com/martingegenleitner/wol-portal/internal/hosts"
	"github.com/martingegenleitner/wol-portal/internal/sshpower"
	"github.com/martingegenleitner/wol-portal/internal/web"
	"github.com/martingegenleitner/wol-portal/internal/wol"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadSettings()
	if err != nil {
		return err
	}
	hostList, err := config.LoadHosts(cfg.HostsFile, cfg.DefaultSSHUser)
	if err != nil {
		return err
	}
	if cfg.InsecureHostKey {
		slog.Warn("SSH host key verification is DISABLED (WOLP_SSH_INSECURE_HOSTKEY)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sessions, err := auth.NewSessions(cfg.SessionSecret, cfg.SecureCookies(), cfg.SessionTTL)
	if err != nil {
		return err
	}
	policy := auth.Policy{Access: cfg.AllowedGroups, Admin: cfg.AdminGroups}

	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	authn, err := auth.NewAuthenticator(discoveryCtx, auth.OIDCConfig{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.RedirectURL(),
		Scopes:       cfg.OIDCScopes,
		GroupsClaim:  cfg.GroupsClaim,
	}, sessions, policy)
	cancel()
	if err != nil {
		return err
	}

	manager := hosts.NewManager(hostList, hosts.Options{
		Waker: wol.Sender{Addr: cfg.WOLBroadcast},
		Shutdowner: &sshpower.Client{
			KnownHostsFile: cfg.KnownHostsFile,
			Insecure:       cfg.InsecureHostKey,
			Timeout:        cfg.SSHTimeout,
		},
		ProbeInterval:  cfg.ProbeInterval,
		PendingTimeout: cfg.PendingTimeout,
	})
	manager.ProbeAll(ctx)
	go manager.Run(ctx)

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&web.Server{
			Hosts:           manager,
			Sessions:        sessions,
			Policy:          policy,
			LoginHandler:    authn.Login,
			CallbackHandler: authn.Callback,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "addr", cfg.Listen, "hosts", len(hostList), "redirect_uri", cfg.RedirectURL())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
