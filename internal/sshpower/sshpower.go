// Package sshpower runs a host's shutdown command over SSH.
package sshpower

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/martingegenleitner/wol-portal/internal/config"
)

// Client connects to hosts with the key configured for each host.
type Client struct {
	// KnownHostsFile is used to verify host keys. Ignored when Insecure is set.
	KnownHostsFile string
	// Insecure disables host key verification. For testing only.
	Insecure bool
	// Timeout bounds the whole operation (connect + command).
	Timeout time.Duration
}

// Shutdown runs h.ShutdownCommand on the host. A connection that drops while the
// command runs (the host going down) counts as success.
func (c *Client) Shutdown(ctx context.Context, h config.Host) error {
	keyData, err := os.ReadFile(h.SSHKey)
	if err != nil {
		return fmt.Errorf("read ssh key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("parse ssh key %s (passphrase-protected keys are not supported): %w", h.SSHKey, err)
	}

	var hostKey ssh.HostKeyCallback
	if c.Insecure {
		hostKey = ssh.InsecureIgnoreHostKey()
	} else if hostKey, err = knownhosts.New(c.KnownHostsFile); err != nil {
		return fmt.Errorf("load known_hosts: %w", err)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cfg := &ssh.ClientConfig{
		User:            h.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", h.Addr())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	// Unblocks handshake and command when the deadline passes.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	sc, chans, reqs, err := ssh.NewClientConn(conn, h.Addr(), cfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(h.ShutdownCommand)
	return interpret(ctx, err, out)
}

func interpret(ctx context.Context, err error, out []byte) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("shutdown command timed out: %w", ctx.Err())
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) || errors.Is(err, io.EOF) {
		return nil // connection went away because the host is shutting down
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		msg := string(out)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("shutdown command exited with status %d: %s", exit.ExitStatus(), msg)
	}
	return fmt.Errorf("run shutdown command: %w", err)
}
