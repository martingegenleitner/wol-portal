package sshpower

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/martingegenleitner/wol-portal/internal/config"
)

// testServer is an in-process SSH server that accepts one client key and
// records the exec requests it receives. exec decides the exit status; a nil
// status means "drop the connection without one" (as a shutting-down host does).
type testServer struct {
	addr    net.Addr
	hostPub ssh.PublicKey
	cmds    chan string
	status  *uint32
}

func newTestServer(t *testing.T, clientPub ssh.PublicKey, status *uint32, output string) *testServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(clientPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &testServer{addr: l.Addr(), hostPub: hostSigner.PublicKey(), cmds: make(chan string, 4), status: status}

	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					nc.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for req := range creqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var p struct{ Cmd string }
							ssh.Unmarshal(req.Payload, &p)
							req.Reply(true, nil)
							s.cmds <- p.Cmd
							if status == nil {
								conn.Close()
								return
							}
							ch.Write([]byte(output))
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{*status}))
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return s
}

func writeClientKey(t *testing.T) (path string, pub ssh.PublicKey) {
	t.Helper()
	pubRaw, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ = ssh.NewPublicKey(pubRaw)
	return path, pub
}

func hostFor(t *testing.T, s *testServer, keyPath, cmd string) config.Host {
	t.Helper()
	tcp := s.addr.(*net.TCPAddr)
	return config.Host{ID: "h", Name: "H", IP: tcp.IP.String(), SSHPort: tcp.Port, SSHUser: "root", SSHKey: keyPath, ShutdownCommand: cmd}
}

func writeKnownHosts(t *testing.T, s *testServer) string {
	t.Helper()
	line := fmt.Sprintf("[%s]:%s %s\n", s.addr.(*net.TCPAddr).IP, strconv.Itoa(s.addr.(*net.TCPAddr).Port), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostPub))))
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestShutdownRunsConfiguredCommand(t *testing.T) {
	keyPath, pub := writeClientKey(t)
	zero := uint32(0)
	s := newTestServer(t, pub, &zero, "")
	c := &Client{KnownHostsFile: writeKnownHosts(t, s), Timeout: 5 * time.Second}

	if err := c.Shutdown(context.Background(), hostFor(t, s, keyPath, "sudo systemctl poweroff")); err != nil {
		t.Fatal(err)
	}
	if got := <-s.cmds; got != "sudo systemctl poweroff" {
		t.Errorf("remote command = %q", got)
	}
}

func TestShutdownNonZeroExit(t *testing.T) {
	keyPath, pub := writeClientKey(t)
	one := uint32(1)
	s := newTestServer(t, pub, &one, "sudo: a password is required")
	c := &Client{KnownHostsFile: writeKnownHosts(t, s), Timeout: 5 * time.Second}

	err := c.Shutdown(context.Background(), hostFor(t, s, keyPath, "sudo poweroff"))
	if err == nil || !strings.Contains(err.Error(), "status 1") || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestShutdownDroppedConnectionIsSuccess(t *testing.T) {
	keyPath, pub := writeClientKey(t)
	s := newTestServer(t, pub, nil, "")
	c := &Client{KnownHostsFile: writeKnownHosts(t, s), Timeout: 5 * time.Second}

	if err := c.Shutdown(context.Background(), hostFor(t, s, keyPath, "poweroff")); err != nil {
		t.Fatalf("dropped connection should count as success: %v", err)
	}
}

func TestShutdownRejectsUnknownHostKey(t *testing.T) {
	keyPath, pub := writeClientKey(t)
	zero := uint32(0)
	s := newTestServer(t, pub, &zero, "")

	other := newTestServer(t, pub, &zero, "") // different host key
	c := &Client{KnownHostsFile: writeKnownHosts(t, other), Timeout: 5 * time.Second}
	// known_hosts entry belongs to another port, so this host is unknown -> must fail
	if err := c.Shutdown(context.Background(), hostFor(t, s, keyPath, "poweroff")); err == nil {
		t.Fatal("connection to a host with an unknown key must fail")
	}
	select {
	case cmd := <-s.cmds:
		t.Fatalf("command %q ran despite failed host key check", cmd)
	default:
	}

	c.Insecure = true
	if err := c.Shutdown(context.Background(), hostFor(t, s, keyPath, "poweroff")); err != nil {
		t.Fatalf("insecure mode should skip verification: %v", err)
	}
}

func TestShutdownWrongKey(t *testing.T) {
	_, pub := writeClientKey(t)
	otherKey, _ := writeClientKey(t)
	zero := uint32(0)
	s := newTestServer(t, pub, &zero, "")
	c := &Client{KnownHostsFile: writeKnownHosts(t, s), Timeout: 5 * time.Second}
	if err := c.Shutdown(context.Background(), hostFor(t, s, otherKey, "poweroff")); err == nil {
		t.Fatal("expected authentication failure")
	}
}
