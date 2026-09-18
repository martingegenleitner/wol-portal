// Package hosts tracks the power state of the configured hosts and triggers
// power-on (Wake-on-LAN) and power-off (SSH) actions.
package hosts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/martingegenleitner/wol-portal/internal/config"
)

type State string

const (
	StateOn           State = "on"
	StateOff          State = "off"
	StatePendingStart State = "pending_start"
	StatePendingStop  State = "pending_stop"
)

var (
	ErrNotFound = errors.New("unknown host")
	ErrBadState = errors.New("action not possible in current state")
)

// Waker sends a Wake-on-LAN packet.
type Waker interface {
	Wake(mac net.HardwareAddr) error
}

// Shutdowner powers a host off.
type Shutdowner interface {
	Shutdown(ctx context.Context, h config.Host) error
}

// ProbeFunc reports whether a host is reachable.
type ProbeFunc func(ctx context.Context, h config.Host) bool

// TCPProbe considers a host up when its SSH port accepts a connection.
func TCPProbe(ctx context.Context, h config.Host) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", h.Addr())
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Status is a snapshot of one host.
type Status struct {
	ID            string
	Name          string
	IP            string
	State         State
	Error         string
	AllowedGroups []string
}

type entry struct {
	cfg config.Host

	mu     sync.Mutex
	state  State
	since  time.Time
	errMsg string
}

// Options configures a Manager.
type Options struct {
	Waker          Waker
	Shutdowner     Shutdowner
	Probe          ProbeFunc
	ProbeInterval  time.Duration
	PendingTimeout time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

type Manager struct {
	entries []*entry
	byID    map[string]*entry
	opt     Options
}

func NewManager(hosts []config.Host, opt Options) *Manager {
	if opt.Probe == nil {
		opt.Probe = TCPProbe
	}
	if opt.ProbeInterval <= 0 {
		opt.ProbeInterval = 5 * time.Second
	}
	if opt.PendingTimeout <= 0 {
		opt.PendingTimeout = 5 * time.Minute
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	m := &Manager{byID: map[string]*entry{}, opt: opt}
	for _, h := range hosts {
		e := &entry{cfg: h, state: StateOff, since: opt.Now()}
		m.entries = append(m.entries, e)
		m.byID[h.ID] = e
	}
	return m
}

// List returns a snapshot of all hosts in configuration order.
func (m *Manager) List() []Status {
	out := make([]Status, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.status())
	}
	return out
}

func (e *entry) status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{
		ID: e.cfg.ID, Name: e.cfg.Name, IP: e.cfg.IP,
		State: e.state, Error: e.errMsg, AllowedGroups: e.cfg.AllowedGroups,
	}
}

// Get returns the status of one host.
func (m *Manager) Get(id string) (Status, error) {
	e, ok := m.byID[id]
	if !ok {
		return Status{}, ErrNotFound
	}
	return e.status(), nil
}

// ProbeAll probes every host once, concurrently, and applies the results.
func (m *Manager) ProbeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range m.entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.probeOnce(ctx, e)
		}()
	}
	wg.Wait()
}

// Run probes all hosts periodically until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.opt.ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.ProbeAll(ctx)
		}
	}
}

func (m *Manager) probeOnce(ctx context.Context, e *entry) {
	up := m.opt.Probe(ctx, e.cfg)
	if ctx.Err() != nil {
		return
	}
	e.observe(up, m.opt.Now(), m.opt.PendingTimeout, m.opt.Logger)
}

// observe folds a probe result into the state machine.
func (e *entry) observe(up bool, now time.Time, timeout time.Duration, log *slog.Logger) {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := func(s State, msg string) {
		if s != e.state {
			log.Info("host state changed", "host", e.cfg.ID, "from", e.state, "to", s)
			e.since = now
		}
		e.state, e.errMsg = s, msg
	}
	switch e.state {
	case StatePendingStart:
		if up {
			set(StateOn, "")
		} else if now.Sub(e.since) > timeout {
			set(StateOff, "host did not come online in time")
		}
	case StatePendingStop:
		if !up {
			set(StateOff, "")
		} else if now.Sub(e.since) > timeout {
			set(StateOn, "host did not shut down in time")
		}
	default:
		next, msg := StateOff, e.errMsg
		if up {
			next = StateOn
		}
		if next != e.state {
			msg = ""
		}
		set(next, msg)
	}
}

// Start sends a magic packet to a host that is off.
func (m *Manager) Start(id string) error {
	e, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	e.mu.Lock()
	if e.state != StateOff {
		st := e.state
		e.mu.Unlock()
		return fmt.Errorf("%w: host is %s", ErrBadState, st)
	}
	e.state, e.since, e.errMsg = StatePendingStart, m.opt.Now(), ""
	e.mu.Unlock()

	m.opt.Logger.Info("sending magic packet", "host", id)
	if err := m.opt.Waker.Wake(e.cfg.HardwareAddr); err != nil {
		e.fail(StatePendingStart, StateOff, "wake-on-lan failed: "+err.Error())
		return err
	}
	return nil
}

// Stop runs the shutdown command on a host that is on. The command runs in the
// background; the host shows as pending until it stops answering.
func (m *Manager) Stop(id string) error {
	e, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	e.mu.Lock()
	if e.state != StateOn {
		st := e.state
		e.mu.Unlock()
		return fmt.Errorf("%w: host is %s", ErrBadState, st)
	}
	e.state, e.since, e.errMsg = StatePendingStop, m.opt.Now(), ""
	e.mu.Unlock()

	m.opt.Logger.Info("shutting down host", "host", id)
	go func() {
		if err := m.opt.Shutdowner.Shutdown(context.Background(), e.cfg); err != nil {
			m.opt.Logger.Error("shutdown failed", "host", id, "err", err)
			e.fail(StatePendingStop, StateOn, "shutdown failed: "+err.Error())
		}
	}()
	return nil
}

// fail moves the host from `from` to `to` with an error message, unless a probe
// has already moved it on.
func (e *entry) fail(from, to State, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == from {
		e.state, e.errMsg = to, msg
	}
}
