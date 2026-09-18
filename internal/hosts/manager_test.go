package hosts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/martingegenleitner/wol-portal/internal/config"
)

type fakeWaker struct {
	err  error
	macs []net.HardwareAddr
}

func (f *fakeWaker) Wake(m net.HardwareAddr) error { f.macs = append(f.macs, m); return f.err }

type fakeShut struct {
	err  error
	done chan struct{}
}

func (f *fakeShut) Shutdown(context.Context, config.Host) error {
	defer close(f.done)
	return f.err
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	m    *Manager
	w    *fakeWaker
	s    *fakeShut
	clk  *clock
	up   *bool
	self func(string) Status
}

func newRig(t *testing.T) *rig {
	t.Helper()
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	r := &rig{w: &fakeWaker{}, s: &fakeShut{done: make(chan struct{})}, clk: &clock{t: time.Unix(1000, 0)}}
	up := false
	r.up = &up
	r.m = NewManager([]config.Host{{ID: "h", Name: "H", IP: "10.0.0.1", SSHPort: 22, HardwareAddr: mac}}, Options{
		Waker: r.w, Shutdowner: r.s,
		Probe:          func(context.Context, config.Host) bool { return *r.up },
		PendingTimeout: time.Minute,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:            r.clk.now,
	})
	r.self = func(id string) Status { s, _ := r.m.Get(id); return s }
	return r
}

func (r *rig) probe() { r.m.ProbeAll(context.Background()) }

func TestProbeSetsOnOff(t *testing.T) {
	r := newRig(t)
	*r.up = true
	r.probe()
	if got := r.self("h").State; got != StateOn {
		t.Fatalf("state = %s", got)
	}
	*r.up = false
	r.probe()
	if got := r.self("h").State; got != StateOff {
		t.Fatalf("state = %s", got)
	}
}

func TestStartFlow(t *testing.T) {
	r := newRig(t)
	r.probe()
	if err := r.m.Start("h"); err != nil {
		t.Fatal(err)
	}
	if len(r.w.macs) != 1 || r.self("h").State != StatePendingStart {
		t.Fatalf("wol=%d state=%s", len(r.w.macs), r.self("h").State)
	}
	if err := r.m.Start("h"); !errors.Is(err, ErrBadState) {
		t.Errorf("second start: %v", err)
	}
	r.probe() // still down -> stays pending
	if r.self("h").State != StatePendingStart {
		t.Fatal("left pending too early")
	}
	*r.up = true
	r.probe()
	if s := r.self("h"); s.State != StateOn || s.Error != "" {
		t.Fatalf("after boot: %+v", s)
	}
}

func TestStartTimeout(t *testing.T) {
	r := newRig(t)
	r.probe()
	r.m.Start("h")
	r.clk.add(2 * time.Minute)
	r.probe()
	if s := r.self("h"); s.State != StateOff || s.Error == "" {
		t.Fatalf("expected off with error, got %+v", s)
	}
}

func TestStartWakeError(t *testing.T) {
	r := newRig(t)
	r.w.err = errors.New("boom")
	r.probe()
	if err := r.m.Start("h"); err == nil {
		t.Fatal("expected error")
	}
	if s := r.self("h"); s.State != StateOff || s.Error == "" {
		t.Fatalf("got %+v", s)
	}
}

func TestStopFlow(t *testing.T) {
	r := newRig(t)
	*r.up = true
	r.probe()
	if err := r.m.Stop("h"); err != nil {
		t.Fatal(err)
	}
	<-r.s.done
	if r.self("h").State != StatePendingStop {
		t.Fatalf("state = %s", r.self("h").State)
	}
	if err := r.m.Stop("h"); !errors.Is(err, ErrBadState) {
		t.Errorf("second stop: %v", err)
	}
	r.probe() // still up
	if r.self("h").State != StatePendingStop {
		t.Fatal("left pending too early")
	}
	*r.up = false
	r.probe()
	if s := r.self("h"); s.State != StateOff || s.Error != "" {
		t.Fatalf("got %+v", s)
	}
}

func TestStopFailureRevertsToOn(t *testing.T) {
	r := newRig(t)
	r.s.err = errors.New("permission denied")
	*r.up = true
	r.probe()
	r.m.Stop("h")
	<-r.s.done
	deadline := time.Now().Add(time.Second)
	for r.self("h").State != StateOn && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s := r.self("h"); s.State != StateOn || s.Error == "" {
		t.Fatalf("got %+v", s)
	}
}

func TestStopTimeout(t *testing.T) {
	r := newRig(t)
	*r.up = true
	r.probe()
	r.m.Stop("h")
	<-r.s.done
	r.clk.add(2 * time.Minute)
	r.probe()
	if s := r.self("h"); s.State != StateOn || s.Error == "" {
		t.Fatalf("got %+v", s)
	}
}

func TestWrongStateAndUnknown(t *testing.T) {
	r := newRig(t)
	r.probe() // off
	if err := r.m.Stop("h"); !errors.Is(err, ErrBadState) {
		t.Errorf("stop while off: %v", err)
	}
	*r.up = true
	r.probe()
	if err := r.m.Start("h"); !errors.Is(err, ErrBadState) {
		t.Errorf("start while on: %v", err)
	}
	if err := r.m.Start("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}
