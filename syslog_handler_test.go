package main

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type syslogRecord struct {
	priority string
	msg      string
}

// fakeSyslog records each message with the priority method it was written
// with.
type fakeSyslog struct {
	mu      sync.Mutex
	records []syslogRecord
}

func (f *fakeSyslog) write(priority, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, syslogRecord{priority, m})
	return nil
}

func (f *fakeSyslog) Debug(m string) error   { return f.write("debug", m) }
func (f *fakeSyslog) Info(m string) error    { return f.write("info", m) }
func (f *fakeSyslog) Warning(m string) error { return f.write("warning", m) }
func (f *fakeSyslog) Err(m string) error     { return f.write("err", m) }

func TestSyslogHandler(t *testing.T) {
	tests := []struct {
		name         string
		log          func(*slog.Logger)
		wantPriority string
		wantMsg      string
	}{
		{"info", func(l *slog.Logger) { l.Info("authentication succeeded", "principal", "foober") }, "info", `level=INFO msg="authentication succeeded" principal=foober`},
		{"warn", func(l *slog.Logger) { l.Warn("authentication failed") }, "warning", `level=WARN msg="authentication failed"`},
		{"error", func(l *slog.Logger) { l.Error("restoring privileges failed") }, "err", `level=ERROR msg="restoring privileges failed"`},
		{"above error", func(l *slog.Logger) { l.Log(t.Context(), slog.LevelError+4, "worse") }, "err", `level=ERROR+4 msg=worse`},
		{"between info and warn", func(l *slog.Logger) { l.Log(t.Context(), slog.LevelInfo+2, "notice") }, "info", `level=INFO+2 msg=notice`},
		{"attrs from With", func(l *slog.Logger) { l.With("user", "foober", "uid", 1000).Warn("no SSH_AUTH_SOCK") }, "warning", `level=WARN msg="no SSH_AUTH_SOCK" user=foober uid=1000`},
		{"group from WithGroup", func(l *slog.Logger) { l.WithGroup("cert").Info("matched", "serial", 1) }, "info", `level=INFO msg=matched cert.serial=1`},
		{"multi-line value stays on one line", func(l *slog.Logger) { l.Warn("authentication failed", "err", "first\nsecond") }, "warning", `level=WARN msg="authentication failed" err="first\nsecond"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSyslog{}
			tt.log(slog.New(newSyslogHandler(f)))

			if len(f.records) != 1 {
				t.Fatalf("got %d records want 1: %+v", len(f.records), f.records)
			}
			got := f.records[0]
			if got.priority != tt.wantPriority {
				t.Errorf("priority got %q want %q", got.priority, tt.wantPriority)
			}
			if got.msg != tt.wantMsg {
				t.Errorf("msg got %q want %q", got.msg, tt.wantMsg)
			}
		})
	}
}

func TestSyslogHandlerDebugDisabled(t *testing.T) {
	f := &fakeSyslog{}
	slog.New(newSyslogHandler(f)).Debug("noisy")
	if len(f.records) != 0 {
		t.Errorf("got %d records want 0: %+v", len(f.records), f.records)
	}
}

// TestSyslogHandlerConcurrent checks loggers derived from one handler can
// be used concurrently without interleaving records.
func TestSyslogHandlerConcurrent(t *testing.T) {
	f := &fakeSyslog{}
	logger := slog.New(newSyslogHandler(f))

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			logger.With("worker", i).Warn("message", "n", i)
		})
	}
	wg.Wait()

	if len(f.records) != 20 {
		t.Fatalf("got %d records want 20", len(f.records))
	}
	for _, r := range f.records {
		var worker, n int
		if _, err := fmt.Sscanf(strings.TrimPrefix(r.msg, "level=WARN msg=message "), "worker=%d n=%d", &worker, &n); err != nil || worker != n {
			t.Errorf("malformed record %q", r.msg)
		}
	}
}
