//go:build darwin || linux

/*
Copyright (c) 2026 Andrew Heberle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// syslogWriter is the part of *syslog.Writer the handler uses: one method
// per priority, each keeping the writer's facility.
type syslogWriter interface {
	Debug(m string) error
	Info(m string) error
	Warning(m string) error
	Err(m string) error
}

// syslogHandler formats records as text (without a time attribute, since
// syslog adds its own timestamp) and writes each at the syslog priority
// matching its level.
type syslogHandler struct {
	w    syslogWriter
	text slog.Handler

	// shared by every handler derived via WithAttrs and WithGroup, since
	// they all write through the same buffer
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func newSyslogHandler(w syslogWriter) *syslogHandler {
	buf := &bytes.Buffer{}
	text := slog.NewTextHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	return &syslogHandler{w: w, text: text, mu: &sync.Mutex{}, buf: buf}
}

func (h *syslogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.text.Enabled(ctx, level)
}

func (h *syslogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.buf.Reset()
	if err := h.text.Handle(ctx, r); err != nil {
		return err
	}
	msg := strings.TrimSuffix(h.buf.String(), "\n")

	switch {
	case r.Level >= slog.LevelError:
		return h.w.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.w.Info(msg)
	default:
		return h.w.Debug(msg)
	}
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &syslogHandler{w: h.w, text: h.text.WithAttrs(attrs), mu: h.mu, buf: h.buf}
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	return &syslogHandler{w: h.w, text: h.text.WithGroup(name), mu: h.mu, buf: h.buf}
}
