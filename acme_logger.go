package acmednschallenge

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// slogHandler routes lego's slog output to a CoreDNS plugin logger.
type slogHandler struct {
	logger clog.P
	attrs  []slog.Attr
}

// Enabled always returns true: clog.P already drops debug output unless the debug plugin is on.
func (h *slogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *slogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Resolve())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)

	msg := b.String()
	switch {
	case r.Level >= slog.LevelError:
		h.logger.Error(msg)
	case r.Level >= slog.LevelWarn:
		h.logger.Warning(msg)
	case r.Level >= slog.LevelInfo:
		h.logger.Info(msg)
	default:
		h.logger.Debug(msg)
	}
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{logger: h.logger, attrs: append(h.attrs[:len(h.attrs):len(h.attrs)], attrs...)}
}

// ponytail: groups are ignored (lego doesn't use them); prefix keys with the group name if it starts to.
func (h *slogHandler) WithGroup(string) slog.Handler { return h }
