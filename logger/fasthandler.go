package logger

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// FastHandler is a high-performance slog.Handler that formats log records
// directly into a pooled byte buffer with zero allocations in steady state.
// It produces output compatible with slog.TextHandler's format.
//
// Use it as a drop-in replacement for slog.TextHandler when performance
// matters more than customization:
//
//	log := slog.New(logger.NewFastHandler(os.Stderr, nil))
//	mw := logger.New(logger.Config{Output: log})
type FastHandler struct {
	w      io.Writer
	level  slog.Level
	prefix []byte // pre-formatted group/attr prefix for WithAttrs/WithGroup
}

// FastHandlerOptions configures a FastHandler.
type FastHandlerOptions struct {
	// Level is the minimum log level. Default: slog.LevelInfo.
	Level slog.Level
}

var fastBufPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 512)
	return &b
}}

// Precomputed level strings avoid per-call formatting.
var levelStrings = [4]string{
	0: "DEBUG",
	1: "INFO",
	2: "WARN",
	3: "ERROR",
}

func levelIndex(l slog.Level) int {
	switch {
	case l < slog.LevelInfo:
		return 0
	case l < slog.LevelWarn:
		return 1
	case l < slog.LevelError:
		return 2
	default:
		return 3
	}
}

// NewFastHandler creates a new FastHandler writing to w.
func NewFastHandler(w io.Writer, opts *FastHandlerOptions) *FastHandler {
	h := &FastHandler{w: w}
	if opts != nil {
		h.level = opts.Level
	}
	return h
}

// Enabled reports whether the handler handles records at the given level.
func (h *FastHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle formats the record and writes it to the output.
func (h *FastHandler) Handle(_ context.Context, r slog.Record) error {
	bp := fastBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	// time=2006-01-02T15:04:05.000Z07:00
	buf = append(buf, "time="...)
	buf = appendTime(buf, r.Time)

	// level=INFO
	buf = append(buf, " level="...)
	buf = append(buf, levelStrings[levelIndex(r.Level)]...)

	// msg=request
	buf = append(buf, " msg="...)
	buf = appendTextValue(buf, r.Message)

	// Pre-formatted attrs from WithAttrs/WithGroup
	if len(h.prefix) > 0 {
		buf = append(buf, h.prefix...)
	}

	// Inline attrs from the record
	r.Attrs(func(a slog.Attr) bool {
		buf = append(buf, ' ')
		buf = appendAttr(buf, a)
		return true
	})

	buf = append(buf, '\n')

	_, err := h.w.Write(buf)

	*bp = buf
	fastBufPool.Put(bp)

	return err
}

// WithAttrs returns a new handler with the given attributes pre-formatted.
func (h *FastHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	var buf []byte
	if len(h.prefix) > 0 {
		buf = append(buf, h.prefix...)
	}
	for _, a := range attrs {
		buf = append(buf, ' ')
		buf = appendAttr(buf, a)
	}
	return &FastHandler{w: h.w, level: h.level, prefix: buf}
}

// WithGroup returns a new handler with the given group name prepended
// to all subsequent attribute keys.
func (h *FastHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	prefix := make([]byte, len(h.prefix))
	copy(prefix, h.prefix)
	return &groupHandler{parent: h, group: name, prefix: prefix}
}

// groupHandler prepends a group name to attribute keys.
type groupHandler struct {
	parent *FastHandler
	group  string
	prefix []byte
}

func (g *groupHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return g.parent.Enabled(ctx, level)
}

func (g *groupHandler) Handle(ctx context.Context, r slog.Record) error {
	bp := fastBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = append(buf, "time="...)
	buf = appendTime(buf, r.Time)
	buf = append(buf, " level="...)
	buf = append(buf, levelStrings[levelIndex(r.Level)]...)
	buf = append(buf, " msg="...)
	buf = appendTextValue(buf, r.Message)

	if len(g.prefix) > 0 {
		buf = append(buf, g.prefix...)
	}

	r.Attrs(func(a slog.Attr) bool {
		buf = append(buf, ' ')
		buf = append(buf, g.group...)
		buf = append(buf, '.')
		buf = appendAttr(buf, a)
		return true
	})

	buf = append(buf, '\n')
	_, err := g.parent.w.Write(buf)

	*bp = buf
	fastBufPool.Put(bp)
	return err
}

func (g *groupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return g
	}
	prefix := make([]byte, len(g.prefix))
	copy(prefix, g.prefix)
	for _, a := range attrs {
		prefix = append(prefix, ' ')
		prefix = append(prefix, g.group...)
		prefix = append(prefix, '.')
		prefix = appendAttr(prefix, a)
	}
	return &groupHandler{parent: g.parent, group: g.group, prefix: prefix}
}

func (g *groupHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return g
	}
	prefix := make([]byte, len(g.prefix))
	copy(prefix, g.prefix)
	return &groupHandler{parent: g.parent, group: g.group + "." + name, prefix: prefix}
}

// appendAttr formats a single slog.Attr into buf.
func appendAttr(buf []byte, a slog.Attr) []byte {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return buf
	}
	buf = append(buf, a.Key...)
	buf = append(buf, '=')
	return appendValue(buf, a.Value)
}

// appendValue formats a slog.Value without using fmt.
func appendValue(buf []byte, v slog.Value) []byte {
	switch v.Kind() {
	case slog.KindString:
		return appendTextValue(buf, v.String())
	case slog.KindInt64:
		return strconv.AppendInt(buf, v.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(buf, v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(buf, v.Float64(), 'g', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(buf, v.Bool())
	case slog.KindDuration:
		return appendDuration(buf, v.Duration())
	case slog.KindTime:
		return appendTime(buf, v.Time())
	case slog.KindGroup:
		attrs := v.Group()
		for i, a := range attrs {
			if i > 0 {
				buf = append(buf, ' ')
			}
			buf = appendAttr(buf, a)
		}
		return buf
	default:
		// LogValuer or Any — fall back to String()
		return appendTextValue(buf, v.String())
	}
}

// appendTextValue appends s, quoting it if it contains spaces or special chars.
func appendTextValue(buf []byte, s string) []byte {
	needsQuote := false
	for i := range len(s) {
		c := s[i]
		if c <= ' ' || c == '"' || c == '=' || c == '\\' {
			needsQuote = true
			break
		}
	}
	if !needsQuote && len(s) > 0 {
		return append(buf, s...)
	}
	buf = append(buf, '"')
	for i := range len(s) {
		c := s[i]
		switch c {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		default:
			buf = append(buf, c)
		}
	}
	buf = append(buf, '"')
	return buf
}

// appendTime formats time in RFC3339 with millisecond precision.
// Avoids time.Format which allocates.
func appendTime(buf []byte, t time.Time) []byte {
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	nsec := t.Nanosecond()

	buf = appendInt(buf, year, 4)
	buf = append(buf, '-')
	buf = appendInt(buf, int(month), 2)
	buf = append(buf, '-')
	buf = appendInt(buf, day, 2)
	buf = append(buf, 'T')
	buf = appendInt(buf, hour, 2)
	buf = append(buf, ':')
	buf = appendInt(buf, min, 2)
	buf = append(buf, ':')
	buf = appendInt(buf, sec, 2)
	buf = append(buf, '.')
	buf = appendInt(buf, nsec/1_000_000, 3)

	_, offset := t.Zone()
	if offset == 0 {
		buf = append(buf, 'Z')
	} else {
		if offset < 0 {
			buf = append(buf, '-')
			offset = -offset
		} else {
			buf = append(buf, '+')
		}
		buf = appendInt(buf, offset/3600, 2)
		buf = append(buf, ':')
		buf = appendInt(buf, (offset%3600)/60, 2)
	}
	return buf
}

// appendDuration formats a duration as a human-readable string (e.g. "1.234ms").
func appendDuration(buf []byte, d time.Duration) []byte {
	abs := d
	if abs < 0 {
		abs = -abs
	}
	if abs < time.Microsecond {
		buf = strconv.AppendFloat(buf, float64(d), 'f', 1, 64)
		return append(buf, "ns"...)
	}
	if abs < time.Millisecond {
		buf = strconv.AppendFloat(buf, float64(d)/float64(time.Microsecond), 'f', 1, 64)
		return append(buf, "µs"...)
	}
	if abs < time.Second {
		buf = strconv.AppendFloat(buf, float64(d)/float64(time.Millisecond), 'f', 1, 64)
		return append(buf, "ms"...)
	}
	buf = strconv.AppendFloat(buf, d.Seconds(), 'f', 3, 64)
	return append(buf, 's')
}

// appendInt appends n zero-padded to width digits.
func appendInt(buf []byte, n, width int) []byte {
	if n < 0 {
		buf = append(buf, '-')
		n = -n
	}
	var tmp [20]byte
	pos := len(tmp)
	for n > 0 || pos > len(tmp)-width {
		pos--
		tmp[pos] = byte('0' + n%10)
		n /= 10
	}
	return append(buf, tmp[pos:]...)
}

// Verify interface compliance.
var _ slog.Handler = (*FastHandler)(nil)

