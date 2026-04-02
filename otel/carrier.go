package otel

import "github.com/goceleris/celeris"

// headerCarrier adapts a celeris Context to propagation.TextMapCarrier.
type headerCarrier struct {
	ctx *celeris.Context
}

func (h headerCarrier) Get(key string) string {
	return h.ctx.Header(key)
}

func (h headerCarrier) Set(key, value string) {
	h.ctx.SetHeader(key, value)
}

func (h headerCarrier) Keys() []string {
	headers := h.ctx.RequestHeaders()
	keys := make([]string, 0, len(headers))
	for _, hdr := range headers {
		// Skip HTTP/2 pseudo-headers (e.g. :method, :path).
		if len(hdr[0]) > 0 && hdr[0][0] == ':' {
			continue
		}
		keys = append(keys, hdr[0])
	}
	return keys
}
