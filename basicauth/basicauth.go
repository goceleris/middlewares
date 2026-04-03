package basicauth

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/goceleris/celeris"
)

// ErrUnauthorized is returned when authentication fails.
var ErrUnauthorized = celeris.NewHTTPError(401, "Unauthorized")

// ErrBadRequest is returned when the Authorization header is
// syntactically malformed: invalid base64, missing colon separator,
// or credentials containing invalid UTF-8 / control characters.
var ErrBadRequest = celeris.NewHTTPError(400, "basicauth: bad request")

// ErrHeaderTooLarge is returned when the Authorization header exceeds HeaderLimit.
var ErrHeaderTooLarge = celeris.NewHTTPError(431, "Request Header Fields Too Large")

// New creates a basic auth middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := defaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	escapedRealm := strings.ReplaceAll(cfg.Realm, `\`, `\\`)
	escapedRealm = strings.ReplaceAll(escapedRealm, `"`, `\"`)
	realmHeader := `Basic realm="` + escapedRealm + `"`
	validator := cfg.Validator
	validatorCtx := cfg.ValidatorWithContext
	headerLimit := cfg.HeaderLimit
	errorHandler := cfg.ErrorHandler

	if errorHandler == nil {
		errorHandler = func(c *celeris.Context, err error) error {
			if err == ErrHeaderTooLarge {
				return ErrHeaderTooLarge
			}
			if err == ErrBadRequest {
				c.SetHeader("cache-control", "no-store")
				c.SetHeader("vary", "authorization")
				return ErrBadRequest
			}
			c.SetHeader("www-authenticate", realmHeader)
			c.SetHeader("cache-control", "no-store")
			c.SetHeader("vary", "authorization")
			return ErrUnauthorized
		}
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		if len(c.Header("authorization")) > headerLimit {
			return errorHandler(c, ErrHeaderTooLarge)
		}

		user, pass, result := parseBasicAuth(c.Header("authorization"))
		switch result {
		case authMalformed:
			return errorHandler(c, ErrBadRequest)
		case authMissing:
			return errorHandler(c, ErrUnauthorized)
		}

		var valid bool
		if validatorCtx != nil {
			valid = validatorCtx(c, user, pass)
		} else {
			valid = validator(user, pass)
		}
		if !valid {
			return errorHandler(c, ErrUnauthorized)
		}

		c.Set(UsernameKey, user)
		return c.Next()
	}
}

// authResult distinguishes the reason a credential parse failed.
type authResult int

const (
	authOK        authResult = iota // credentials parsed successfully
	authMissing                     // no header, wrong scheme, or empty payload
	authMalformed                   // bad base64, no colon, or invalid bytes
)

// parseBasicAuth extracts and validates Basic credentials from the raw
// Authorization header value. It returns authMissing when no Basic
// credentials are present, authMalformed when the payload is
// syntactically broken, and authOK on success.
func parseBasicAuth(auth string) (user, pass string, result authResult) {
	if auth == "" {
		result = authMissing
		return
	}
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		result = authMissing
		return
	}
	payload := auth[len(prefix):]
	if payload == "" {
		result = authMissing
		return
	}

	var buf [192]byte
	if base64.StdEncoding.DecodedLen(len(payload)) > len(buf) {
		result = authMalformed
		return
	}
	n, err := base64.StdEncoding.Decode(buf[:],
		unsafe.Slice(unsafe.StringData(payload), len(payload)))
	if err != nil {
		result = authMalformed
		return
	}

	decoded := string(buf[:n])
	i := strings.IndexByte(decoded, ':')
	if i < 0 {
		result = authMalformed
		return
	}

	user = decoded[:i]
	pass = decoded[i+1:]
	if !validCredentialBytes(user, pass) {
		result = authMalformed
		return
	}

	result = authOK
	return
}

// validCredentialBytes rejects credentials that contain invalid UTF-8
// sequences or ASCII control characters (bytes < 0x20 or DEL 0x7F).
//
// NFC normalization is intentionally omitted to avoid a dependency on
// golang.org/x/text. Callers storing passwords should normalize to NFC
// before hashing if Unicode equivalence matters.
func validCredentialBytes(user, pass string) bool {
	if !utf8.ValidString(user) || !utf8.ValidString(pass) {
		return false
	}
	for i := 0; i < len(user); i++ {
		if user[i] < 0x20 || user[i] == 0x7F {
			return false
		}
	}
	for i := 0; i < len(pass); i++ {
		if pass[i] < 0x20 || pass[i] == 0x7F {
			return false
		}
	}
	return true
}

// UsernameFromContext returns the authenticated username from the context store.
// Returns an empty string if no username was stored (e.g., no auth or skipped).
func UsernameFromContext(c *celeris.Context) string {
	v, ok := c.Get(UsernameKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
