package session

import (
	"sort"
	"sync"
	"time"

	"github.com/goceleris/celeris"
)

var sessionPool = sync.Pool{New: func() any { return &Session{} }}

// Session holds per-request session data backed by a [Store].
type Session struct {
	id          string
	data        map[string]any
	store       Store
	expiry      time.Duration
	idleOverride time.Duration // per-session idle timeout override; 0 = use config default
	keyGen      func() string
	modified    bool
	fresh       bool // true for newly created sessions
	destroyed   bool
}

// Get returns the value for key from the session data.
func (s *Session) Get(key string) (any, bool) {
	v, ok := s.data[key]
	return v, ok
}

// GetString returns the value for key as a string. Returns "" if the key
// is missing or the value is not a string.
func (s *Session) GetString(key string) string {
	v, _ := s.data[key]
	str, _ := v.(string)
	return str
}

// GetInt returns the value for key as an int. Returns 0 if the key is
// missing or the value is not an int.
func (s *Session) GetInt(key string) int {
	v, _ := s.data[key]
	i, _ := v.(int)
	return i
}

// GetBool returns the value for key as a bool. Returns false if the key
// is missing or the value is not a bool.
func (s *Session) GetBool(key string) bool {
	v, _ := s.data[key]
	b, _ := v.(bool)
	return b
}

// GetFloat64 returns the value for key as a float64. Returns 0 if the key
// is missing or the value is not a float64.
func (s *Session) GetFloat64(key string) float64 {
	v, _ := s.data[key]
	f, _ := v.(float64)
	return f
}

// Set stores a key-value pair in the session and marks it as modified.
// The reserved key "_abs_exp" is silently rejected to protect internal
// absolute-timeout bookkeeping.
func (s *Session) Set(key string, value any) {
	if key == absExpKey {
		return
	}
	s.data[key] = value
	s.modified = true
}

// Delete removes a key from the session and marks it as modified.
func (s *Session) Delete(key string) {
	delete(s.data, key)
	s.modified = true
}

// Clear removes all user data from the session and marks it as modified.
// The internal _abs_exp timestamp is preserved.
func (s *Session) Clear() {
	absExp, hasAbsExp := s.data[absExpKey]
	clear(s.data)
	if hasAbsExp {
		s.data[absExpKey] = absExp
	}
	s.modified = true
}

// ID returns the session identifier.
func (s *Session) ID() string { return s.id }

// IsFresh returns true if this is a newly created session (no prior cookie).
func (s *Session) IsFresh() bool { return s.fresh }

// Keys returns a sorted list of all user-visible keys in the session data.
// The internal "_abs_exp" key is excluded.
func (s *Session) Keys() []string {
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		if k == absExpKey {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len returns the number of user-visible key-value pairs in the session.
// The internal "_abs_exp" key is excluded from the count.
func (s *Session) Len() int {
	n := len(s.data)
	if _, ok := s.data[absExpKey]; ok {
		n--
	}
	return n
}

// Save persists the session data to the store. This is called automatically
// after the handler chain when the session has been modified; call it
// explicitly only if you need to guarantee persistence mid-handler.
func (s *Session) Save() error {
	return s.store.Save(s.id, s.data, s.expiry)
}

// Destroy invalidates the session by clearing data and deleting it from
// the store.
func (s *Session) Destroy() error {
	s.data = make(map[string]any)
	s.modified = false
	s.destroyed = true
	return s.store.Delete(s.id)
}

// Regenerate issues a new session ID while preserving data. The old session
// is deleted from the store. The data is saved under the new ID by the
// post-handler save (since modified is set to true). This should be called
// after privilege changes (e.g., login) to prevent session fixation.
func (s *Session) Regenerate() error {
	oldID := s.id
	s.id = s.keyGen()
	if err := s.store.Delete(oldID); err != nil {
		return err
	}
	s.modified = true
	return nil
}

// SetIdleTimeout overrides the idle timeout for this individual session.
// The post-handler save uses this value instead of the config-level
// [Config].IdleTimeout. Pass 0 to revert to the config default.
func (s *Session) SetIdleTimeout(d time.Duration) {
	s.idleOverride = d
	s.modified = true
}

// Reset is a convenience method that combines [Session.Clear],
// [Session.Regenerate], and marks the session as modified in a single call.
// Useful for "log out and start fresh" flows.
func (s *Session) Reset() error {
	s.Clear()
	return s.Regenerate()
}

// FromContext retrieves the [Session] from the request context.
// Returns nil if the session middleware was not applied or the request was
// skipped.
func FromContext(c *celeris.Context) *Session {
	v, ok := c.Get(ContextKey)
	if !ok {
		return nil
	}
	s, _ := v.(*Session)
	return s
}

// validSessionID checks that s has the expected length and contains only
// lowercase hex characters [0-9a-f]. When idLen is negative, validation
// is disabled and any non-empty string passes.
func validSessionID(s string, idLen int) bool {
	if idLen < 0 {
		return s != ""
	}
	if len(s) != idLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// New creates a session middleware with the given config.
func New(config ...Config) celeris.HandlerFunc {
	cfg := DefaultConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg = applyDefaults(cfg)
	cfg.validate()

	skipMap := make(map[string]struct{}, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipMap[p] = struct{}{}
	}

	store := cfg.Store
	cookieName := cfg.CookieName
	keyGen := cfg.KeyGenerator
	idleTimeout := cfg.IdleTimeout
	absTimeout := cfg.AbsoluteTimeout
	absDisabled := absTimeout < 0
	sessionOnly := cfg.CookieSessionOnly
	sessionIDLen := cfg.SessionIDLength
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = func(_ *celeris.Context, err error) error { return err }
	}

	extract := cfg.Extractor
	useCookieExtractor := extract == nil
	if useCookieExtractor {
		extract = CookieExtractor(cookieName)
	}

	cookie := celeris.Cookie{
		Name:     cfg.CookieName,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.CookieMaxAge,
		Secure:   cfg.CookieSecure,
		HTTPOnly: cfg.CookieHTTPOnly,
		SameSite: cfg.CookieSameSite,
	}

	return func(c *celeris.Context) error {
		if cfg.Skip != nil && cfg.Skip(c) {
			return c.Next()
		}

		if _, ok := skipMap[c.Path()]; ok {
			return c.Next()
		}

		sess := sessionPool.Get().(*Session)
		sess.store = store
		sess.expiry = idleTimeout
		sess.keyGen = keyGen
		sess.data = make(map[string]any)
		sess.id = ""
		sess.modified = false
		sess.destroyed = false
		sess.fresh = false
		sess.idleOverride = 0

		loaded := false
		sid := extract(c)
		if sid != "" && !validSessionID(sid, sessionIDLen) {
			sid = ""
		}
		if sid != "" {
			data, loadErr := store.Get(sid)
			if loadErr != nil {
				return errorHandler(c, loadErr)
			}
			if data != nil && !absDisabled {
				// Check absolute timeout.
				if ts, ok := data[absExpKey]; ok {
					if created, ok := ts.(int64); ok {
						if time.Since(time.Unix(0, created)) > absTimeout {
							// Session exceeded absolute timeout; destroy and create fresh.
							_ = store.Delete(sid)
							data = nil
						}
					}
				}
			}
			if data != nil {
				sess.id = sid
				sess.data = data
				loaded = true
			}
		}

		if !loaded {
			sess.id = keyGen()
			sess.fresh = true
			if !absDisabled {
				sess.data[absExpKey] = time.Now().UnixNano()
			}
		}

		c.Set(ContextKey, sess)

		chainErr := c.Next()

		if sess.destroyed {
			if useCookieExtractor {
				ck := cookie
				ck.Value = ""
				ck.MaxAge = -1
				c.SetCookie(&ck)
			} else {
				c.SetHeader(cookieName, "")
			}
		} else if sess.modified || sess.fresh {
			expiry := idleTimeout
			if sess.idleOverride > 0 {
				expiry = sess.idleOverride
			}
			saveErr := store.Save(sess.id, sess.data, expiry)
			if saveErr != nil {
				return errorHandler(c, saveErr)
			}
			if useCookieExtractor {
				ck := cookie
				ck.Value = sess.id
				if sessionOnly {
					ck.MaxAge = 0
				}
				c.SetCookie(&ck)
			} else {
				c.SetHeader(cookieName, sess.id)
			}
		}

		sess.data = nil
		sessionPool.Put(sess)

		return chainErr
	}
}
