package csrf

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// Storage defines the interface for server-side CSRF token storage.
// When configured, the middleware validates tokens against the store
// instead of relying solely on cookie comparison (signed double-submit).
type Storage interface {
	// Get retrieves a token by key. Returns the token and true if found
	// and not expired, or empty string and false otherwise.
	Get(key string) (string, bool)

	// Set stores a token with the given key and expiry duration.
	Set(key string, token string, expiry time.Duration)

	// Delete removes a token by key.
	Delete(key string)
}

// MemoryStorageConfig configures the in-memory CSRF token store.
type MemoryStorageConfig struct {
	// Shards is the number of lock shards. Default: runtime.NumCPU().
	Shards int

	// CleanupInterval is how often expired entries are evicted.
	// Default: 1 minute.
	CleanupInterval time.Duration

	// CleanupContext, if set, controls cleanup goroutine lifetime.
	// When the context is cancelled, the cleanup goroutine stops.
	// If nil, cleanup runs until the process exits.
	CleanupContext context.Context
}

type memoryStorage struct {
	shards []storageShard
	mask   uint64
}

type storageShard struct {
	mu    sync.Mutex
	items map[string]*storageItem
}

type storageItem struct {
	token  string
	expiry int64 // UnixNano; 0 means no expiry
}

// NewMemoryStorage creates an in-memory CSRF token store backed by sharded maps.
// A background goroutine periodically evicts expired tokens.
func NewMemoryStorage(config ...MemoryStorageConfig) Storage {
	var cfg MemoryStorageConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.Shards <= 0 {
		cfg.Shards = runtime.NumCPU()
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = time.Minute
	}

	n := nextPow2(cfg.Shards)
	s := &memoryStorage{
		shards: make([]storageShard, n),
		mask:   uint64(n - 1),
	}
	for i := range s.shards {
		s.shards[i].items = make(map[string]*storageItem)
	}

	ctx := cfg.CleanupContext
	if ctx == nil {
		ctx = context.Background()
	}
	go s.cleanup(ctx, cfg.CleanupInterval)

	return s
}

func (m *memoryStorage) shard(key string) *storageShard {
	return &m.shards[fnv1a(key)&m.mask]
}

func (m *memoryStorage) Get(key string) (string, bool) {
	s := m.shard(key)
	s.mu.Lock()
	item, ok := s.items[key]
	if !ok {
		s.mu.Unlock()
		return "", false
	}
	if item.expiry > 0 && time.Now().UnixNano() > item.expiry {
		delete(s.items, key)
		s.mu.Unlock()
		return "", false
	}
	token := item.token
	s.mu.Unlock()
	return token, true
}

func (m *memoryStorage) Set(key string, token string, expiry time.Duration) {
	s := m.shard(key)
	var exp int64
	if expiry > 0 {
		exp = time.Now().Add(expiry).UnixNano()
	}
	s.mu.Lock()
	s.items[key] = &storageItem{token: token, expiry: exp}
	s.mu.Unlock()
}

func (m *memoryStorage) Delete(key string) {
	s := m.shard(key)
	s.mu.Lock()
	delete(s.items, key)
	s.mu.Unlock()
}

func (m *memoryStorage) cleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	shardIdx := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s := &m.shards[shardIdx%len(m.shards)]
			shardIdx++
			nowNano := now.UnixNano()
			s.mu.Lock()
			for k, item := range s.items {
				if item.expiry > 0 && nowNano > item.expiry {
					delete(s.items, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func fnv1a(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
