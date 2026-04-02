package session

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// Store defines the interface for session storage backends.
//
// All methods accept a [context.Context] to support cancellation and
// deadline propagation. The middleware passes the request context
// obtained from [celeris.Context.Context].
type Store interface {
	// Get retrieves session data by ID. Returns nil map and no error if the
	// session does not exist or has expired.
	Get(ctx context.Context, id string) (map[string]any, error)

	// Save persists session data with the given expiry duration.
	Save(ctx context.Context, id string, data map[string]any, expiry time.Duration) error

	// Delete removes a session by ID.
	Delete(ctx context.Context, id string) error

	// Reset wipes all sessions from the store.
	Reset(ctx context.Context) error
}

// MemoryStoreConfig configures the in-memory session store.
type MemoryStoreConfig struct {
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

type memoryStore struct {
	shards []msShard
	mask   uint64
	expiry time.Duration
}

type msShard struct {
	mu    sync.Mutex
	items map[string]*msItem
}

type msItem struct {
	data   map[string]any
	expiry int64 // UnixNano; 0 means no expiry
}

// NewMemoryStore creates an in-memory session store backed by sharded maps.
// A background goroutine periodically evicts expired sessions.
func NewMemoryStore(config ...MemoryStoreConfig) Store {
	var cfg MemoryStoreConfig
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
	s := &memoryStore{
		shards: make([]msShard, n),
		mask:   uint64(n - 1),
	}
	for i := range s.shards {
		s.shards[i].items = make(map[string]*msItem)
	}

	ctx := cfg.CleanupContext
	if ctx == nil {
		ctx = context.Background()
	}
	go s.cleanup(ctx, cfg.CleanupInterval)

	return s
}

func (m *memoryStore) shard(id string) *msShard {
	return &m.shards[fnv1a(id)&m.mask]
}

func (m *memoryStore) Get(_ context.Context, id string) (map[string]any, error) {
	s := m.shard(id)
	s.mu.Lock()
	item, ok := s.items[id]
	if !ok {
		s.mu.Unlock()
		return nil, nil
	}
	if item.expiry > 0 && time.Now().UnixNano() > item.expiry {
		delete(s.items, id)
		s.mu.Unlock()
		return nil, nil
	}
	// Return a shallow copy so callers cannot mutate the store's map.
	cp := make(map[string]any, len(item.data))
	for k, v := range item.data {
		cp[k] = v
	}
	s.mu.Unlock()
	return cp, nil
}

func (m *memoryStore) Save(_ context.Context, id string, data map[string]any, expiry time.Duration) error {
	s := m.shard(id)
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	var exp int64
	if expiry > 0 {
		exp = time.Now().Add(expiry).UnixNano()
	}
	s.mu.Lock()
	s.items[id] = &msItem{data: cp, expiry: exp}
	s.mu.Unlock()
	return nil
}

func (m *memoryStore) Delete(_ context.Context, id string) error {
	s := m.shard(id)
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
	return nil
}

func (m *memoryStore) Reset(_ context.Context) error {
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		clear(s.items)
		s.mu.Unlock()
	}
	return nil
}

func (m *memoryStore) cleanup(ctx context.Context, interval time.Duration) {
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
