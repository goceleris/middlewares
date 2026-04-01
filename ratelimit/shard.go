package ratelimit

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type shardedLimiter struct {
	shards []shard
	mask   uint64
	rps    float64
	burst  int
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastFill int64 // UnixNano
}

func newShardedLimiter(shardCount int, rps float64, burst int, cleanupInterval time.Duration, ctx context.Context) *shardedLimiter {
	n := nextPow2(shardCount)
	l := &shardedLimiter{
		shards: make([]shard, n),
		mask:   uint64(n - 1),
		rps:    rps,
		burst:  burst,
	}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	go l.cleanup(ctx, cleanupInterval)

	return l
}

// allow checks if a request for the given key is allowed.
// Returns (allowed bool, remaining int, resetUnixNano int64).
func (l *shardedLimiter) allow(key string, now int64) (bool, int, int64) {
	idx := fnv1a(key) & l.mask
	s := &l.shards[idx]
	s.mu.Lock()

	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{
			tokens:   float64(l.burst) - 1,
			lastFill: now,
		}
		s.buckets[key] = b
		s.mu.Unlock()
		reset := now + int64(float64(time.Second)/l.rps)
		return true, l.burst - 1, reset
	}

	// Refill tokens.
	elapsed := float64(now-b.lastFill) / float64(time.Second)
	b.tokens += elapsed * l.rps
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastFill = now

	if b.tokens < 1 {
		remaining := 0
		wait := (1 - b.tokens) / l.rps
		reset := now + int64(wait*float64(time.Second))
		s.mu.Unlock()
		return false, remaining, reset
	}

	b.tokens--
	remaining := int(b.tokens)
	reset := now + int64(float64(time.Second)/l.rps)
	s.mu.Unlock()
	return true, remaining, reset
}

func (l *shardedLimiter) cleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	shardIdx := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s := &l.shards[shardIdx%len(l.shards)]
			shardIdx++
			expiry := now.UnixNano() - int64(10*time.Second)
			s.mu.Lock()
			for k, b := range s.buckets {
				if b.lastFill < expiry && b.tokens >= float64(l.burst) {
					delete(s.buckets, k)
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

// smallInts caches string representations of integers 0-999.
// Covers >99% of rate limit remaining/reset values without allocation.
var smallInts [1000]string

func init() {
	for i := range smallInts {
		smallInts[i] = strconv.Itoa(i)
	}
}

func formatInt(n int) string {
	if n >= 0 && n < len(smallInts) {
		return smallInts[n]
	}
	return strconv.Itoa(n)
}

func formatResetSeconds(resetNano, nowNano int64) string {
	secs := (resetNano - nowNano + int64(time.Second) - 1) / int64(time.Second)
	if secs < 0 {
		secs = 0
	}
	if secs < int64(len(smallInts)) {
		return smallInts[secs]
	}
	return strconv.FormatInt(secs, 10)
}
