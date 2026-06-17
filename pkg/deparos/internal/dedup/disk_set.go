// Package dedup provides disk-backed deduplication using LevelDB.
package dedup

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// diskSetShards is the number of striped insert locks. Insertions of distinct
// keys hash to different stripes and so run concurrently; only same-key races
// serialize (on the same stripe), which is what preserves the exactly-once
// semantics IsSeen guarantees. 64 keeps collisions rare across the worker pool.
const diskSetShards = 64

// DiskSet provides disk-backed deduplication using LevelDB with internal bloom filter.
// Thread-safe for concurrent access.
type DiskSet struct {
	db *leveldb.DB
	// closeMu guards db's lifecycle: IsSeen/Contains hold RLock for the whole
	// operation; Close holds the exclusive Lock so it can't nil out db while a
	// lookup is in flight.
	closeMu sync.RWMutex
	// shards stripe the new-key insert critical section by key hash so inserts of
	// different keys don't serialize on one global lock — the contention the old
	// single write lock created during the high-discovery early crawl.
	shards  [diskSetShards]sync.Mutex
	hits    atomic.Uint64
	size    atomic.Int64
	path    string
	cleanup bool
}

// shardFor returns the stripe lock for key (FNV-1a over the bytes).
func (s *DiskSet) shardFor(key string) *sync.Mutex {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h%diskSetShards]
}

// Config holds DiskSet configuration.
type Config struct {
	// BasePath is the base directory for disk storage.
	// Empty string uses system temp directory.
	BasePath string

	// Namespace isolates this DiskSet from others in the same BasePath.
	Namespace string

	// Cleanup removes the disk files on Close() if true.
	Cleanup bool
}

// NewDiskSet creates a disk-backed dedup set.
func NewDiskSet(cfg *Config) (*DiskSet, error) {
	if cfg == nil {
		cfg = &Config{Cleanup: true}
	}

	basePath := cfg.BasePath
	if basePath == "" {
		basePath = os.TempDir()
	}

	path := basePath
	if cfg.Namespace != "" {
		path = filepath.Join(basePath, cfg.Namespace)
	}

	opts := &opt.Options{
		Filter:              filter.NewBloomFilter(10), // LevelDB internal bloom (10 bits/key)
		CompactionTableSize: 32 * opt.MiB,
		WriteBuffer:         4 * opt.MiB,
		BlockCacheCapacity:  2 * opt.MiB,
	}

	db, err := leveldb.OpenFile(path, opts)
	if err != nil {
		return nil, fmt.Errorf("open leveldb at %s: %w", path, err)
	}

	return &DiskSet{
		db:      db,
		path:    path,
		cleanup: cfg.Cleanup,
	}, nil
}

// IsSeen returns true if key was seen before. If not seen, it records the key
// and returns false. Exactly one caller observes false for a given new key, even
// under concurrent first-sight — callers rely on that (e.g. addObservedExtension's
// wasNew gate and the size counter).
//
// Locking: the whole operation holds closeMu.RLock (which only excludes Close,
// not other IsSeen calls). The already-seen fast path needs nothing more — Has is
// concurrency-safe. A new key takes its per-key stripe lock and re-checks Has, so
// two racers on the same key serialize and the second sees the first's write.
// Distinct keys hash to different stripes and never contend, so the early-crawl
// new-key flood no longer funnels through a single global write lock.
func (s *DiskSet) IsSeen(key string) bool {
	keyBytes := []byte(key)

	s.closeMu.RLock()
	defer s.closeMu.RUnlock()

	if s.db == nil {
		return true
	}

	// Fast path: already seen — no stripe lock needed.
	if has, err := s.db.Has(keyBytes, nil); err == nil && has {
		s.hits.Add(1)
		return true
	}

	// Slow path: serialize per-key-hash so exactly one caller records a new key.
	shard := s.shardFor(key)
	shard.Lock()
	defer shard.Unlock()

	if has, err := s.db.Has(keyBytes, nil); err == nil && has {
		s.hits.Add(1)
		return true
	}

	_ = s.db.Put(keyBytes, nil, nil)
	s.size.Add(1)
	return false
}

// Contains returns true if key exists (read-only check).
// Does not mark the key as seen if not present.
// Thread-safe: the shared lock guards against Close, LevelDB handles the rest.
func (s *DiskSet) Contains(key string) bool {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.db == nil {
		return false
	}
	has, err := s.db.Has([]byte(key), nil)
	return err == nil && has
}

// Size returns the number of unique keys stored.
func (s *DiskSet) Size() int64 {
	return s.size.Load()
}

// Hits returns the number of duplicate keys detected.
func (s *DiskSet) Hits() uint64 {
	return s.hits.Load()
}

// Close releases resources and optionally removes disk files. It takes the
// exclusive lock so it can't run concurrently with an in-flight IsSeen/Contains
// (which hold the shared lock), making the db = nil store safe.
func (s *DiskSet) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()

	if s.db == nil {
		return nil
	}

	err := s.db.Close()
	s.db = nil

	if s.cleanup && s.path != "" {
		_ = os.RemoveAll(s.path)
	}

	return err
}
