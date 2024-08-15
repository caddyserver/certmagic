// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

type storageEntry struct {
	i KeyInfo
	d []byte
}

// memoryStorage is a Storage implemention that exists only in memory
// it is intended for testing and one-time-deploys where no persistence is needed
type memoryStorage struct {
	m  map[string]storageEntry
	mu sync.RWMutex

	kmu *keyMutex
}

func NewMemoryStorage() Storage {
	return &memoryStorage{
		m:   map[string]storageEntry{},
		kmu: newKeyMutex(),
	}
}

// Exists returns true if key exists in s.
func (s *memoryStorage) Exists(ctx context.Context, key string) bool {
	ans, err := s.List(ctx, key, true)
	if err != nil {
		return false
	}
	return len(ans) != 0
}

// Store saves value at key.
func (s *memoryStorage) Store(_ context.Context, key string, value []byte) error {
	s.m[key] = storageEntry{
		i: KeyInfo{
			Key:        key,
			Modified:   time.Now(),
			Size:       int64(len(value)),
			IsTerminal: true,
		},
		d: value,
	}
	return nil
}

// Load retrieves the value at key.
func (s *memoryStorage) Load(_ context.Context, key string) ([]byte, error) {
	val, ok := s.m[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return val.d, nil
}

// Delete deletes the value at key.
func (s *memoryStorage) Delete(_ context.Context, key string) error {
	delete(s.m, key)
	return nil
}

// List returns all keys that match prefix.
func (s *memoryStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var keyList []string

	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	// adapted from https://github.com/pberkel/caddy-storage-redis/blob/main/storage.go#L369
	// Iterate over each child key
	for _, k := range keys {
		// Directory keys will have a "/" suffix
		trimmedKey := strings.TrimSuffix(k, "/")
		// Reconstruct the full path of child key
		fullPathKey := path.Join(prefix, trimmedKey)
		// If current key is a directory
		if recursive && k != trimmedKey {
			// Recursively traverse all child directories
			childKeys, err := s.List(ctx, fullPathKey, recursive)
			if err != nil {
				return keyList, err
			}
			keyList = append(keyList, childKeys...)
		} else {
			keyList = append(keyList, fullPathKey)
		}
	}

	return keys, nil
}

// Stat returns information about key.
func (s *memoryStorage) Stat(_ context.Context, key string) (KeyInfo, error) {
	val, ok := s.m[key]
	if !ok {
		return KeyInfo{}, os.ErrNotExist
	}
	return val.i, nil
}

// Lock obtains a lock named by the given name. It blocks
// until the lock can be obtained or an error is returned.
func (s *memoryStorage) Lock(ctx context.Context, name string) error {
	return s.kmu.LockKey(ctx, name)
}

// Unlock releases the lock for name.
func (s *memoryStorage) Unlock(_ context.Context, name string) error {
	return s.kmu.UnlockKey(name)
}

func (s *memoryStorage) String() string {
	return "memoryStorage"
}

// Interface guard
var _ Storage = (*memoryStorage)(nil)

type keyMutex struct {
	m  map[string]*semaphore.Weighted
	mu sync.Mutex
}

func newKeyMutex() *keyMutex {
	return &keyMutex{
		m: map[string]*semaphore.Weighted{},
	}
}

func (km *keyMutex) LockKey(ctx context.Context, id string) error {
	select {
	case <-ctx.Done():
		// as a special case, caddy allows for the cancelled context to be used for a trylock.
		if km.mutex(id).TryAcquire(1) {
			return nil
		}
		return ctx.Err()
	default:
		return km.mutex(id).Acquire(ctx, 1)
	}
}

// Releases the lock associated with the specified ID.
func (km *keyMutex) UnlockKey(id string) error {
	km.mutex(id).Release(1)
	return nil
}

func (km *keyMutex) mutex(id string) *semaphore.Weighted {
	km.mu.Lock()
	defer km.mu.Unlock()
	val, ok := km.m[id]
	if !ok {
		val = semaphore.NewWeighted(1)
		km.m[id] = val
	}
	return val
}
