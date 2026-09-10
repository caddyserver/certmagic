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
	"errors"
	"io/fs"

	"go.uber.org/zap"
)

// cachedStorage returns the Storage to use for a certificate's assets when
// they are being loaded in order to serve the certificate. If a LocalCache
// is configured, loads are answered from it whenever it has the asset.
func (cfg *Config) cachedStorage() Storage {
	return cfg.certStorage(true)
}

// groundTruthStorage returns the Storage to use for a certificate's assets
// when the caller has to observe what the rest of the cluster sees, such as
// when renewing, issuing, or reloading a certificate that another instance
// renewed. Loads go to Storage, but they still refresh the LocalCache with
// what they read, so a stale local copy doesn't stay stale.
func (cfg *Config) groundTruthStorage() Storage {
	return cfg.certStorage(false)
}

// certStorage returns the Storage to use for a certificate's assets: its
// certificate, private key, and metadata files, and its OCSP staple. If a
// LocalCache is configured, the returned Storage keeps it up to date with
// everything it loads, stores, and deletes. Prefer calling cachedStorage or
// groundTruthStorage, which name the two ways to use it.
func (cfg *Config) certStorage(readLocal bool) Storage {
	if cfg.LocalCache == nil {
		return cfg.Storage
	}
	return localCacheStorage{
		Storage:   cfg.Storage,
		local:     cfg.LocalCache,
		readLocal: readLocal,
		logger:    cfg.Logger,
	}
}

// errUnusableCert means a certificate's assets were all loaded but do not make
// a usable certificate: they don't parse, or the certificate and private key
// don't belong together. Read through a LocalCache, that is what a write torn
// between its files looks like, so reading them from Storage instead is worth
// one try; other errors -- assets that are absent, or storage that is
// unavailable -- say nothing about the local cache.
var errUnusableCert = errors.New("unusable certificate")

// localCacheStorage is a Storage that keeps a node-local copy of the items
// it reads from and writes to the embedded, authoritative Storage. Only
// Load, Store, and Delete are cached; everything else -- notably Exists,
// List, and locking -- goes straight to the authoritative Storage, since
// those are how instances coordinate with each other.
//
// The local cache is only an optimization, so its errors are logged rather
// than returned.
type localCacheStorage struct {
	Storage
	local     Storage
	readLocal bool
	logger    *zap.Logger
}

func (ls localCacheStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if ls.readLocal {
		value, err := ls.local.Load(ctx, key)
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			ls.logger.Warn("loading from local cache; falling back to storage",
				zap.String("key", key),
				zap.Error(err))
		}
	}
	value, err := ls.Storage.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	ls.cacheLocally(ctx, key, value)
	return value, nil
}

func (ls localCacheStorage) Store(ctx context.Context, key string, value []byte) error {
	err := ls.Storage.Store(ctx, key, value)
	if err != nil {
		return err
	}
	ls.cacheLocally(ctx, key, value)
	return nil
}

// Delete evicts key from the local cache even if deleting it from the
// authoritative Storage failed, so that we don't keep serving something
// that was meant to be deleted.
func (ls localCacheStorage) Delete(ctx context.Context, key string) error {
	err := ls.Storage.Delete(ctx, key)
	localErr := ls.local.Delete(ctx, key)
	if localErr != nil && !errors.Is(localErr, fs.ErrNotExist) {
		ls.logger.Warn("deleting from local cache",
			zap.String("key", key),
			zap.Error(localErr))
	}
	return err
}

func (ls localCacheStorage) cacheLocally(ctx context.Context, key string, value []byte) {
	err := ls.local.Store(ctx, key, value)
	if err != nil {
		ls.logger.Warn("storing in local cache",
			zap.String("key", key),
			zap.Error(err))
	}
}

var _ Storage = localCacheStorage{}
