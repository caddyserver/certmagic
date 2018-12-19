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
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// FileStorage facilitates forming file paths derived from a root
// directory. It is used to get file paths in a consistent,
// cross-platform way or persisting ACME assets on the file system.
type FileStorage struct {
	Path string

	lockWaiters   map[string]fileLockWaiter
	lockWaitersMu sync.Mutex
}

// Exists returns true if key exists in fs.
func (fs *FileStorage) Exists(key string) bool {
	_, err := os.Stat(fs.Filename(key))
	return !os.IsNotExist(err)
}

// Store saves value at key.
func (fs *FileStorage) Store(key string, value []byte) error {
	filename := fs.Filename(key)
	err := os.MkdirAll(filepath.Dir(filename), 0700)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, value, 0600)
}

// Load retrieves the value at key.
func (fs *FileStorage) Load(key string) ([]byte, error) {
	contents, err := ioutil.ReadFile(fs.Filename(key))
	if os.IsNotExist(err) {
		return nil, ErrNotExist(err)
	}
	return contents, nil
}

// Delete deletes the value at key.
func (fs *FileStorage) Delete(key string) error {
	err := os.Remove(fs.Filename(key))
	if os.IsNotExist(err) {
		return ErrNotExist(err)
	}
	return err
}

// List returns all keys that match prefix.
func (fs *FileStorage) List(prefix string, recursive bool) ([]string, error) {
	var keys []string
	walkPrefix := fs.Filename(prefix)

	err := filepath.Walk(walkPrefix, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("%s: file info is nil", fpath)
		}
		if fpath == walkPrefix {
			return nil
		}

		suffix, err := filepath.Rel(walkPrefix, fpath)
		if err != nil {
			return fmt.Errorf("%s: could not make path relative: %v", fpath, err)
		}
		keys = append(keys, path.Join(prefix, suffix))

		if !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})

	return keys, err
}

// Stat returns information about key.
func (fs *FileStorage) Stat(key string) (KeyInfo, error) {
	fi, err := os.Stat(fs.Filename(key))
	if os.IsNotExist(err) {
		return KeyInfo{}, ErrNotExist(err)
	}
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		Key:        key,
		Modified:   fi.ModTime(),
		Size:       fi.Size(),
		IsTerminal: !fi.IsDir(),
	}, nil
}

// Filename returns the key as a path on the file
// system prefixed by fs.Path.
func (fs *FileStorage) Filename(key string) string {
	return filepath.Join(fs.Path, filepath.FromSlash(key))
}

// Lock obtains a lock named by the given key. It blocks
// until the lock can be obtained or an error is returned.
func (fs *FileStorage) Lock(key string) error {
	// see if this process is already waiting for the same lock;
	// if so, we might as well borrow the same waiter
	fs.lockWaitersMu.Lock()
	if fs.lockWaiters == nil {
		fs.lockWaiters = make(map[string]fileLockWaiter)
	}
	fw, ok := fs.lockWaiters[key]
	fs.lockWaitersMu.Unlock()
	if ok {
		// this process is already waiting for the
		// lock; wait on the same wait chan to avoid
		// more polling than is necessary
		fw.wait()
	}

	return fs.getLock(key)
}

func (fs *FileStorage) getLock(key string) error {
	start := time.Now()
	filename := fs.lockFilename(key)

	for {
		err := createLockfile(filename)
		if err == nil {
			// got the lock, yay
			return nil
		}
		if !os.IsExist(err) {
			// unexpected error
			return fmt.Errorf("creating lock file: %v", err)
		}

		// lock file already exists

		info, err := os.Stat(filename)
		switch {
		case os.IsNotExist(err):
			// must have just been removed; try again to create it
			continue

		case err != nil:
			// unexpected error
			return fmt.Errorf("accessing lock file: %v", err)

		case fileLockIsStale(info):
			// lock file is stale - delete it and try again to create one
			log.Printf("[INFO][%s] Lock for '%s' is stale; removing then retrying: %s",
				fs, key, filename)
			removeLockfile(filename)
			continue

		case time.Since(start) > staleLockDuration*2:
			// should never happen, hopefully
			return fmt.Errorf("possible deadlock: %s passed trying to obtain lock for %s",
				time.Since(start), key)

		default:
			// lock file exists and is not stale; wait on it,
			// and allow other threads in this process to share
			// our wait logic so we don't excessively poll
			fs.lockWaitersMu.Lock()
			fw, ok := fs.lockWaiters[key]
			if ok {
				// waiter already exists for this lock; use
				// it, then try again to obtain the lock
				fs.lockWaitersMu.Unlock()
				fw.wait()
				continue
			}
			waitChan := make(chan struct{})
			fs.lockWaiters[key] = waitChan
			fs.lockWaitersMu.Unlock()

			// poll until the lock is available; ours should be
			// the only thread in this process polling the disk
			for time.Since(start) < staleLockDuration {
				info, err := os.Stat(filename)
				if err != nil || fileLockIsStale(info) {
					fs.lockWaitersMu.Lock()
					close(waitChan)
					delete(fs.lockWaiters, key)
					fs.lockWaitersMu.Unlock()
					break
				}
				time.Sleep(fileLockPollInterval)
			}
		}
	}
}

// Unlock releases the lock for name.
func (fs *FileStorage) Unlock(key string) error {
	return removeLockfile(fs.lockFilename(key))
}

func (fs *FileStorage) String() string {
	return "FileStorage:" + fs.Path
}

func (fs *FileStorage) lockFilename(key string) string {
	return filepath.Join(fs.lockDir(), StorageKeys.safe(key)+".lock")
}

func (fs *FileStorage) lockDir() string {
	return filepath.Join(fs.Path, "locks")
}

// fileLockWaiter is used to block until a
// lock might be available; it is used solely
// to reduce excessive polling of the file
// system.
type fileLockWaiter <-chan struct{}

// wait blocks until w is closed, or
// until the lock being waited upon
// would have become stale.
func (w fileLockWaiter) wait() {
	select {
	case <-time.Tick(staleLockDuration):
	case <-w:
	}
}

func fileLockIsStale(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	return time.Since(info.ModTime()) > staleLockDuration
}

// createLockfile atomically creates the lockfile
// identified by filename. A successfully created
// lockfile should be removed with removeLockfile.
func createLockfile(filename string) error {
	err := atomicallyCreateFile(filename)
	if err == nil {
		// if the app crashes in removeLockfile(), there is a
		// small chance the .unlock file is left behind; it's
		// safe to simply remove it as it's a guard against
		// double removal of the .lock file.
		os.Remove(filename + ".unlock")
	}
	return err
}

// removeLockfile atomically removes filename,
// which must be a lockfile created by createLockfile.
// See discussion in PR #7 for more background:
// https://github.com/mholt/certmagic/pull/7
func removeLockfile(filename string) error {
	unlockFilename := filename + ".unlock"
	if err := atomicallyCreateFile(unlockFilename); err != nil {
		if os.IsExist(err) {
			// another process is handling the unlocking
			return nil
		}
		return err
	}
	defer os.Remove(unlockFilename)
	return os.Remove(filename)
}

// atomicallyCreateFile atomically creates the file
// identified by filename if it doesn't already exist.
func atomicallyCreateFile(filename string) error {
	// no need to check this, we only really care about the file creation error
	os.MkdirAll(filepath.Dir(filename), 0700)
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL, 0644)
	if err == nil {
		f.Close()
	}
	return err
}

// homeDir returns the best guess of the current user's home
// directory from environment variables. If unknown, "." (the
// current directory) is returned instead.
func homeDir() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" {
		home = "."
	}
	return home
}

func dataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "certmagic")
}

// staleLockDuration is the length of time
// before considering a lock to be stale.
const staleLockDuration = 2 * time.Hour

// fileLockPollInterval is how frequently
// to check the existence of a lock file
const fileLockPollInterval = 1 * time.Second

var _ Storage = (*FileStorage)(nil)
