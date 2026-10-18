package certmagic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFileStorageLockUnreadableLockfile ensures a lock file whose contents
// can't be decoded is eventually treated as stale. A process that crashes
// while updating a lock file (which involves truncating and rewriting it) can
// leave one empty or partially written; treating an unreadable file as a
// permanent error makes the lock unacquirable forever, even though its
// timestamps are unusable and its owner is long gone.
func TestFileStorageLockUnreadableLockfile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{
			name: "truncated",
			// left behind if a process dies between the truncate and the
			// write in updateLockfileFreshness
			content: []byte(`{"created":"2024-01-01T00:00:00Z","upda`),
		},
		{
			name: "zero-filled",
			// some file systems leave a zero-filled file after a crash
			// instead of a truncated one
			content: make([]byte, 98),
		},
		{
			name: "partially decodable",
			// the decoder can populate Created before it trips over a
			// corrupted Updated, so a decodable prefix must not make a
			// corrupt lock file look fresh
			content: []byte(fmt.Sprintf(`{"created":%q,"updated":"not-a-timestamp"}`,
				time.Now().Format(time.RFC3339Nano))),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &FileStorage{Path: t.TempDir()}
			const name = "issue_cert_example.com"

			lockFile := s.lockFilename(name)
			if err := os.MkdirAll(filepath.Dir(lockFile), 0700); err != nil {
				t.Fatalf("creating lock dir: %v", err)
			}
			if err := os.WriteFile(lockFile, tc.content, 0600); err != nil {
				t.Fatalf("writing unreadable lock file: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			if err := s.Lock(ctx, name); err != nil {
				t.Fatalf("Lock() with an unreadable (stale) lock file: %v", err)
			}

			// the unreadable lock file must have been replaced by a valid one
			contents, err := os.ReadFile(lockFile)
			if err != nil {
				t.Fatalf("reading acquired lock file: %v", err)
			}
			var meta lockMeta
			if err := json.Unmarshal(contents, &meta); err != nil {
				t.Fatalf("lock file was not replaced with valid metadata: %v (contents: %q)", err, contents)
			}

			if err := s.Unlock(ctx, name); err != nil {
				t.Fatalf("Unlock(): %v", err)
			}
		})
	}
}
