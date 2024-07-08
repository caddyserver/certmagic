package certmagic_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/caddyserver/certmagic/internal/testutil"
)

func TestFileStorageStoreLoad(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	err = s.Store(ctx, "foo", []byte("bar"))
	testutil.RequireNoError(t, err)
	dat, err := s.Load(ctx, "foo")
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, dat, []byte("bar"))
}

func TestFileStorageStoreLoadRace(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	a := bytes.Repeat([]byte("a"), 4096*1024)
	b := bytes.Repeat([]byte("b"), 4096*1024)
	err = s.Store(ctx, "foo", a)
	testutil.RequireNoError(t, err)
	done := make(chan struct{})
	go func() {
		err := s.Store(ctx, "foo", b)
		testutil.RequireNoError(t, err)
		close(done)
	}()
	dat, err := s.Load(ctx, "foo")
	<-done
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, 4096*1024, len(dat))
}

func TestFileStorageWriteLock(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	// cctx is a cancelled ctx. so if we can't immediately get the lock, it will fail
	cctx, cn := context.WithCancel(ctx)
	cn()
	// should success
	err = s.Lock(cctx, "foo")
	testutil.RequireNoError(t, err)
	// should fail
	err = s.Lock(cctx, "foo")
	testutil.RequireError(t, err)

	err = s.Unlock(cctx, "foo")
	testutil.RequireNoError(t, err)
	// shouldn't fail
	err = s.Lock(cctx, "foo")
	testutil.RequireNoError(t, err)

	err = s.Unlock(cctx, "foo")
	testutil.RequireNoError(t, err)
}
