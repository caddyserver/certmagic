package certmagic_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/require"
)

func TestFileStorageStoreLoad(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	require.NoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	err = s.Store(ctx, "foo", []byte("bar"))
	require.NoError(t, err)
	dat, err := s.Load(ctx, "foo")
	require.NoError(t, err)
	require.EqualValues(t, dat, []byte("bar"))
}

func TestFileStorageStoreLoadRace(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	require.NoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	a := bytes.Repeat([]byte("a"), 4096*1024)
	b := bytes.Repeat([]byte("b"), 4096*1024)
	err = s.Store(ctx, "foo", a)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		err := s.Store(ctx, "foo", b)
		require.NoError(t, err)
		close(done)
	}()
	dat, err := s.Load(ctx, "foo")
	<-done
	require.NoError(t, err)
	require.Len(t, dat, 4096*8)
}

func TestFileStorageWriteLock(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	require.NoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	// cctx is a cancelled ctx. so if we can't immediately get the lock, it will fail
	cctx, cn := context.WithCancel(ctx)
	cn()
	// should success
	err = s.Lock(cctx, "foo")
	require.NoError(t, err)
	// should fail
	err = s.Lock(cctx, "foo")
	require.Error(t, err)

	err = s.Unlock(cctx, "foo")
	require.NoError(t, err)
	// shouldn't fail
	err = s.Lock(cctx, "foo")
	require.NoError(t, err)

	err = s.Unlock(cctx, "foo")
	require.NoError(t, err)
}
