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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestShouldEmit(t *testing.T) {
	noop := func(context.Context, string, map[string]any) error { return nil }

	for _, tc := range []struct {
		name    string
		cfg     Config
		expects bool
	}{
		{
			name:    "no handler at all",
			cfg:     Config{},
			expects: false,
		},
		{
			name:    "handler, but no way to ask about subscribers",
			cfg:     Config{OnEvent: noop},
			expects: true,
		},
		{
			name:    "handler says it has a subscriber",
			cfg:     Config{OnEvent: noop, ShouldEmitFunc: func(string) bool { return true }},
			expects: true,
		},
		{
			name:    "handler says it has no subscriber",
			cfg:     Config{OnEvent: noop, ShouldEmitFunc: func(string) bool { return false }},
			expects: false,
		},
		{
			name:    "no handler outweighs a subscriber claim",
			cfg:     Config{ShouldEmitFunc: func(string) bool { return true }},
			expects: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.shouldEmit("tls_get_certificate"); got != tc.expects {
				t.Errorf("shouldEmit() = %v, want %v", got, tc.expects)
			}
		})
	}
}

// The event name has to reach ShouldEmitFunc, or a caller cannot
// distinguish the handshake event from the rest.
func TestShouldEmitReceivesEventName(t *testing.T) {
	var asked []string
	cfg := Config{
		OnEvent:        func(context.Context, string, map[string]any) error { return nil },
		ShouldEmitFunc: func(name string) bool { asked = append(asked, name); return false },
	}

	cfg.shouldEmit("cert_obtained")
	cfg.shouldEmit("tls_get_certificate")

	if len(asked) != 2 || asked[0] != "cert_obtained" || asked[1] != "tls_get_certificate" {
		t.Errorf("ShouldEmitFunc was asked about %v", asked)
	}
}

func testCertificate(tb testing.TB) tls.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type testConn struct{ net.Conn }

func (testConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51234} }
func (testConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443} }

func testClientHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        "example.com",
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.X25519},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		Conn:              testConn{},
	}
}

// handshakeConfig returns a Config serving one cached certificate for
// example.com, with the given event hooks installed.
func handshakeConfig(tb testing.TB, onEvent func(context.Context, string, map[string]any) error, hasSubs func(string) bool) *Config {
	tb.Helper()

	var cfg *Config
	cache := NewCache(CacheOptions{
		GetConfigForCert: func(Certificate) (*Config, error) { return cfg, nil },
		Logger:           zap.NewNop(),
	})
	tb.Cleanup(cache.Stop)

	cfg = New(cache, Config{
		Storage:        &FileStorage{Path: tb.TempDir()},
		Logger:         zap.NewNop(),
		OnEvent:        onEvent,
		ShouldEmitFunc: hasSubs,
	})
	if _, err := cfg.CacheUnmanagedTLSCertificate(context.Background(), testCertificate(tb), nil); err != nil {
		tb.Fatal(err)
	}
	return cfg
}

func TestGetCertificateSkipsUnobservedEvent(t *testing.T) {
	var emitted []string
	record := func(_ context.Context, name string, _ map[string]any) error {
		emitted = append(emitted, name)
		return nil
	}

	t.Run("subscribed", func(t *testing.T) {
		cfg := handshakeConfig(t, record, func(string) bool { return true })
		emitted = nil // drop what caching the certificate emitted
		if _, err := cfg.GetCertificate(testClientHello()); err != nil {
			t.Fatal(err)
		}
		if len(emitted) != 1 || emitted[0] != "tls_get_certificate" {
			t.Errorf("emitted %v, want [tls_get_certificate]", emitted)
		}
	})

	t.Run("not subscribed", func(t *testing.T) {
		cfg := handshakeConfig(t, record, func(string) bool { return false })
		emitted = nil // drop what caching the certificate emitted
		if _, err := cfg.GetCertificate(testClientHello()); err != nil {
			t.Fatal(err)
		}
		if len(emitted) != 0 {
			t.Errorf("emitted %v, want nothing", emitted)
		}
	})

	t.Run("no way to ask", func(t *testing.T) {
		cfg := handshakeConfig(t, record, nil)
		emitted = nil // drop what caching the certificate emitted
		if _, err := cfg.GetCertificate(testClientHello()); err != nil {
			t.Fatal(err)
		}
		if len(emitted) != 1 {
			t.Errorf("emitted %v, want [tls_get_certificate]", emitted)
		}
	})
}

// A subscribed handler can still abort the handshake.
func TestGetCertificateHonorsEventAbort(t *testing.T) {
	abort := errors.New("nope")
	cfg := handshakeConfig(t,
		func(context.Context, string, map[string]any) error { return abort },
		func(string) bool { return true })

	if _, err := cfg.GetCertificate(testClientHello()); !errors.Is(err, abort) {
		t.Errorf("got error %v, want it to wrap %v", err, abort)
	}
}

// What a handshake pays for tls_get_certificate when something is subscribed
// to it: the data is built and dispatched, as before.
func BenchmarkGetCertificateEventSubscribed(b *testing.B) {
	cfg := handshakeConfig(b,
		func(context.Context, string, map[string]any) error { return nil },
		func(string) bool { return true })
	benchmarkGetCertificate(b, cfg)
}

// The common case: a handler is installed for other events, but nothing is
// subscribed to this one.
func BenchmarkGetCertificateEventUnsubscribed(b *testing.B) {
	cfg := handshakeConfig(b,
		func(context.Context, string, map[string]any) error { return nil },
		func(string) bool { return false })
	benchmarkGetCertificate(b, cfg)
}

func benchmarkGetCertificate(b *testing.B, cfg *Config) {
	b.Helper()
	hello := testClientHello()
	if _, err := cfg.GetCertificate(hello); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cfg.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}

// The predicate is written against a particular OnEvent, so a config that
// brings its own handler must not inherit Default's predicate: it knows
// nothing about that handler and would silence it.
func TestShouldEmitFuncInheritedWithOnEvent(t *testing.T) {
	defaultOnEvent := func(context.Context, string, map[string]any) error { return nil }
	defaultPredicate := func(string) bool { return false }

	oldOnEvent, oldPredicate := Default.OnEvent, Default.ShouldEmitFunc
	Default.OnEvent, Default.ShouldEmitFunc = defaultOnEvent, defaultPredicate
	t.Cleanup(func() { Default.OnEvent, Default.ShouldEmitFunc = oldOnEvent, oldPredicate })

	newConfig := func(tb testing.TB, cfg Config) *Config {
		tb.Helper()
		var out *Config
		cache := NewCache(CacheOptions{
			GetConfigForCert: func(Certificate) (*Config, error) { return out, nil },
			Logger:           zap.NewNop(),
		})
		tb.Cleanup(cache.Stop)
		cfg.Storage = &FileStorage{Path: tb.TempDir()}
		cfg.Logger = zap.NewNop()
		out = New(cache, cfg)
		return out
	}

	t.Run("own handler does not inherit the predicate", func(t *testing.T) {
		cfg := newConfig(t, Config{
			OnEvent: func(context.Context, string, map[string]any) error { return nil },
		})
		if cfg.ShouldEmitFunc != nil {
			t.Error("inherited Default's predicate onto a caller's own OnEvent")
		}
		if !cfg.shouldEmit("tls_get_certificate") {
			t.Error("caller's handler is being silenced")
		}
	})

	t.Run("inherited handler brings its predicate", func(t *testing.T) {
		cfg := newConfig(t, Config{})
		if cfg.ShouldEmitFunc == nil {
			t.Fatal("did not inherit Default's predicate alongside Default's OnEvent")
		}
		if cfg.shouldEmit("tls_get_certificate") {
			t.Error("Default's predicate is not being consulted")
		}
	})

	t.Run("own predicate is kept", func(t *testing.T) {
		cfg := newConfig(t, Config{ShouldEmitFunc: func(string) bool { return true }})
		if !cfg.shouldEmit("tls_get_certificate") {
			t.Error("caller's own predicate was replaced")
		}
	})
}
