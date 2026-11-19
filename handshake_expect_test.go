// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package certmagic

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// TestGetCertificateExpectsNamesBeforeManage is a regression test for
// the case the original #8431 fix did not cover: Caddy starts serving
// before it calls Manage, so a handshake can arrive before ManageAsync
// has registered any load to wait for. ExpectNames is called first
// (as Caddy now does before starting its listeners), the handshake
// starts before any Manage call, and only then does ManageAsync run.
// The handshake must wait for that load and be served the certificate.
func TestGetCertificateExpectsNamesBeforeManage(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		managed    string // name passed to ExpectNames and ManageAsync
		serverName string // SNI sent by the client
	}{
		{name: "exact name", managed: "example.test", serverName: "example.test"},
		{name: "wildcard", managed: "*.example.test", serverName: "s1.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &delayedLoadStorage{Storage: &FileStorage{Path: t.TempDir()}}
			cfg, am := managedLoadTestConfig(storage)

			// a previous run already issued and stored a valid cert
			res := testIssuedCertResource(t, am, tc.managed, time.Now().Add(-time.Hour))
			if err := cfg.saveCertResource(ctx, am, res); err != nil {
				t.Fatalf("storing cert resource: %v", err)
			}

			// storage reads become slow: the startup window
			const delay = 400 * time.Millisecond
			storage.delay.Store(int64(delay))

			// Caddy announces the names it is about to manage before
			// it starts serving; no load has started yet
			cfg.ExpectNames([]string{tc.managed})

			// a handshake arrives and must block on the announcement,
			// before any Manage call is made
			hello := &tls.ClientHelloInfo{ServerName: tc.serverName, Conn: testConn{}}
			type result struct {
				cert *tls.Certificate
				err  error
			}
			resultChan := make(chan result, 1)
			start := time.Now()
			go func() {
				cert, err := cfg.GetCertificate(hello)
				resultChan <- result{cert, err}
			}()

			// give the handshake time to reach the wait; it must still
			// be waiting, not failed, even though Manage has not run
			time.Sleep(75 * time.Millisecond)
			select {
			case res := <-resultChan:
				t.Fatalf("handshake finished before Manage was called: cert=%v err=%v", res.cert, res.err)
			default:
			}

			// only now does certificate management begin, as in
			// Caddy's automatic HTTPS phase 2; it must adopt the
			// announcement the handshake is waiting on
			if err := cfg.ManageAsync(ctx, []string{tc.managed}); err != nil {
				t.Fatalf("ManageAsync: %v", err)
			}

			select {
			case res := <-resultChan:
				elapsed := time.Since(start)
				if res.err != nil {
					t.Fatalf("expected handshake waiting on an expected name to succeed once Manage loaded the cert, got: %v", res.err)
				}
				if res.cert == nil || res.cert.Leaf == nil {
					t.Fatalf("expected a certificate, got: %v", res.cert)
				}
				if elapsed < delay {
					t.Errorf("expected handshake to wait for the managed load (at least %v), but it returned after %v", delay, elapsed)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("handshake did not finish after ManageAsync loaded the certificate")
			}
		})
	}
}

// TestGetCertificateExpectationNeverFulfilled verifies that a
// handshake for a name that was announced with ExpectNames but never
// managed does not hang: it waits at most the (shortened) wait budget
// and then falls through to the usual "no certificate available"
// error.
func TestGetCertificateExpectationNeverFulfilled(t *testing.T) {
	oldTimeout := managedLoadWaitTimeout
	managedLoadWaitTimeout = 300 * time.Millisecond
	defer func() { managedLoadWaitTimeout = oldTimeout }()

	cfg, _ := managedLoadTestConfig(&FileStorage{Path: t.TempDir()})
	cfg.ExpectNames([]string{"example.test"})

	hello := &tls.ClientHelloInfo{ServerName: "example.test", Conn: testConn{}}
	start := time.Now()
	_, err := cfg.GetCertificate(hello)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "no certificate available") {
		t.Fatalf("expected 'no certificate available' error for a name that was never managed, got: %v", err)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("handshake returned after %v; it should have waited out the %v budget for the expected load first", elapsed, managedLoadWaitTimeout)
	}
	if elapsed > 10*time.Second {
		t.Errorf("handshake took %v for a name that was never managed; it must not hang", elapsed)
	}
}

// TestManagedLoadOverlappingLoads verifies that overlapping loads for
// the same name are reference-counted: a waiter must not wake when
// the first load finishes, only when the last one does, and ending a
// load twice must not count twice.
func TestManagedLoadOverlappingLoads(t *testing.T) {
	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c}

	end1 := cfg.beginManagedLoad("example.test")
	end2 := cfg.beginManagedLoad("example.test")

	waitedChan := make(chan bool, 1)
	go func() {
		waited, err := cfg.waitForManagedLoad(context.Background(), "example.test")
		if err != nil {
			t.Errorf("waitForManagedLoad: %v", err)
		}
		waitedChan <- waited
	}()

	// let the waiter snapshot the registry and block on the channel
	time.Sleep(50 * time.Millisecond)

	end1()
	end1() // idempotent: must not count as the second load finishing

	// the waiter must still be waiting for the second load
	time.Sleep(150 * time.Millisecond)
	select {
	case <-waitedChan:
		t.Fatal("waiter woke after only the first of two overlapping loads finished")
	default:
	}

	end2()

	select {
	case waited := <-waitedChan:
		if !waited {
			t.Error("expected waitForManagedLoad to report that it waited")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not wake after the last overlapping load finished")
	}
}

// TestWaitForManagedLoadSingleBudget verifies that the exact name and
// its wildcard variant share one wait budget: with both entries
// pending forever, the total wait is about one budget, not two.
func TestWaitForManagedLoadSingleBudget(t *testing.T) {
	oldTimeout := managedLoadWaitTimeout
	managedLoadWaitTimeout = 300 * time.Millisecond
	defer func() { managedLoadWaitTimeout = oldTimeout }()

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c}
	cfg.ExpectNames([]string{"s1.example.test", "*.example.test"})

	start := time.Now()
	waited, err := cfg.waitForManagedLoad(context.Background(), "s1.example.test")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("waitForManagedLoad: %v", err)
	}
	if !waited {
		t.Fatal("expected waitForManagedLoad to report that it waited")
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("waited only %v; expected about one budget (%v)", elapsed, managedLoadWaitTimeout)
	}
	if elapsed > 450*time.Millisecond {
		t.Errorf("waited %v; exact and wildcard candidates must share one budget (%v), not one budget each", elapsed, managedLoadWaitTimeout)
	}
}

// TestExpectNamesIdempotentAndAdopted verifies that ExpectNames keeps
// a single entry per name, and that a later load adopts that entry's
// channel instead of replacing it, so early waiters are woken by the
// load they were waiting for.
func TestExpectNamesIdempotentAndAdopted(t *testing.T) {
	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c}

	cfg.ExpectNames([]string{"example.test"})
	before := c.managedLoadChans([]string{"example.test"})
	if len(before) != 1 {
		t.Fatalf("expected 1 wait channel after ExpectNames, got %d", len(before))
	}

	cfg.ExpectNames([]string{"example.test"})
	after := c.managedLoadChans([]string{"example.test"})
	if len(after) != 1 || after[0] != before[0] {
		t.Fatal("second ExpectNames call must be a no-op keeping the same channel")
	}

	end := cfg.beginManagedLoad("example.test")
	adopted := c.managedLoadChans([]string{"example.test"})
	if len(adopted) != 1 || adopted[0] != before[0] {
		t.Fatal("beginManagedLoad must adopt the expected entry's channel, not replace it")
	}

	end()
	if chans := c.managedLoadChans([]string{"example.test"}); len(chans) != 0 {
		t.Fatalf("expected the entry to be removed once the adopted load finished, got %d channels", len(chans))
	}
	select {
	case <-before[0]:
	default:
		t.Fatal("expected the adopted entry's channel to be closed when the load finished")
	}
}
