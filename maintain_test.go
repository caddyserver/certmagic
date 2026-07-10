package certmagic

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// failingIssuer is a fake Issuer that always fails, simulating a CA
// challenge validation failure (e.g. because DNS is broken, as in
// caddyserver/caddy#7843). It counts how many times Issue was called so
// tests can assert on attempt cadence.
type failingIssuer struct {
	calls atomic.Int32
	err   error
}

func (fi *failingIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	fi.calls.Add(1)
	return nil, fi.err
}

func (fi *failingIssuer) IssuerKey() string { return "failing_test_issuer" }

// TestQueueRenewalTaskPacesRetriesItself is a regression test for
// caddyserver/caddy#7843: after a transient failure (e.g. a DNS outage)
// prevented renewal, the certificate did not get renewed again even after
// the underlying problem cleared, until the process was restarted.
//
// Root cause: queueRenewalTask used to submit a job to the package-level
// jm that internally looped through doWithRetry's retryIntervals schedule
// for up to maxRetryDuration (30 days) without returning. Because jm.Submit
// silently drops duplicate submissions for a name that is already
// in-flight, every subsequent periodic maintenance tick's call to
// queueRenewalTask for the same certificate was a silent no-op: the only
// thing actually driving retries was the single long-lived job's own
// internal sleep, which could be up to 6 hours between attempts, and,
// depending on scheduling, could appear to simply stop making progress.
//
// This test simulates two consecutive maintenance ticks in quick
// succession for a certificate whose issuer always fails, and asserts:
//  1. The first tick makes exactly one renewal attempt.
//  2. A second tick immediately afterward makes NO additional attempt,
//     because we are intentionally backing off (this is desired -- we
//     don't want to hammer the CA every RenewCheckInterval).
//  3. Once the backoff interval has elapsed, a third tick DOES make
//     another attempt -- proving that renewal attempts are paced by an
//     externally observable, bounded schedule (retryIntervals[0], on the
//     order of a minute) rather than being silently stuck behind a
//     multi-hour-or-longer sleep inside a single dedup-protected job.
func TestQueueRenewalTaskPacesRetriesItself(t *testing.T) {
	const domain = "example.com"
	issuer := &failingIssuer{err: fmt.Errorf("simulated DNS-01 challenge failure")}

	certCache := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{
		Issuers:          []Issuer{issuer},
		Storage:          &FileStorage{Path: t.TempDir()},
		Logger:           defaultTestLogger,
		DisableARI:       true, // keep the renewal-needed check to plain expiration logic
		ReusePrivateKeys: true, // avoid needing a KeySource for a fresh key
		certCache:        certCache,
	}
	cfg.OCSP.DisableStapling = true

	// Build an already-expired self-signed leaf certificate and stash it in
	// storage as the "current" cert resource, so loadCertResourceAnyIssuer
	// finds something to renew.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour), // already expired
	}
	leaf, priv, certPEM := mustIssueTestCertificate(t, tmpl, nil, nil)

	privPEM, err := PEMEncodePrivateKey(priv)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: certPEM,
		PrivateKeyPEM:  privPEM,
		issuerKey:      issuer.IssuerKey(),
	}
	ctx := context.Background()
	if err := cfg.saveCertResource(ctx, issuer, certRes); err != nil {
		t.Fatalf("seeding cert resource in storage: %v", err)
	}

	oldCert := Certificate{
		Names:     []string{domain},
		managed:   true,
		issuerKey: issuer.IssuerKey(),
	}
	oldCert.Leaf = leaf

	jobName := "renew_" + domain
	// Make sure we start from a clean slate in the shared package-level
	// schedule, in case another test left state behind.
	renewalRetrySchedule.clear(jobName)
	t.Cleanup(func() { renewalRetrySchedule.clear(jobName) })

	// --- Tick 1: should make exactly one attempt, then back off. ---
	if err := certCache.queueRenewalTask(ctx, oldCert, cfg); err != nil {
		t.Fatalf("queueRenewalTask (tick 1): %v", err)
	}
	if !waitUntil(time.Second, func() bool { return issuer.calls.Load() == 1 }) {
		t.Fatalf("expected exactly 1 issuance attempt after tick 1, got %d", issuer.calls.Load())
	}
	// Give the job's error-handling path (which calls
	// renewalRetrySchedule.recordFailure) a moment to run after Issue
	// returns, since it happens in the jobManager worker goroutine.
	if !waitUntil(time.Second, func() bool { return !renewalRetrySchedule.readyFor(jobName) }) {
		t.Fatal("expected renewal name to be backing off after a failed attempt")
	}

	// --- Tick 2: fires immediately after tick 1; must NOT attempt again,
	// because we are still within the first backoff interval. This is the
	// crux of the fix: previously it was jm's dedup (silent, unbounded)
	// doing this job; now it's an explicit, bounded backoff check. ---
	if err := certCache.queueRenewalTask(ctx, oldCert, cfg); err != nil {
		t.Fatalf("queueRenewalTask (tick 2): %v", err)
	}
	time.Sleep(50 * time.Millisecond) // give any (unwanted) job a chance to run
	if got := issuer.calls.Load(); got != 1 {
		t.Fatalf("expected still only 1 issuance attempt immediately after tick 2 (should be backing off), got %d", got)
	}

	// --- Simulate the backoff interval elapsing by directly rewinding the
	// recorded schedule (equivalent to waiting retryIntervals[0], which we
	// don't want this test to actually spend real time on). ---
	renewalRetrySchedule.mu.Lock()
	if st, ok := renewalRetrySchedule.state[jobName]; ok {
		st.nextAttempt = time.Now().Add(-time.Millisecond)
	} else {
		t.Fatal("expected backoff state to be recorded for job name")
	}
	renewalRetrySchedule.mu.Unlock()

	// --- Tick 3: backoff has elapsed, so this tick must retry. ---
	if err := certCache.queueRenewalTask(ctx, oldCert, cfg); err != nil {
		t.Fatalf("queueRenewalTask (tick 3): %v", err)
	}
	if !waitUntil(time.Second, func() bool { return issuer.calls.Load() == 2 }) {
		t.Fatalf("expected a second issuance attempt once the backoff interval elapsed, got %d", issuer.calls.Load())
	}
}
