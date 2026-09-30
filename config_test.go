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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/certmagic/internal/testutil"
	"github.com/mholt/acmez/v3/acme"
)

func TestSaveCertResource(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := testConfig.loadCertResource(ctx, am, domain, testConfig.groundTruthStorage())
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\t"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\n"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte(" "), []byte(""))
	if !reflect.DeepEqual(cert, siteData) {
		t.Errorf("Expected '%+v' to match '%+v'\n%s\n%s", cert.IssuerData, siteData.IssuerData, string(cert.IssuerData), string(siteData.IssuerData))
	}
}

type mockStorageWithLease struct {
	*FileStorage
	renewCalled  bool
	renewError   error
	lastLockKey  string
	lastDuration time.Duration
}

func (m *mockStorageWithLease) RenewLockLease(ctx context.Context, lockKey string, leaseDuration time.Duration) error {
	m.renewCalled = true
	m.lastLockKey = lockKey
	m.lastDuration = leaseDuration
	return m.renewError
}

func TestRenewLockLeaseDuration(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	// Test attempt 0
	cfg := &Config{Logger: defaultTestLogger}
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	expected := retryIntervals[0] + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)

	// Test attempt beyond array bounds
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 999)
	expected = maxRetryDuration + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)
}

// Test that lease renewal works when storage supports it
func TestRenewLockLeaseWithInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	testutil.RequireNoError(t, err)

	testutil.RequireEqual(t, true, mockStorage.renewCalled)
}

// Test that no error occurs when storage doesn't support lease renewal
func TestRenewLockLeaseWithoutInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	storage := &FileStorage{Path: tmpDir}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, storage, "test-lock", 0)
	testutil.RequireNoError(t, err)
}

func mustJSON(val any) []byte {
	result, err := json.Marshal(val)
	if err != nil {
		panic("marshaling JSON: " + err.Error())
	}
	return result
}

// fakeIssuer is a minimal Issuer implementation for tests. It records whether
// it was asked to issue a certificate and returns a canned certificate so that
// obtain/renew flows can complete without contacting a real CA. The obtain and
// renew code paths do not parse the returned certificate, so placeholder PEM
// contents are sufficient (matching the convention used elsewhere in this file).
type fakeIssuer struct {
	key     string
	certPEM []byte
	issued  bool
}

func (f *fakeIssuer) IssuerKey() string { return f.key }

func (f *fakeIssuer) Issue(_ context.Context, _ *x509.CertificateRequest) (*IssuedCertificate, error) {
	f.issued = true
	return &IssuedCertificate{Certificate: f.certPEM}, nil
}

// TestRenewCertObtainsWhenIssuerChanged is a regression test for
// https://github.com/caddyserver/caddy/issues/6732. When the issuer is changed
// between config reloads, the previously-obtained certificate remains stored
// under the OLD issuer's storage path. Because renewal reuses the stored
// certificate resource, a naive renewal looks for the resource under the
// currently-configured (new) issuer only, never finds it, and retries in vain
// until the certificate expires. Renewal must instead fall back to obtaining a
// fresh certificate from the currently-configured issuer.
func TestRenewCertObtainsWhenIssuerChanged(t *testing.T) {
	ctx := context.Background()
	domain := "example.com"

	storageDir := "./_testdata_renew_issuer_change"
	storage := &FileStorage{Path: storageDir}
	defer os.RemoveAll(storageDir)

	oldIssuer := &fakeIssuer{key: "old-issuer"}
	newIssuer := &fakeIssuer{key: "new-issuer", certPEM: []byte("new issuer certificate")}

	// Seed storage with the existing certificate resource under the OLD issuer's
	// key only -- exactly the on-disk state after the issuer is changed.
	seedCfg := newWithCache(new(Cache), Config{
		Issuers: []Issuer{oldIssuer},
		Storage: storage,
		Logger:  defaultTestLogger,
	})
	err := seedCfg.saveCertResource(ctx, oldIssuer, CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: []byte("old issuer certificate"),
		PrivateKeyPEM:  []byte("old issuer private key"),
		IssuerData:     mustJSON(acme.Certificate{URL: "https://old.example/cert"}),
		issuerKey:      oldIssuer.IssuerKey(),
	})
	if err != nil {
		t.Fatalf("seeding old certificate resource: %v", err)
	}

	// Config is reloaded with a DIFFERENT issuer; the old certificate is still
	// managed/cached, so renewal is eventually triggered for it. Use the
	// synchronous (interactive) path so a failure surfaces immediately instead
	// of being retried until the max retry duration.
	cfg := newWithCache(new(Cache), Config{
		Issuers: []Issuer{newIssuer},
		Storage: storage,
		Logger:  defaultTestLogger,
	})

	// Precondition: the new issuer has no resources in storage yet, so a naive
	// renewal would fail to load the certificate resource.
	if cfg.storageHasCertResources(ctx, newIssuer, domain) {
		t.Fatalf("precondition failed: new issuer unexpectedly already has certificate resources in storage")
	}

	if err := cfg.RenewCertSync(ctx, domain, false); err != nil {
		t.Fatalf("RenewCertSync after issuer change should obtain a new certificate, got error: %v", err)
	}

	if !newIssuer.issued {
		t.Error("expected the new issuer to issue a certificate (obtain fallback), but Issue was never called")
	}
	if !cfg.storageHasCertResources(ctx, newIssuer, domain) {
		t.Errorf("expected certificate resources to be stored under the new issuer %q after renewal", newIssuer.IssuerKey())
	}
}
