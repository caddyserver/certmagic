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

	siteData, err := testConfig.loadCertResource(ctx, am, domain)
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
	renewLockLease(ctx, mockStorage, "test-lock", 0)
	expected := retryIntervals[0] + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)

	// Test attempt beyond array bounds
	renewLockLease(ctx, mockStorage, "test-lock", 999)
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

	err = renewLockLease(ctx, mockStorage, "test-lock", 0)
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

	err = renewLockLease(ctx, storage, "test-lock", 0)
	testutil.RequireNoError(t, err)
}

func mustJSON(val any) []byte {
	result, err := json.Marshal(val)
	if err != nil {
		panic("marshaling JSON: " + err.Error())
	}
	return result
}
