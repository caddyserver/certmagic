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
//
//go:debug rsa1024min=0
package certmagic

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodeRSAPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 128) // make tests faster; small key size OK for testing
	if err != nil {
		t.Fatal(err)
	}

	// test save
	savedBytes, err := PEMEncodePrivateKey(privateKey)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// test load
	loadedKey, err := PEMDecodePrivateKey(savedBytes)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// test load (should fail)
	_, err = PEMDecodePrivateKey(savedBytes[2:])
	if err == nil {
		t.Error("loading private key should have failed")
	}

	// verify loaded key is correct
	if !privateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

func TestSaveAndLoadECCPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// test save
	savedBytes, err := PEMEncodePrivateKey(privateKey)
	if err != nil {
		t.Fatal("error saving private key:", err)
	}

	// test load
	loadedKey, err := PEMDecodePrivateKey(savedBytes)
	if err != nil {
		t.Error("error loading private key:", err)
	}

	// verify loaded key is correct
	if !privateKeysSame(privateKey, loadedKey) {
		t.Error("Expected key bytes to be the same, but they weren't")
	}
}

// privateKeysSame compares the bytes of a and b and returns true if they are the same.
func privateKeysSame(a, b crypto.PrivateKey) bool {
	return bytes.Equal(privateKeyBytes(a), privateKeyBytes(b))
}

// privateKeyBytes returns the bytes of DER-encoded key.
func privateKeyBytes(key crypto.PrivateKey) []byte {
	var keyBytes []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, _ = x509.MarshalECPrivateKey(key)
	case ed25519.PrivateKey:
		return key
	}
	return keyBytes
}

// testTwoIssuerConfig returns a config with a preferred and a fallback issuer,
// as one would have for failover between two CAs.
func testTwoIssuerConfig(t *testing.T) (*Config, *ACMEIssuer, *ACMEIssuer, *recordingStorage) {
	t.Helper()

	preferred := &ACMEIssuer{CA: "https://preferred.example.com/acme/directory"}
	fallback := &ACMEIssuer{CA: "https://fallback.example.com/acme/directory"}
	storage := &recordingStorage{Storage: &FileStorage{Path: t.TempDir()}}
	cfg := &Config{
		Issuers:            []Issuer{preferred, fallback},
		Storage:            storage,
		RenewalWindowRatio: DefaultRenewalWindowRatio,
		Logger:             defaultTestLogger,
		certCache: &Cache{
			cache:      make(map[string]Certificate),
			cacheIndex: make(map[string][]string),
			logger:     defaultTestLogger,
		},
	}
	preferred.config = cfg
	fallback.config = cfg

	return cfg, preferred, fallback, storage
}

// saveTestCertResource stores a certificate for domain from issuer, valid for
// 90 days from notBefore.
func saveTestCertResource(t *testing.T, cfg *Config, issuer Issuer, domain string, notBefore time.Time) {
	t.Helper()

	err := cfg.saveCertResource(context.Background(), issuer, testIssuedCertResource(t, issuer, domain, notBefore))
	if err != nil {
		t.Fatalf("Expected no error saving cert resource, got: %v", err)
	}
}

// readAssetsOf reports whether storage was asked for any of the certificate
// assets belonging to issuer.
func readAssetsOf(storage *recordingStorage, issuer Issuer, domain string) bool {
	prefix := StorageKeys.CertsSitePrefix(issuer.IssuerKey(), domain)
	for _, call := range storage.calls {
		if call.name != "Load" || len(call.args) == 0 {
			continue
		}
		if key, ok := call.args[0].(string); ok && strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func TestLoadCertResourceAnyIssuerPrefersNewestByDefault(t *testing.T) {
	cfg, preferred, fallback, storage := testTwoIssuerConfig(t)
	const domain = "example.com"
	now := time.Now()

	saveTestCertResource(t, cfg, preferred, domain, now.Add(-24*time.Hour))
	saveTestCertResource(t, cfg, fallback, domain, now)

	storage.calls = nil
	certRes, err := cfg.loadCertResourceAnyIssuer(context.Background(), domain, cfg.Storage)
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}

	if certRes.issuerKey != fallback.IssuerKey() {
		t.Errorf("Expected the newest certificate, from %s, got one from %s", fallback.IssuerKey(), certRes.issuerKey)
	}
	if !readAssetsOf(storage, fallback, domain) {
		t.Error("Expected all issuers to be read when LoadFirstUsableCert is not set")
	}
}

func TestLoadFirstUsableCertSkipsLaterIssuers(t *testing.T) {
	cfg, preferred, fallback, storage := testTwoIssuerConfig(t)
	cfg.LoadFirstUsableCert = true
	const domain = "example.com"
	now := time.Now()

	// the fallback's certificate is newer, so it is the one that would win
	// without LoadFirstUsableCert
	saveTestCertResource(t, cfg, preferred, domain, now.Add(-24*time.Hour))
	saveTestCertResource(t, cfg, fallback, domain, now)

	storage.calls = nil
	certRes, err := cfg.loadCertResourceAnyIssuer(context.Background(), domain, cfg.Storage)
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}

	if certRes.issuerKey != preferred.IssuerKey() {
		t.Errorf("Expected the certificate from %s, got one from %s", preferred.IssuerKey(), certRes.issuerKey)
	}
	if readAssetsOf(storage, fallback, domain) {
		t.Error("Expected the fallback issuer's assets not to be read")
	}
}

// The preferred certificate has to be one we would serve as-is for its issuer
// to end the search; otherwise a newer certificate from a later issuer is
// still the better one to serve.
func TestLoadFirstUsableCertLooksPastCertNeedingRenewal(t *testing.T) {
	cfg, preferred, fallback, storage := testTwoIssuerConfig(t)
	cfg.LoadFirstUsableCert = true
	const domain = "example.com"
	now := time.Now()

	saveTestCertResource(t, cfg, preferred, domain, now.Add(-85*24*time.Hour))
	saveTestCertResource(t, cfg, fallback, domain, now)

	storage.calls = nil
	certRes, err := cfg.loadCertResourceAnyIssuer(context.Background(), domain, cfg.Storage)
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}

	if certRes.issuerKey != fallback.IssuerKey() {
		t.Errorf("Expected the newest certificate, from %s, got one from %s", fallback.IssuerKey(), certRes.issuerKey)
	}
}

// A certificate obtained during failover lives under an issuer that is not the
// preferred one, and still has to be found.
func TestLoadFirstUsableCertFindsFailoverCert(t *testing.T) {
	cfg, _, fallback, _ := testTwoIssuerConfig(t)
	cfg.LoadFirstUsableCert = true
	const domain = "example.com"

	saveTestCertResource(t, cfg, fallback, domain, time.Now())

	certRes, err := cfg.loadCertResourceAnyIssuer(context.Background(), domain, cfg.Storage)
	if err != nil {
		t.Fatalf("Expected no error loading cert resource, got: %v", err)
	}

	if certRes.issuerKey != fallback.IssuerKey() {
		t.Errorf("Expected the certificate from %s, got one from %s", fallback.IssuerKey(), certRes.issuerKey)
	}
}
