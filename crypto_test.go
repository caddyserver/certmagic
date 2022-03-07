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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
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
