//go:build go1.27

package certmagic

import (
	"crypto/mldsa"
	"testing"
)

func TestMLDSAKeyGen(t *testing.T) {
	kg := StandardKeyGenerator{KeyType: MLDSA44}
	priv, err := kg.GenerateKey()
	if err != nil {
		t.Fatalf("expected nil error when generating ML-DSA 44 key: %v", err)
	}

	if priv == nil {
		t.Fatalf("expected non-nil ML-DSA 44 key")
	}

	key := priv.(*mldsa.PrivateKey)
	if key.PublicKey().Parameters() != mldsa.MLDSA44() {
		t.Fatalf("expected ML-DSA 44 parameter set")
	}
}
