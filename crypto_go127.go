//go:build go1.27

package certmagic

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"fmt"
)

const (
	MLDSA44 = KeyType("mldsa44")
	MLDSA65 = KeyType("mldsa65")
	MLDSA87 = KeyType("mldsa87")
)

func maybePQCEncode(key crypto.PrivateKey) ([]byte, string, error) {
	switch key.(type) {
	case *mldsa.PrivateKey:
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		return encoded, "MLDSA", err
	}

	return nil, "", fmt.Errorf("unsupported key type: %T", key)
}

func maybePQCDecode(key crypto.PrivateKey) crypto.Signer {
	switch key.(type) {
	case *mldsa.PrivateKey:
		return key.(crypto.Signer)
	}

	return nil
}

func maybePQCKeyGen(kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case MLDSA44:
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case MLDSA65:
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case MLDSA87:
		return mldsa.GenerateKey(mldsa.MLDSA87())
	}

	return nil, nil
}
