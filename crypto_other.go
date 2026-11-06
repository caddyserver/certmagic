//go:build !go1.27

package certmagic

import (
	"crypto"
	"fmt"
)

func maybePQCEncode(key crypto.PrivateKey) ([]byte, string, error) {
	return nil, "", fmt.Errorf("unsupported key type: %T", key)
}

func maybePQCDeocde(key crypto.PrivateKey) crypto.Signer {
	return nil
}

func maybePQCKeyGen(kt KeyType) (crypto.PrivateKey, error) {
	return nil, nil
}
