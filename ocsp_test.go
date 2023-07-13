package certmagic

import (
	"context"
	"errors"
	"testing"
)

// certWithoutOCSPServer is a minimal self-signed certificate.
const certWithoutOCSPServer = `-----BEGIN CERTIFICATE-----
MIIBEDCBtqADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ0p
7FKiv9p5rMMzntQeEBesKQnFR4XYFZ/SVlgJHFzd/QZ2sSxW+Mlbz78TTp4DMMIZ
J0z/Tw2+6fWdvoCYCW2jHTAbMBkGA1UdEQEB/wQPMA2CC2V4YW1wbGUuY29tMAoG
CCqGSM49BAMCA0kAMEYCIQDMbDvbJ/SXgRoblhBmt80F5iAyuOA0v20x0gpImK01
oQIhANxdGJPvBaz0wOVBCSpd5jHbPxPxwqKZYJEes6y7eM+I
-----END CERTIFICATE-----`

const privateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDJ59ptjq3MzILH4zn5IKoH1sYn+zrUeq2kD8+DD2x+OoAoGCCqGSM49
AwEHoUQDQgAEnSnsUqK/2nmswzOe1B4QF6wpCcVHhdgVn9JWWAkcXN39BnaxLFb4
yVvPvxNOngMwwhknTP9PDb7p9Z2+gJgJbQ==
-----END EC PRIVATE KEY-----`

func TestOCSPServerNotSpecified(t *testing.T) {
	var config OCSPConfig
	storage := &FileStorage{Path: t.TempDir()}

	pemCert := []byte(certWithoutOCSPServer)
	cert, err := makeCertificate(pemCert, []byte(privateKey))
	if err != nil {
		t.Fatal("couldn't make certificate:", err)
	}

	err = stapleOCSP(context.Background(), config, storage, &cert, pemCert)
	if !errors.Is(err, ErrNoOCSPServerSpecified) {
		t.Error("expected ErrOCSPServerNotSpecified in error", err)
	}
}
