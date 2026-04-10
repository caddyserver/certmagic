package certmagic

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/ocsp"
)

const certWithOCSPServer = `-----BEGIN CERTIFICATE-----
MIIBhDCCASqgAwIBAgICIAAwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMHVGVzdCBD
QTAeFw0yMzAxMDExMjAwMDBaFw0yMzAyMDExMjAwMDBaMAAwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASKHiP246N+KqJ8vC3USQ/iYbpPP0vGB10R5eqx/beVRQhb
V/JSDzfy5dcwq0Nigd1pW38UoIkMi6wqWcq3YVT0o4GBMH8wDAYDVR0TAQH/BAIw
ADAfBgNVHSMEGDAWgBT4SjfmxJPgtGvBLh254h0YFnl3sjAgBgNVHREEGTAXghVP
Q1NQIFRlc3QgQ2VydGlmaWNhdGUwLAYIKwYBBQUHAQEEIDAeMBwGCCsGAQUFBzAB
hhBvY3NwLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIB58v3YIMZT2V63A
yT6Pu/4BPAzYQdwHMt20cr3EH8UvAiEA6HrQYMzhSR20wAFyJhopcRkEaoWkO1ia
lwi/iTExLvc=
-----END CERTIFICATE-----`

const certWithoutOCSPServer = `-----BEGIN CERTIFICATE-----
MIIBUzCB+6ADAgECAgIgADAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdUZXN0IENB
MB4XDTIzMDEwMTEyMDAwMFoXDTIzMDIwMTEyMDAwMFowADBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABIoeI/bjo34qony8LdRJD+Jhuk8/S8YHXRHl6rH9t5VFCFtX
8lIPN/Ll1zCrQ2KB3WlbfxSgiQyLrCpZyrdhVPSjUzBRMAwGA1UdEwEB/wQCMAAw
HwYDVR0jBBgwFoAU+Eo35sST4LRrwS4dueIdGBZ5d7IwIAYDVR0RBBkwF4IVT0NT
UCBUZXN0IENlcnRpZmljYXRlMAoGCCqGSM49BAMCA0cAMEQCIED/dOQDxqQuguR+
MCyJvc5q6umr2kvVZi8/FJnb6Js/AiANZw75cefKnpRALcsRmIRFaN1fL3OQB4On
9ChkZWfqaw==
-----END CERTIFICATE-----`

// certKey is the private key for both certWithOCSPServer and
// certWithoutOCSPServer.
const certKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINnVcgrSNh4HlThWlZpegq14M8G/p9NVDtdVjZrseUGLoAoGCCqGSM49
AwEHoUQDQgAEih4j9uOjfiqifLwt1EkP4mG6Tz9LxgddEeXqsf23lUUIW1fyUg83
8uXXMKtDYoHdaVt/FKCJDIusKlnKt2FU9A==
-----END EC PRIVATE KEY-----`

// caCert is the issuing certificate for certWithOCSPServer and
// certWithoutOCSPServer.
const caCert = `-----BEGIN CERTIFICATE-----
MIIBXDCCAQGgAwIBAgICEAAwCgYIKoZIzj0EAwIwADAeFw0yMzAxMDExMjAwMDBa
Fw0yMzAyMDExMjAwMDBaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASdKexS
or/aeazDM57UHhAXrCkJxUeF2BWf0lZYCRxc3f0GdrEsVvjJW8+/E06eAzDCGSdM
/08Nvun1nb6AmAlto2swaTAOBgNVHQ8BAf8EBAMCAgQwEwYDVR0lBAwwCgYIKwYB
BQUHAwkwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU+Eo35sST4LRrwS4dueId
GBZ5d7IwEgYDVR0RBAswCYIHVGVzdCBDQTAKBggqhkjOPQQDAgNJADBGAiEAg9Dn
GgrOdPS24IB3zTIc0AJN847vtDpQzL5srXMjdSsCIQC2rVnJUrtE4+C3O/xLIEtT
IZ3GS4ii0f9W5zBT/FtkfA==
-----END CERTIFICATE-----`

const caKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDJ59ptjq3MzILH4zn5IKoH1sYn+zrUeq2kD8+DD2x+OoAoGCCqGSM49
AwEHoUQDQgAEnSnsUqK/2nmswzOe1B4QF6wpCcVHhdgVn9JWWAkcXN39BnaxLFb4
yVvPvxNOngMwwhknTP9PDb7p9Z2+gJgJbQ==
-----END EC PRIVATE KEY-----`

func TestStapleOCSP(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}

	t.Run("disabled", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		config := OCSPConfig{DisableStapling: true}
		err := stapleOCSP(ctx, config, storage, &cert, nil)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if cert.Certificate.OCSPStaple != nil {
			t.Error("unexpected OCSP staple")
		}
	})
	t.Run("no OCSP server", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithoutOCSPServer, certKey)
		err := stapleOCSP(ctx, OCSPConfig{}, storage, &cert, nil)
		if !errors.Is(err, ErrNoOCSPServerSpecified) {
			t.Error("expected ErrNoOCSPServerSpecified in error", err)
		}
	})

	// Start an OCSP responder test server.
	responses := make(map[string][]byte)
	responder := startOCSPResponder(t, responses)
	t.Cleanup(responder.Close)

	ca := mustMakeCertificate(t, caCert, caKey)

	// The certWithOCSPServer certificate has a bogus ocsp.example.com endpoint.
	// Use the ResponderOverrides option to point to the test server instead.
	config := OCSPConfig{
		ResponderOverrides: map[string]string{
			"ocsp.example.com": responder.URL,
		},
	}

	t.Run("ok", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		tpl := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.Leaf.SerialNumber,
		}
		r, err := ocsp.CreateResponse(
			ca.Leaf, ca.Leaf, tpl, ca.PrivateKey.(crypto.Signer))
		if err != nil {
			t.Fatal("couldn't create OCSP response", err)
		}
		responses[cert.Leaf.SerialNumber.String()] = r

		bundle := []byte(certWithOCSPServer + "\n" + caCert)
		err = stapleOCSP(ctx, config, storage, &cert, bundle)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if !bytes.Equal(cert.Certificate.OCSPStaple, r) {
			t.Error("expected OCSP response to be stapled to certificate")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		tpl := ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: cert.Leaf.SerialNumber,
		}
		r, err := ocsp.CreateResponse(
			ca.Leaf, ca.Leaf, tpl, ca.PrivateKey.(crypto.Signer))
		if err != nil {
			t.Fatal("couldn't create OCSP response", err)
		}
		responses[cert.Leaf.SerialNumber.String()] = r

		bundle := []byte(certWithOCSPServer + "\n" + caCert)
		err = stapleOCSP(ctx, config, storage, &cert, bundle)
		if err != nil {
			t.Error("unexpected error:", err)
		} else if cert.Certificate.OCSPStaple != nil {
			t.Error("revoked OCSP response should not be stapled")
		}
	})
	t.Run("no issuing cert", func(t *testing.T) {
		cert := mustMakeCertificate(t, certWithOCSPServer, certKey)
		err := stapleOCSP(ctx, config, storage, &cert, nil)
		expected := "no OCSP stapling for [ocsp test certificate]: " +
			"no URL to issuing certificate"
		if err == nil || err.Error() != expected {
			t.Errorf("expected error %q but got %q", expected, err)
		}
	})
}

func mustMakeCertificate(t *testing.T, cert, key string) Certificate {
	t.Helper()
	c, err := makeCertificate([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal("couldn't make certificate:", err)
	}
	return c
}

func startOCSPResponder(
	t *testing.T, responses map[string][]byte,
) *httptest.Server {
	h := func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/ocsp-request" {
			t.Errorf("unexpected request Content-Type %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		request, err := ocsp.ParseRequest(b)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(responses[request.SerialNumber.String()])
	}
	return httptest.NewServer(http.HandlerFunc(h))
}
