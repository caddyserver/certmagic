package certmagic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

type ariWrappedIssuer struct{ Issuer }

func TestRenewCertARIReplaces(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wrapped      bool
		differentCA  bool
		disableARI   bool
		testCA       bool
		attempts     int
		wantReplaces bool
	}{
		{name: "direct", wantReplaces: true},
		{name: "wrapped", wrapped: true, wantReplaces: true},
		{name: "direct different CA", differentCA: true},
		{name: "wrapped different CA", wrapped: true, differentCA: true},
		{name: "ARI disabled", wrapped: true, disableARI: true},
		{name: "test CA", wrapped: true, testCA: true},
		{name: "second retry", wrapped: true, attempts: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tc.attempts != 0 {
				ctx = context.WithValue(ctx, AttemptsCtxKey, &tc.attempts)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			ca := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
				NotBefore: now.Add(-100 * 24 * time.Hour), NotAfter: now.Add(100 * 24 * time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				SubjectKeyId: []byte{1, 2, 3},
			}
			old := &x509.Certificate{
				SerialNumber: big.NewInt(2), DNSNames: []string{"example.test"},
				Subject:   pkix.Name{CommonName: "example.test"},
				NotBefore: now.Add(-89 * 24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
			}
			oldDER, err := x509.CreateCertificate(rand.Reader, old, ca, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			old, err = x509.ParseCertificate(oldDER)
			if err != nil {
				t.Fatal(err)
			}
			keyPEM, err := PEMEncodePrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}

			orders := make(chan string, 4)
			var certMu sync.Mutex
			var certPEM []byte
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Replay-Nonce", "test-nonce")
				w.Header().Set("Content-Type", "application/json")
				var payload []byte
				if r.Method == http.MethodPost {
					var jws struct{ Payload string }
					if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
						t.Error(err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					var err error
					payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
					if err != nil {
						t.Error(err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
				}
				switch r.URL.Path {
				case "/directory":
					json.NewEncoder(w).Encode(map[string]string{
						"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/new-account", "newOrder": server.URL + "/new-order",
					})
				case "/nonce":
					w.WriteHeader(http.StatusOK)
				case "/new-account":
					w.Header().Set("Location", server.URL+"/account/1")
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]string{"status": "valid", "orders": server.URL + "/orders"})
				case "/new-order":
					var order struct{ Replaces string }
					if err := json.Unmarshal(payload, &order); err != nil {
						t.Error(err)
					}
					orders <- order.Replaces
					w.Header().Set("Location", server.URL+"/order/1")
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]any{"status": "ready", "authorizations": []string{}, "finalize": server.URL + "/finalize"})
				case "/finalize":
					var request struct{ CSR string }
					if err := json.Unmarshal(payload, &request); err != nil {
						t.Error(err)
						return
					}
					csrDER, err := base64.RawURLEncoding.DecodeString(request.CSR)
					if err != nil {
						t.Error(err)
						return
					}
					csr, err := x509.ParseCertificateRequest(csrDER)
					if err != nil {
						t.Error(err)
						return
					}
					leaf := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour)}
					der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
					if err != nil {
						t.Error(err)
						return
					}
					certMu.Lock()
					certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
					certMu.Unlock()
					json.NewEncoder(w).Encode(map[string]string{"status": "valid", "certificate": server.URL + "/certificate"})
				case "/order/1":
					json.NewEncoder(w).Encode(map[string]string{"status": "valid", "certificate": server.URL + "/certificate"})
				case "/certificate":
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					certMu.Lock()
					defer certMu.Unlock()
					w.Write(certPEM)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			cfg := newWithCache(new(Cache), Config{Storage: &FileStorage{Path: t.TempDir()}, Logger: zap.NewNop(), DisableARI: tc.disableARI})
			am := NewACMEIssuer(cfg, ACMEIssuer{CA: server.URL + "/directory", Email: "test@example.test", Agreed: true, Logger: zap.NewNop()})
			if tc.testCA {
				am.TestCA = am.CA
			}
			var issuer Issuer = am
			if tc.wrapped {
				issuer = &ariWrappedIssuer{Issuer: am}
			}
			cfg.Issuers = []Issuer{issuer}
			previousCA := am.CA
			if tc.differentCA {
				previousCA = server.URL + "/other-directory"
			}
			err = cfg.saveCertResource(ctx, issuer, CertificateResource{
				SANs: []string{"example.test"}, PrivateKeyPEM: keyPEM,
				CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldDER}),
				IssuerData:     mustJSON(acme.Certificate{CA: previousCA}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.RenewCertSync(ctx, "example.test", false); err != nil {
				t.Fatal(err)
			}
			var replaces string
			select {
			case replaces = <-orders:
			default:
				t.Fatal("no ACME newOrder request")
			}
			want := ""
			if tc.wantReplaces {
				want = base64.RawURLEncoding.EncodeToString(old.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(old.SerialNumber.Bytes())
			}
			if replaces != want {
				t.Errorf("newOrder replaces = %q, want %q", replaces, want)
			}
			stored, err := cfg.loadCertResource(ctx, issuer, "example.test", cfg.Storage)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.X509KeyPair(stored.CertificatePEM, stored.PrivateKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if leaf.SerialNumber.Cmp(big.NewInt(3)) != 0 {
				t.Fatalf("renewed certificate not saved: serial = %v", leaf.SerialNumber)
			}
		})
	}
}
