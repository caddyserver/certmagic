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
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/zerossl"
	"github.com/mholt/acmez/v2/acme"
	"go.uber.org/zap"
)

// NewZeroSSLIssuer returns a ZeroSSL issuer with default values filled in
// for empty fields in the template.
func NewZeroSSLIssuer(cfg *Config, template ZeroSSLIssuer) *ZeroSSLIssuer {
	if cfg == nil {
		panic("cannot make valid ZeroSSLIssuer without an associated CertMagic config")
	}
	template.config = cfg
	template.logger = defaultLogger.Named("zerossl")
	return &template
}

// ZeroSSLIssuer can get certificates from ZeroSSL's API. (To use ZeroSSL's ACME
// endpoint, use the ACMEIssuer instead.) Note that use of the API is restricted
// by payment tier.
type ZeroSSLIssuer struct {
	// The API key (or "access key") for using the ZeroSSL API.
	APIKey string

	// How many days the certificate should be valid for.
	ValidityDays int

	// The host to bind to when opening a listener for
	// verifying domain names (or IPs).
	ListenHost string

	// If HTTP is forwarded from port 80, specify the
	// forwarded port here.
	AltHTTPPort int

	// To use CNAME validation instead of HTTP
	// validation, set this field.
	CNAMEValidation *DNSManager

	config *Config
	logger *zap.Logger
}

// Issue obtains a certificate for the given csr.
func (iss *ZeroSSLIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	client := iss.getClient()

	identifiers := namesFromCSR(csr)
	logger := iss.logger.With(zap.Strings("identifiers", identifiers))

	logger.Info("creating certificate")

	cert, err := client.CreateCertificate(ctx, csr, iss.ValidityDays)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %v", err)
	}

	logger = logger.With(zap.String("cert_id", cert.ID))
	logger.Info("created certificate")

	defer func(certID string) {
		if err != nil {
			err := client.CancelCertificate(context.WithoutCancel(ctx), certID)
			if err == nil {
				logger.Info("canceled certificate")
			} else {
				logger.Error("unable to cancel certificate", zap.Error(err))
			}
		}
	}(cert.ID)

	var verificationMethod zerossl.VerificationMethod

	if iss.CNAMEValidation == nil {
		verificationMethod = zerossl.HTTPVerification
		logger = logger.With(zap.String("verification_method", string(verificationMethod)))

		httpVerifier := &httpSolver{
			address: net.JoinHostPort(iss.ListenHost, strconv.Itoa(iss.getHTTPPort())),
			handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				if !strings.HasPrefix(req.URL.Path, zerosslValidationPathPrefix) {
					return
				}

				validation, ok := cert.Validation.OtherMethods[req.Host]
				if !ok {
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				// ensure URL matches
				validationURL, err := url.Parse(validation.FileValidationURLHTTP)
				if err != nil {
					logger.Error("got invalid URL from CA",
						zap.String("file_validation_url", validation.FileValidationURLHTTP),
						zap.Error(err))
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}
				if req.URL.Path != validationURL.Path {
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				logger.Info("served HTTP validation file")

				fmt.Fprint(rw, strings.Join(validation.FileValidationContent, "\n"))
			}),
		}

		distSolver := distributedSolver{
			storage:                iss.config.Storage,
			storageKeyIssuerPrefix: "zerossl",
			solver:                 httpVerifier,
		}

		if err = distSolver.Present(ctx, acme.Challenge{}); err != nil {
			return nil, fmt.Errorf("presenting token for verification: %v", err)
		}
		defer distSolver.CleanUp(ctx, acme.Challenge{})
	} else {
		verificationMethod = zerossl.CNAMEVerification
		logger = logger.With(zap.String("verification_method", string(verificationMethod)))

		// create the CNAME record(s)
		records := make(map[string]zoneRecord, len(cert.Validation.OtherMethods))
		for name, verifyInfo := range cert.Validation.OtherMethods {
			zr, err := iss.CNAMEValidation.createRecord(ctx, verifyInfo.CnameValidationP1, "CNAME", verifyInfo.CnameValidationP2)
			if err != nil {
				return nil, fmt.Errorf("creating CNAME record: %v", err)
			}
			defer func(name string, zr zoneRecord) {
				if err := iss.CNAMEValidation.cleanUpRecord(ctx, zr); err != nil {
					logger.Warn("cleaning up temporary validation record failed",
						zap.String("dns_name", name),
						zap.Error(err))
				}
			}(name, zr)
			records[name] = zr
		}

		// wait for them to propagate
		for name, zr := range records {
			if err := iss.CNAMEValidation.wait(ctx, zr); err != nil {
				// allow it, since the CA will ultimately decide, but definitely log it
				logger.Warn("failed CNAME record propagation check", zap.String("domain", name), zap.Error(err))
			}
		}
	}

	logger.Info("validating identifiers")

	cert, err = client.VerifyIdentifiers(ctx, cert.ID, verificationMethod, nil)
	if err != nil {
		return nil, fmt.Errorf("verifying identifiers: %v", err)
	}

	switch cert.Status {
	case "pending_validation":
		logger.Info("validations succeeded; waiting for certificate to be issued")

		cert, err = iss.waitForCertToBeIssued(ctx, client, cert)
		if err != nil {
			return nil, fmt.Errorf("waiting for certificate to be issued: %v", err)
		}
	case "issued":
		logger.Info("validations succeeded; downloading certificate bundle")
	default:
		return nil, fmt.Errorf("unexpected certificate status: %s", cert.Status)
	}

	bundle, err := client.DownloadCertificate(ctx, cert.ID, false)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate: %v", err)
	}

	logger.Info("successfully downloaded issued certificate")

	return &IssuedCertificate{
		Certificate: []byte(bundle.CertificateCrt + bundle.CABundleCrt),
		Metadata:    cert,
	}, nil
}

func (*ZeroSSLIssuer) waitForCertToBeIssued(ctx context.Context, client zerossl.Client, cert zerossl.CertificateObject) (zerossl.CertificateObject, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return cert, ctx.Err()
		case <-ticker.C:
			var err error
			cert, err = client.GetCertificate(ctx, cert.ID)
			if err != nil {
				return cert, err
			}
			if cert.Status == "issued" {
				return cert, nil
			}
			if cert.Status != "pending_validation" {
				return cert, fmt.Errorf("unexpected certificate status: %s", cert.Status)
			}
		}
	}
}

func (iss *ZeroSSLIssuer) getClient() zerossl.Client {
	return zerossl.Client{AccessKey: iss.APIKey}
}

func (iss *ZeroSSLIssuer) getHTTPPort() int {
	useHTTPPort := HTTPChallengePort
	if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
		useHTTPPort = HTTPPort
	}
	if iss.AltHTTPPort > 0 {
		useHTTPPort = iss.AltHTTPPort
	}
	return useHTTPPort
}

// IssuerKey returns the unique issuer key for ZeroSSL.
func (iss *ZeroSSLIssuer) IssuerKey() string {
	return "zerossl"
}

// Revoke revokes the given certificate. Only do this if there is a security or trust
// concern with the certificate.
func (iss *ZeroSSLIssuer) Revoke(ctx context.Context, cert CertificateResource, reason int) error {
	r := zerossl.UnspecifiedReason
	switch reason {
	case acme.ReasonKeyCompromise:
		r = zerossl.KeyCompromise
	case acme.ReasonAffiliationChanged:
		r = zerossl.AffiliationChanged
	case acme.ReasonSuperseded:
		r = zerossl.Superseded
	case acme.ReasonCessationOfOperation:
		r = zerossl.CessationOfOperation
	default:
		return fmt.Errorf("unsupported reason: %d", reason)
	}
	return iss.getClient().RevokeCertificate(ctx, cert.IssuerData.(zerossl.CertificateObject).ID, r)
}

const (
	zerosslAPIBase              = "https://" + zerossl.BaseURL + "/acme"
	zerosslValidationPathPrefix = "/.well-known/pki-validation/"
)

// Interface guards
var (
	_ Issuer  = (*ZeroSSLIssuer)(nil)
	_ Revoker = (*ZeroSSLIssuer)(nil)
)
