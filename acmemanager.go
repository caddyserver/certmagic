package certmagic

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/dns01"
)

// ACMEManager gets certificates using ACME. It implements the PreChecker,
// Issuer, and Revoker interfaces.
//
// It is NOT VALID to use an ACMEManager without calling NewACMEManager().
// It fills in default values from DefaultACME as well as setting up
// internal state that is necessary for valid use. Always call
// NewACMEManager() to get a valid ACMEManager value.
type ACMEManager struct {
	// The endpoint of the directory for the ACME
	// CA we are to use
	CA string

	// TestCA is the endpoint of the directory for
	// an ACME CA to use to test domain validation,
	// but any certs obtained from this CA are
	// discarded
	TestCA string

	// The email address to use when creating or
	// selecting an existing ACME server account
	Email string

	// Set to true if agreed to the CA's
	// subscriber agreement
	Agreed bool

	// An optional external account to associate
	// with this ACME account
	ExternalAccount *ExternalAccountBinding

	// Disable all HTTP challenges
	DisableHTTPChallenge bool

	// Disable all TLS-ALPN challenges
	DisableTLSALPNChallenge bool

	// The host (ONLY the host, not port) to listen
	// on if necessary to start a listener to solve
	// an ACME challenge
	ListenHost string

	// The alternate port to use for the ACME HTTP
	// challenge; if non-empty, this port will be
	// used instead of HTTPChallengePort to spin up
	// a listener for the HTTP challenge
	AltHTTPPort int

	// The alternate port to use for the ACME
	// TLS-ALPN challenge; the system must forward
	// TLSALPNChallengePort to this port for
	// challenge to succeed
	AltTLSALPNPort int

	// The DNS provider to use when solving the
	// ACME DNS challenge
	DNSProvider challenge.Provider

	// The ChallengeOption struct to provide
	// custom precheck or name resolution options
	// for DNS challenge validation and execution
	DNSChallengeOption dns01.ChallengeOption

	// TrustedRoots specifies a pool of root CA
	// certificates to trust when communicating
	// over a network to a peer.
	TrustedRoots *x509.CertPool

	// The maximum amount of time to allow for
	// obtaining a certificate. If empty, the
	// default from the underlying lego lib is
	// used. If set, it must not be too low so
	// as to cancel orders too early, running
	// the risk of rate limiting.
	CertObtainTimeout time.Duration

	config *Config
}

// NewACMEManager constructs a valid ACMEManager based on a template
// configuration; any empty values will be filled in by defaults in
// DefaultACME. The associated config is also required.
//
// Typically, you'll create the Config first, then call NewACMEManager(),
// then assign the return value to the Issuer/Revoker fields of the Config.
func NewACMEManager(cfg *Config, template ACMEManager) *ACMEManager {
	if cfg == nil {
		panic("cannot make valid ACMEManager without an associated CertMagic config")
	}
	if template.CA == "" {
		template.CA = DefaultACME.CA
	}
	if template.TestCA == "" && template.CA == DefaultACME.CA {
		// only use the default test CA if the CA is also
		// the default CA; no point in testing against
		// Let's Encrypt's staging server if we are not
		// using their production server too
		template.TestCA = DefaultACME.TestCA
	}
	if template.Email == "" {
		template.Email = DefaultACME.Email
	}
	if !template.Agreed {
		template.Agreed = DefaultACME.Agreed
	}
	if !template.DisableHTTPChallenge {
		template.DisableHTTPChallenge = DefaultACME.DisableHTTPChallenge
	}
	if !template.DisableTLSALPNChallenge {
		template.DisableTLSALPNChallenge = DefaultACME.DisableTLSALPNChallenge
	}
	if template.ListenHost == "" {
		template.ListenHost = DefaultACME.ListenHost
	}
	if template.AltHTTPPort == 0 {
		template.AltHTTPPort = DefaultACME.AltHTTPPort
	}
	if template.AltTLSALPNPort == 0 {
		template.AltTLSALPNPort = DefaultACME.AltTLSALPNPort
	}
	if template.DNSProvider == nil {
		template.DNSProvider = DefaultACME.DNSProvider
	}
	if template.DNSChallengeOption == nil {
		template.DNSChallengeOption = DefaultACME.DNSChallengeOption
	}
	if template.TrustedRoots == nil {
		template.TrustedRoots = DefaultACME.TrustedRoots
	}
	if template.CertObtainTimeout == 0 {
		template.CertObtainTimeout = DefaultACME.CertObtainTimeout
	}
	template.config = cfg
	return &template
}

// IssuerKey returns the unique issuer key for the
// confgured CA endpoint.
func (am *ACMEManager) IssuerKey() string {
	return am.issuerKey(am.CA)
}

func (am *ACMEManager) issuerKey(ca string) string {
	key := ca
	if caURL, err := url.Parse(key); err == nil {
		key = caURL.Host
		if caURL.Path != "" {
			// keep the path, but make sure it's a single
			// component (i.e. no forward slashes, and for
			// good measure, no backward slashes either)
			const hyphen = "-"
			repl := strings.NewReplacer(
				"/", hyphen,
				"\\", hyphen,
			)
			path := strings.Trim(repl.Replace(caURL.Path), hyphen)
			if path != "" {
				key += hyphen + path
			}
		}
	}
	return key
}

// PreCheck performs a few simple checks before obtaining or
// renewing a certificate with ACME, and returns whether this
// batch is eligible for certificates if using Let's Encrypt.
// It also ensures that an email address is available.
func (am *ACMEManager) PreCheck(names []string, interactive bool) error {
	letsEncrypt := strings.Contains(am.CA, "api.letsencrypt.org")
	if letsEncrypt {
		for _, name := range names {
			if !SubjectQualifiesForPublicCert(name) {
				return fmt.Errorf("subject does not qualify for a Let's Encrypt certificate: %s", name)
			}
		}
	}
	return am.getEmail(interactive)
}

// Issue implements the Issuer interface. It obtains a certificate for the given csr using
// the ACME configuration am.
func (am *ACMEManager) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	if am.config == nil {
		panic("missing config pointer (must use NewACMEManager)")
	}

	var isRetry bool
	if attempts, ok := ctx.Value(AttemptsCtxKey).(*int); ok {
		isRetry = *attempts > 0
	}

	cert, usedTestCA, err := am.doIssue(ctx, csr, isRetry)
	if err != nil {
		return nil, err
	}

	// important to note that usedTestCA is not necessarily the same as isRetry
	// (usedTestCA can be true if the main CA and the test CA happen to be the same)
	if isRetry && usedTestCA && am.CA != am.TestCA {
		// succeeded with testing endpoint, so try again with production endpoint
		// (only if the production endpoint is different from the testing endpoint)
		// TODO: This logic is imperfect and could benefit from some refinement.
		// The two CA endpoints likely have different states, which could cause one
		// to succeed and the other to fail, even if it's not a validation error.
		// Two common cases would be:
		// 1) Rate limiter state. This is more likely to cause prod to fail while
		// staging succeeds, since prod usually has tighter rate limits. Thus, if
		// initial attempt failed in prod due to rate limit, first retry (on staging)
		// might succeed, and then trying prod again right way would probably still
		// fail; normally this would terminate retries but the right thing to do in
		// this case is to back off and retry again later. We could refine this logic
		// to stick with the production endpoint on retries unless the error changes.
		// 2) Cached authorizations state. If a domain validates successfully with
		// one endpoint, but then the other endpoint is used, it might fail, e.g. if
		// DNS was just changed or is still propagating. In this case, the second CA
		// should continue to be retried with backoff, without switching back to the
		// other endpoint. This is more likely to happen if a user is testing with
		// the staging CA as the main CA, then changes their configuration once they
		// think they are ready for the production endpoint.
		cert, _, err = am.doIssue(ctx, csr, false)
		if err != nil {
			// succeeded with test CA but failed just now with the production CA;
			// either we are observing differing internal states of each CA that will
			// work out with time, or there is a bug/misconfiguration somewhere
			// externally; it is hard to tell which! one easy cue is whether the
			// error is specifically a 429 (Too Many Requests); if so, we should
			// probably keep retrying
			var acmeErr acme.ProblemDetails
			if errors.As(err, &acmeErr) {
				if acmeErr.HTTPStatus == http.StatusTooManyRequests {
					// DON'T abort retries; the test CA succeeded (even
					// if it's cached, it recently succeeded!) so we just
					// need to keep trying (with backoff) until this CA's
					// rate limits expire...
					// TODO: as mentioned in comment above, we would benefit
					// by pinning the main CA at this point instead of
					// needlessly retrying with the test CA first each time
					return nil, err
				}
			}
			return nil, ErrNoRetry{err}
		}
	}

	return cert, err
}

func (am *ACMEManager) doIssue(ctx context.Context, csr *x509.CertificateRequest, useTestCA bool) (*IssuedCertificate, bool, error) {
	client, err := am.newACMEClientWithRetry(useTestCA)
	if err != nil {
		return nil, false, err
	}
	usingTestCA := client.usingTestCA()

	nameSet := namesFromCSR(csr)

	if !useTestCA {
		if err := client.throttle(ctx, nameSet); err != nil {
			return nil, usingTestCA, err
		}
	}

	certRes, err := client.tryAllEnabledChallenges(ctx, csr)
	if err != nil {
		return nil, usingTestCA, fmt.Errorf("%v %w", nameSet, err)
	}

	ic := &IssuedCertificate{
		Certificate: certRes.Certificate,
		Metadata:    certRes,
	}

	return ic, usingTestCA, nil
}

func (c *acmeClient) tryAllEnabledChallenges(ctx context.Context, csr *x509.CertificateRequest) (*certificate.Resource, error) {
	// start with all enabled challenges
	challenges := c.initialChallenges()
	if len(challenges) == 0 {
		return nil, fmt.Errorf("no challenge types enabled")
	}

	// try while a challenge type is still available
	var cert *certificate.Resource
	var err error
	for len(challenges) > 0 {
		var chosenChallenge challenge.Type
		chosenChallenge, challenges = c.nextChallenge(challenges)
		cert, err = c.acmeClient.Certificate.ObtainForCSR(*csr, true)
		if err == nil {
			return cert, nil
		}
		log.Printf("[ERROR] %s (challenge=%s remaining=%v)", err, chosenChallenge, challenges)
		time.Sleep(2 * time.Second)
	}
	return cert, err
}

// Revoke implements the Revoker interface. It revokes the given certificate.
func (am *ACMEManager) Revoke(ctx context.Context, cert CertificateResource) error {
	client, err := am.newACMEClient(false, false)
	if err != nil {
		return err
	}

	meta := cert.IssuerData.(map[string]interface{})
	cr := certificate.Resource{
		Domain:        meta["domain"].(string),
		CertURL:       meta["certUrl"].(string),
		CertStableURL: meta["certStableURL"].(string),
	}

	return client.revoke(ctx, cr)
}

// ExternalAccountBinding contains information for
// binding an external account to an ACME account.
type ExternalAccountBinding struct {
	KeyID string
	HMAC  string
}

// DefaultACME specifies the default settings
// to use for ACMEManagers.
var DefaultACME = ACMEManager{
	CA:     LetsEncryptProductionCA,
	TestCA: LetsEncryptStagingCA,
}

// Some well-known CA endpoints available to use.
const (
	LetsEncryptStagingCA    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LetsEncryptProductionCA = "https://acme-v02.api.letsencrypt.org/directory"
)

// prefixACME is the storage key prefix used for ACME-specific assets.
const prefixACME = "acme"

// Interface guards
var (
	_ PreChecker = (*ACMEManager)(nil)
	_ Issuer     = (*ACMEManager)(nil)
	_ Revoker    = (*ACMEManager)(nil)
)
