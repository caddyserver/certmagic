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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
)

// Config configures a certificate manager instance.
// An empty Config is not valid: use New() to obtain
// a valid Config.
type Config struct {
	// The endpoint of the directory for the ACME
	// CA we are to use
	CA string

	// The email address to use when creating or
	// selecting an existing ACME server account
	Email string

	// Set to true if agreed to the CA's
	// subscriber agreement
	Agreed bool

	// Disable all HTTP challenges
	DisableHTTPChallenge bool

	// Disable all TLS-ALPN challenges
	DisableTLSALPNChallenge bool

	// How long before expiration to renew certificates
	RenewDurationBefore time.Duration

	// An optional event callback clients can set
	// to subscribe to certain things happening
	// internally by this config; invocations are
	// synchronous, so make them return quickly!
	OnEvent func(event string, data interface{})

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

	// NextProtos is a list of supported application level protocols, in
	// order of preference.
	// The default NextProtos is ["h2", "http/1.1", "acme-tls/1"].
	NextProtos []string

	// The DNS provider to use when solving the
	// ACME DNS challenge
	DNSProvider challenge.Provider

	// The ChallengeOption struct to provide
	// custom precheck or name resolution options
	// for DNS challenge validation and execution
	DNSChallengeOption dns01.ChallengeOption

	// The type of key to use when generating
	// certificates
	KeyType certcrypto.KeyType

	// The maximum amount of time to allow for
	// obtaining a certificate. If empty, the
	// default from the underlying lego lib is
	// used. If set, it must not be too low so
	// as to cancel orders too early, running
	// the risk of rate limiting.
	CertObtainTimeout time.Duration

	// DefaultServerName specifies a server name
	// to use when choosing a certificate if the
	// ClientHello's ServerName field is empty
	DefaultServerName string

	// The state needed to operate on-demand TLS;
	// if non-nil, on-demand TLS is enabled and
	// certificate operations are deferred to
	// TLS handshakes (or as-needed)
	OnDemand *OnDemandConfig

	// Add the must staple TLS extension to the
	// CSR generated by lego/acme
	MustStaple bool

	// The storage to access when storing or
	// loading TLS assets
	Storage Storage

	// NewManager returns a new Manager. If nil,
	// an ACME client will be created and used.
	NewManager func(interactive bool) (Manager, error)

	// CertSelection chooses one of the certificates
	// with which the ClientHello will be completed.
	// If not set, the first matching certificate
	// will be used.
	CertSelection CertificateSelector

	// TrustedRoots specifies a pool of root CA
	// certificates to trust when communicating
	// over a network to a peer.
	TrustedRoots *x509.CertPool

	// Pointer to the in-memory certificate cache
	certCache *Cache
}

// NewDefault makes a valid config based on the package
// Default config. Most users will call this function
// instead of New() since most use cases require only a
// single config for any and all certificates.
//
// If your requirements are more advanced (for example,
// multiple configs depending on the certificate), then use
// New() instead. (You will need to make your own Cache
// first.) If you only need a single Config to manage your
// certs (even if that config changes, as long as it is the
// only one), customize the Default package variable before
// calling NewDefault().
//
// All calls to NewDefault() will return configs that use the
// same, default certificate cache. All configs returned
// by NewDefault() are based on the values of the fields of
// Default at the time it is called.
func NewDefault() *Config {
	defaultCacheMu.Lock()
	if defaultCache == nil {
		defaultCache = NewCache(CacheOptions{
			// the cache will likely need to renew certificates,
			// so it will need to know how to do that, which
			// depends on the certificate being managed and which
			// can change during the lifetime of the cache; this
			// callback makes it possible to get the latest and
			// correct config with which to manage the cert,
			// but if the user does not provide one, we can only
			// assume that we are to use the default config
			GetConfigForCert: func(Certificate) (Config, error) {
				return Default, nil
			},
		})
	}
	certCache := defaultCache
	defaultCacheMu.Unlock()

	return newWithCache(certCache, Default)
}

// New makes a new, valid config based on cfg and
// uses the provided certificate cache. certCache
// MUST NOT be nil or this function will panic.
//
// Use this method when you have an advanced use case
// that requires a custom certificate cache and config
// that may differ from the Default. For example, if
// not all certificates are managed/renewed the same
// way, you need to make your own Cache value with a
// GetConfigForCert callback that returns the correct
// configuration for each certificate. However, for
// the vast majority of cases, there will be only a
// single Config, thus the default cache (which always
// uses the default Config) and default config will
// suffice, and you should use New() instead.
func New(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("a certificate cache is required")
	}
	if certCache.options.GetConfigForCert == nil {
		panic("cache must have GetConfigForCert set in its options")
	}
	return newWithCache(certCache, cfg)
}

// newWithCache ensures that cfg is a valid config by populating
// zero-value fields from the Default Config. If certCache is
// nil, this function panics.
func newWithCache(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("cannot make a valid config without a pointer to a certificate cache")
	}

	// fill in default values
	if cfg.CA == "" {
		cfg.CA = Default.CA
	}
	if cfg.Email == "" {
		cfg.Email = Default.Email
	}
	if cfg.OnDemand == nil {
		cfg.OnDemand = Default.OnDemand
	}
	if !cfg.Agreed {
		cfg.Agreed = Default.Agreed
	}
	if !cfg.DisableHTTPChallenge {
		cfg.DisableHTTPChallenge = Default.DisableHTTPChallenge
	}
	if !cfg.DisableTLSALPNChallenge {
		cfg.DisableTLSALPNChallenge = Default.DisableTLSALPNChallenge
	}
	if cfg.RenewDurationBefore == 0 {
		cfg.RenewDurationBefore = Default.RenewDurationBefore
	}
	if cfg.OnEvent == nil {
		cfg.OnEvent = Default.OnEvent
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = Default.ListenHost
	}
	if cfg.AltHTTPPort == 0 {
		cfg.AltHTTPPort = Default.AltHTTPPort
	}
	if cfg.AltTLSALPNPort == 0 {
		cfg.AltTLSALPNPort = Default.AltTLSALPNPort
	}
	if cfg.DNSProvider == nil {
		cfg.DNSProvider = Default.DNSProvider
	}
	if cfg.DNSChallengeOption == nil {
		cfg.DNSChallengeOption = Default.DNSChallengeOption
	}
	if cfg.KeyType == "" {
		cfg.KeyType = Default.KeyType
	}
	if cfg.CertObtainTimeout == 0 {
		cfg.CertObtainTimeout = Default.CertObtainTimeout
	}
	if cfg.DefaultServerName == "" {
		cfg.DefaultServerName = Default.DefaultServerName
	}
	if cfg.OnDemand == nil {
		cfg.OnDemand = Default.OnDemand
	}
	if !cfg.MustStaple {
		cfg.MustStaple = Default.MustStaple
	}
	if cfg.Storage == nil {
		cfg.Storage = Default.Storage
	}
	if cfg.NewManager == nil {
		cfg.NewManager = Default.NewManager
	}

	// absolutely don't allow a nil storage,
	// because that would make almost anything
	// a config can do pointless
	if cfg.Storage == nil {
		cfg.Storage = defaultFileStorage
	}

	// ensure the unexported fields are valid
	cfg.certCache = certCache

	return &cfg
}

// ManageSync causes the certificates for domainNames to be managed
// according to cfg. If cfg.OnDemand is not nil, then this simply
// whitelists the domain names and defers the certificate operations
// to when they are needed. Otherwise, the certificates for each
// name are loaded from storage or obtained from the CA. If loaded
// from storage, they are renewed if they are expiring or expired.
// It then caches the certificate in memory and is prepared to serve
// them up during TLS handshakes.
//
// Note that name whitelisting for on-demand management only takes
// effect if cfg.OnDemand.DecisionFunc is not set (is nil); it will
// not overwrite an existing DecisionFunc, nor will it overwrite
// its decision; i.e. the implicit whitelist is only used if no
// DecisionFunc is set.
//
// This method is synchronous, meaning that certificates for all
// domainNames must be successfully obtained (or renewed) before
// it returns. It returns immediately on the first error for any
// of the given domainNames. This behavior is recommended for
// interactive use (i.e. when an administrator is present) so
// that errors can be reported and fixed immediately.
func (cfg *Config) ManageSync(domainNames []string) error {
	return cfg.manageAll(nil, domainNames, false)
}

// ManageAsync is the same as ManageSync, except that ACME
// operations are performed asynchronously (in the background).
// This method returns before certificates are ready. It is
// crucial that the administrator monitors the logs and is
// notified of any errors so that corrective action can be
// taken as soon as possible. Any errors returned from this
// method occurred before ACME transactions started.
//
// As long as logs are monitored, this method is typically
// recommended for non-interactive environments.
//
// If there are failures loading, obtaining, or renewing a
// certificate, it will be retried with exponential backoff
// for up to about 30 days, with a maximum interval of about
// 24 hours. Cancelling ctx will cancel retries and shut down
// any goroutines spawned by ManageAsync.
func (cfg *Config) ManageAsync(ctx context.Context, domainNames []string) error {
	return cfg.manageAll(ctx, domainNames, true)
}

func (cfg *Config) manageAll(ctx context.Context, domainNames []string, async bool) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// first, check all domains for validity
	for _, domainName := range domainNames {
		if !HostQualifies(domainName) {
			return fmt.Errorf("name does not qualify for automatic certificate management: %s", domainName)
		}
	}

	for _, domainName := range domainNames {
		// if on-demand is configured, defer obtain and renew operations
		if cfg.OnDemand != nil {
			if !cfg.OnDemand.whitelistContains(domainName) {
				cfg.OnDemand.hostWhitelist = append(cfg.OnDemand.hostWhitelist, domainName)
			}
			continue
		}
		if async {
			go func(domainName string) {
				var wait time.Duration
				// the first 17 iterations ramp up the wait interval to
				// ~24h, and the remaining iterations retry at that
				// maximum backoff until giving up after ~30 days total.
				const maxIter = 46
				for i := 1; i <= maxIter; i++ {
					timer := time.NewTimer(wait)
					select {
					case <-ctx.Done():
						timer.Stop()
						log.Printf("[ERROR][%s] Context cancelled", domainName)
						return
					case <-timer.C:
						err := cfg.manageOne(ctx, domainName)
						if err == nil {
							return
						}
						if !errors.Is(err, context.Canceled) {
							log.Printf("[ERROR] %s - backing off and retrying (attempt %d/%d)...", strings.TrimSpace(err.Error()), i, maxIter)
						}
					}
					// retry with exponential backoff
					if wait == 0 {
						// this starting interval (~2.6 seconds) doubles nicely to ~24h
						wait = 2636719 * time.Microsecond
					} else if wait < 24*time.Hour {
						wait *= 2
					}
				}
			}(domainName)
		} else {
			err := cfg.manageOne(ctx, domainName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (cfg *Config) manageOne(ctx context.Context, domainName string) error {
	// try loading an existing certificate; if it doesn't
	// exist yet, obtain one and try loading it again
	cert, err := cfg.CacheManagedCertificate(domainName)
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// if it doesn't exist, get it, then try loading it again
			err := cfg.ObtainCert(ctx, domainName, false)
			if err != nil {
				return fmt.Errorf("%s: obtaining certificate: %w", domainName, err)
			}
			cert, err = cfg.CacheManagedCertificate(domainName)
			if err != nil {
				return fmt.Errorf("%s: caching certificate after obtaining it: %v", domainName, err)
			}
			return nil
		}
		return fmt.Errorf("%s: caching certificate: %v", domainName, err)
	}

	// for existing certificates, make sure it is renewed
	if cert.NeedsRenewal(cfg) {
		err := cfg.RenewCert(ctx, domainName, false)
		if err != nil {
			return fmt.Errorf("%s: renewing certificate: %w", domainName, err)
		}
	}

	return nil
}

// ObtainCert obtains a certificate for name using cfg, as long
// as a certificate does not already exist in storage for that
// name. The name must qualify and cfg must be flagged as Managed.
// This function is a no-op if storage already has a certificate
// for name.
//
// It only obtains and stores certificates (and their keys),
// it does not load them into memory. If interactive is true,
// the user may be shown a prompt.
func (cfg *Config) ObtainCert(ctx context.Context, name string, interactive bool) error {
	if cfg.storageHasCertResources(name) {
		return nil
	}
	skip, err := cfg.preObtainOrRenewChecks(name, interactive)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	manager, err := cfg.newManager(interactive)
	if err != nil {
		return err
	}
	log.Printf("[INFO][%s] Obtain certificate", name)
	return manager.Obtain(ctx, name)
}

// RenewCert renews the certificate for name using cfg. It stows the
// renewed certificate and its assets in storage if successful.
func (cfg *Config) RenewCert(ctx context.Context, name string, interactive bool) error {
	skip, err := cfg.preObtainOrRenewChecks(name, interactive)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	manager, err := cfg.newManager(interactive)
	if err != nil {
		return err
	}
	log.Printf("[INFO][%s] Renew certificate", name)
	return manager.Renew(ctx, name)
}

// RevokeCert revokes the certificate for domain via ACME protocol.
func (cfg *Config) RevokeCert(ctx context.Context, domain string, interactive bool) error {
	manager, err := cfg.newManager(interactive)
	if err != nil {
		return err
	}
	return manager.Revoke(ctx, domain)
}

// TLSConfig is an opinionated method that returns a
// recommended, modern TLS configuration that can be
// used to configure TLS listeners, which also supports
// the TLS-ALPN challenge and serves up certificates
// managed by cfg.
//
// Unlike the package TLS() function, this method does
// not, by itself, enable certificate management for
// any domain names.
//
// Feel free to further customize the returned tls.Config,
// but do not mess with the GetCertificate or NextProtos
// fields unless you know what you're doing, as they're
// necessary to solve the TLS-ALPN challenge.
func (cfg *Config) TLSConfig() *tls.Config {
	nextProtos := cfg.NextProtos
	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1", tlsalpn01.ACMETLS1Protocol}
	}

	return &tls.Config{
		// these two fields necessary for TLS-ALPN challenge
		GetCertificate: cfg.GetCertificate,
		NextProtos:     nextProtos,

		// the rest recommended for modern TLS servers
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites:             preferredDefaultCipherSuites(),
		PreferServerCipherSuites: true,
	}
}

// preObtainOrRenewChecks perform a few simple checks before
// obtaining or renewing a certificate with ACME, and returns
// whether this name should be skipped (like if it's not
// managed TLS) as well as any error. It ensures that the
// config is Managed, that the name qualifies for a certificate,
// and that an email address is available.
func (cfg *Config) preObtainOrRenewChecks(name string, allowPrompts bool) (bool, error) {
	if !HostQualifies(name) {
		return true, nil
	}

	err := cfg.getEmail(allowPrompts)
	if err != nil {
		return false, err
	}

	return false, nil
}

// storageHasCertResources returns true if the storage
// associated with cfg's certificate cache has all the
// resources related to the certificate for domain: the
// certificate, the private key, and the metadata.
func (cfg *Config) storageHasCertResources(domain string) bool {
	certKey := StorageKeys.SiteCert(cfg.CA, domain)
	keyKey := StorageKeys.SitePrivateKey(cfg.CA, domain)
	metaKey := StorageKeys.SiteMeta(cfg.CA, domain)
	return cfg.Storage.Exists(certKey) &&
		cfg.Storage.Exists(keyKey) &&
		cfg.Storage.Exists(metaKey)
}

// managedCertNeedsRenewal returns true if certRes is
// expiring soon or already expired, or if the process
// of checking the expiration returned an error.
func (cfg *Config) managedCertNeedsRenewal(certRes certificate.Resource) bool {
	cert, err := makeCertificate(certRes.Certificate, certRes.PrivateKey)
	if err != nil {
		return true
	}
	return cert.NeedsRenewal(cfg)
}

// Manager is a type that can manage a certificate.
// They are usually very short-lived.
type Manager interface {
	Obtain(ctx context.Context, name string) error
	Renew(ctx context.Context, name string) error
	Revoke(ctx context.Context, name string) error
}

// CertificateSelector is a type which can select a certificate to use given multiple choices.
type CertificateSelector interface {
	SelectCertificate(*tls.ClientHelloInfo, []Certificate) (Certificate, error)
}
