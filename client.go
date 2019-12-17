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
	"context"
	"crypto/tls"
	"fmt"
	"log"
	weakrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/http01"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())
}

// acmeClient is a wrapper over acme.Client with
// some custom state attached. It is used to obtain,
// renew, and revoke certificates with ACME.
type acmeClient struct {
	config     *Config
	acmeClient *lego.Client
	challenges []challenge.Type
}

// listenerAddressInUse returns true if a TCP connection
// can be made to addr within a short time interval.
func listenerAddressInUse(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err == nil
}

// lockKey returns a key for a lock that is specific to the operation
// named op being performed related to domainName and this config's CA.
func (cfg *Config) lockKey(op, domainName string) string {
	return fmt.Sprintf("%s_%s_%s", op, domainName, cfg.CA)
}

// checkStorage tests the storage by writing random bytes
// to a random key, and then loading those bytes and
// comparing the loaded value. If this fails, the provided
// cfg.Storage mechanism should not be used.
func (cfg *Config) checkStorage() error {
	key := fmt.Sprintf("rw_test_%d", weakrand.Int())
	contents := make([]byte, 1024*10) // size sufficient for one or two ACME resources
	_, err := weakrand.Read(contents)
	if err != nil {
		return err
	}
	err = cfg.Storage.Store(key, contents)
	if err != nil {
		return err
	}
	defer func() {
		deleteErr := cfg.Storage.Delete(key)
		if deleteErr != nil {
			log.Printf("[ERROR] Deleting test key %s from storage: %v", key, err)
		}
		// if there was no other error, make sure
		// to return any error returned from Delete
		if err == nil {
			err = deleteErr
		}
	}()
	loaded, err := cfg.Storage.Load(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(contents, loaded) {
		return fmt.Errorf("load yielded different value than was stored; expected %d bytes, got %d bytes of differing elements", len(contents), len(loaded))
	}
	return nil
}

func (cfg *Config) newManager(interactive bool) (Manager, error) {
	// ensure storage is writeable and readable
	// TODO: this is not necessary every time; should only
	// perform check once every so often for each storage,
	// which may require some global state...
	err := cfg.checkStorage()
	if err != nil {
		return nil, fmt.Errorf("failed storage check: %v - storage is probably misconfigured", err)
	}

	const maxTries = 3
	var mgr Manager
	for i := 0; i < maxTries; i++ {
		if cfg.NewManager != nil {
			mgr, err = cfg.NewManager(interactive)
		} else {
			mgr, err = cfg.newACMEClient(interactive)
		}
		if err == nil {
			break
		}
		if acmeErr, ok := err.(acme.ProblemDetails); ok {
			if acmeErr.HTTPStatus == http.StatusTooManyRequests {
				log.Printf("[ERROR] Too many requests when making new ACME client: %+v - aborting", acmeErr)
				return nil, err
			}
		}
		log.Printf("[ERROR] Making new certificate manager: %v (attempt %d/%d)", err, i+1, maxTries)
		time.Sleep(1 * time.Second)
	}
	return mgr, err
}

func (cfg *Config) newACMEClient(interactive bool) (*acmeClient, error) {
	// look up or create the user account
	leUser, err := cfg.getUser(cfg.Email)
	if err != nil {
		return nil, err
	}

	// ensure key type and timeout are set
	keyType := cfg.KeyType
	if keyType == "" {
		keyType = Default.KeyType
	}
	certObtainTimeout := cfg.CertObtainTimeout
	if certObtainTimeout == 0 {
		certObtainTimeout = Default.CertObtainTimeout
	}

	// ensure CA URL (directory endpoint) is set
	caURL := Default.CA
	if cfg.CA != "" {
		caURL = cfg.CA
	}

	// ensure endpoint is secure (assume HTTPS if scheme is missing)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}
	u, err := url.Parse(caURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" && !isLoopback(u.Host) && !isInternal(u.Host) {
		return nil, fmt.Errorf("%s: insecure CA URL (HTTPS required)", caURL)
	}

	clientKey := caURL + leUser.Email + string(keyType)

	// if an underlying client with this configuration already exists, reuse it
	// TODO: Could this be a global cache instead, perhaps?
	cfg.acmeClientsMu.Lock()
	client, ok := cfg.acmeClients[clientKey]
	if !ok {
		// the client facilitates our communication with the CA server
		legoCfg := lego.NewConfig(leUser)
		legoCfg.CADirURL = caURL
		legoCfg.UserAgent = buildUAString()
		legoCfg.HTTPClient.Timeout = HTTPTimeout
		legoCfg.Certificate = lego.CertificateConfig{
			KeyType: keyType,
			Timeout: certObtainTimeout,
		}
		if cfg.TrustedRoots != nil {
			if ht, ok := legoCfg.HTTPClient.Transport.(*http.Transport); ok {
				if ht.TLSClientConfig == nil {
					ht.TLSClientConfig = new(tls.Config)
					ht.ForceAttemptHTTP2 = true
				}
				ht.TLSClientConfig.RootCAs = cfg.TrustedRoots
			}
		}
		client, err = lego.NewClient(legoCfg)
		if err != nil {
			cfg.acmeClientsMu.Unlock()
			return nil, err
		}
		cfg.acmeClients[clientKey] = client
	}
	cfg.acmeClientsMu.Unlock()

	// if not registered, the user must register an account
	// with the CA and agree to terms
	if leUser.Registration == nil {
		if interactive { // can't prompt a user who isn't there
			termsURL := client.GetToSURL()
			if !cfg.Agreed && termsURL != "" {
				cfg.Agreed = cfg.askUserAgreement(client.GetToSURL())
			}
			if !cfg.Agreed && termsURL != "" {
				return nil, fmt.Errorf("user must agree to CA terms")
			}
		}

		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: cfg.Agreed})
		if err != nil {
			return nil, err
		}
		leUser.Registration = reg

		// persist the user to storage
		err = cfg.saveUser(leUser)
		if err != nil {
			return nil, fmt.Errorf("could not save user: %v", err)
		}
	}

	c := &acmeClient{
		config:     cfg,
		acmeClient: client,
	}

	return c, nil
}

// Obtain obtains a single certificate for name. It stores the certificate
// on the disk if successful. This function is safe for concurrent use.
//
// Our storage mechanism only supports one name per certificate, so this
// function (along with Renew and Revoke) only accepts one domain as input.
// It could be easily modified to support SAN certificates if our storage
// mechanism is upgraded later, but that will increase logical complexity
// in other areas and is not recommended at scale (even Cloudflare now
// utilizes fewer-or-single-SAN certificates at their scale: see
// https://twitter.com/epatryk/status/1135615936176775174).
//
// Callers who have access to a Config value should use the ObtainCert
// method on that instead of this lower-level method.
//
// This method is throttled according to RateLimitOrders.
func (c *acmeClient) Obtain(ctx context.Context, name string) error {
	if err := c.throttle(ctx, "Obtain", name); err != nil {
		return err
	}

	// ensure idempotency of the obtain operation for this name
	lockKey := c.config.lockKey("cert_acme", name)
	err := obtainLock(c.config.Storage, lockKey)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseLock(c.config.Storage, lockKey); err != nil {
			log.Printf("[ERROR][%s] Obtain: Unable to unlock '%s': %v", name, lockKey, err)
		}
	}()

	// check if obtain is still needed -- might have been obtained during lock
	if c.config.storageHasCertResources(name) {
		log.Printf("[INFO][%s] Obtain: Certificate already exists in storage", name)
		return nil
	}

	challenges := c.initialChallenges()
	if len(challenges) == 0 {
		log.Printf("[ERROR][%s] No challenge types enabled; obtain is doomed", name)
	}
	var chosenChallenge challenge.Type

	// try while a challenge type is still available;
	// and for each challenge, retry a few times
challengeLoop:
	for len(challenges) > 0 {
		chosenChallenge, challenges = c.nextChallenge(challenges)
		const maxAttempts = 2
		for attempts := 0; attempts < maxAttempts; attempts++ {
			err = c.tryObtain(name)
			if err == nil {
				break challengeLoop
			}
			log.Printf("[ERROR][%s] %s (attempt %d/%d; challenge=%s)",
				name, strings.TrimSpace(err.Error()), attempts+1, maxAttempts, chosenChallenge)
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		return err
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_obtained", name)
	}

	return nil
}

// tryObtain uses the underlying ACME client to obtain a
// certificate for name and puts the result in storage if
// it succeeds. There are no retries here and c must be
// fully configured already.
func (c *acmeClient) tryObtain(name string) error {
	request := certificate.ObtainRequest{
		Domains:    []string{name},
		Bundle:     true,
		MustStaple: c.config.MustStaple,
	}
	certificate, err := c.acmeClient.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// double-check that we actually got a certificate, in case there's a bug upstream
	// (see issue mholt/caddy#2121)
	if certificate.Domain == "" || certificate.Certificate == nil {
		return fmt.Errorf("returned certificate was empty; probably an unchecked error obtaining it")
	}

	// Success - immediately save the certificate resource
	err = c.config.saveCertResource(certificate)
	if err != nil {
		return fmt.Errorf("saving assets: %v", err)
	}

	return nil
}

// Renew renews the managed certificate for name. It puts the renewed
// certificate into storage (not the cache). This function is safe for
// concurrent use.
//
// Callers who have access to a Config value should use the RenewCert
// method on that instead of this lower-level method.
//
// This method is throttled according to RateLimitOrders.
func (c *acmeClient) Renew(ctx context.Context, name string) error {
	if err := c.throttle(ctx, "Renew", name); err != nil {
		return err
	}

	// ensure idempotency of the renew operation for this name
	lockKey := c.config.lockKey("cert_acme", name)
	err := obtainLock(c.config.Storage, lockKey)
	if err != nil {
		return err
	}
	defer func() {
		if err := releaseLock(c.config.Storage, lockKey); err != nil {
			log.Printf("[ERROR][%s] Renew: Unable to unlock '%s': %v", name, lockKey, err)
		}
	}()

	// Prepare for renewal (load PEM cert, key, and meta)
	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	// Check if renew is still needed - might have been renewed while waiting for lock
	if !c.config.managedCertNeedsRenewal(certRes) {
		log.Printf("[INFO][%s] Renew: Certificate appears to have been renewed already", name)
		return nil
	}

	challenges := c.initialChallenges()
	if len(challenges) == 0 {
		log.Printf("[ERROR][%s] No challenge types enabled; renew is doomed", name)
	}
	var chosenChallenge challenge.Type

	// try while a challenge type is still available;
	// and for each challenge, retry a few times
challengeLoop:
	for len(challenges) > 0 {
		chosenChallenge, challenges = c.nextChallenge(challenges)
		const maxAttempts = 2
		for attempts := 0; attempts < maxAttempts; attempts++ {
			// TODO: consider moving throttle to here instead, the only potentially negative consequence is that the lock in storage may be persisted and get "stale" when it's actually not stale...
			err = c.tryRenew(certRes)
			if err == nil {
				break challengeLoop
			}
			log.Printf("[ERROR][%s] %s (attempt %d/%d; challenge=%s)",
				name, strings.TrimSpace(err.Error()), attempts+1, maxAttempts, chosenChallenge)
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		return err
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_renewed", name)
	}

	return nil
}

// tryRenew uses the underlying ACME client to renew the
// certificate represented by certRes and puts the result
// in storage if it succeeds. There are no retries here
// and c must be fully configured already.
func (c *acmeClient) tryRenew(certRes certificate.Resource) error {
	newCertMeta, err := c.acmeClient.Certificate.Renew(certRes, true, c.config.MustStaple)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %v", err)
	}

	// double-check that we actually got a certificate, in case there's a bug upstream
	// (see issue mholt/caddy#2121)
	if newCertMeta == nil || newCertMeta.Domain == "" || newCertMeta.Certificate == nil {
		return fmt.Errorf("returned certificate was empty; probably an unchecked error renewing it")
	}

	// Success - immediately save the renewed certificate resource
	err = c.config.saveCertResource(newCertMeta)
	if err != nil {
		return fmt.Errorf("saving assets: %v", err)
	}

	return nil
}

// Revoke revokes the certificate for name and deletes it from storage.
func (c *acmeClient) Revoke(_ context.Context, name string) error {
	if !c.config.Storage.Exists(StorageKeys.SitePrivateKey(c.config.CA, name)) {
		return fmt.Errorf("private key not found for %s", name)
	}

	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	err = c.acmeClient.Certificate.Revoke(certRes.Certificate)
	if err != nil {
		return err
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_revoked", name)
	}

	err = c.config.Storage.Delete(StorageKeys.SiteCert(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate file: %v", err)
	}
	err = c.config.Storage.Delete(StorageKeys.SitePrivateKey(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete private key: %v", err)
	}
	err = c.config.Storage.Delete(StorageKeys.SiteMeta(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate metadata: %v", err)
	}

	return nil
}

// initialChallenges returns the initial set of challenges
// to try using c.config as a basis.
func (c *acmeClient) initialChallenges() []challenge.Type {
	// if configured, use DNS challenge exclusively
	if c.config.DNSProvider != nil {
		return []challenge.Type{challenge.DNS01}
	}

	// otherwise, use HTTP and TLS-ALPN challenges if enabled
	var chal []challenge.Type
	if !c.config.DisableHTTPChallenge {
		chal = append(chal, challenge.HTTP01)
	}
	if !c.config.DisableTLSALPNChallenge {
		chal = append(chal, challenge.TLSALPN01)
	}
	return chal
}

// nextChallenge chooses a challenge randomly from the given list of
// available challenges and configures c.acmeClient to use that challenge
// according to c.config. It pops the chosen challenge from the list and
// returns that challenge along with the new list without that challenge.
// If len(available) == 0, this is a no-op.
//
// Don't even get me started on how dumb it is we need to do this here
// instead of the upstream lego library doing it for us. Lego used to
// randomize the challenge order, thus allowing another one to be used
// if the first one failed. https://github.com/go-acme/lego/issues/842
// (It also has an awkward API for adjusting the available challenges.)
// At time of writing, lego doesn't try anything other than the TLS-ALPN
// challenge, even if the HTTP challenge is also enabled. So we take
// matters into our own hands and enable only one challenge at a time
// in the underlying client, randomly selected by us.
func (c *acmeClient) nextChallenge(available []challenge.Type) (challenge.Type, []challenge.Type) {
	if len(available) == 0 {
		return "", available
	}

	// make sure we choose a challenge randomly, which lego used to do but
	// the critical feature was surreptitiously removed in ~2018 in a commit
	// too large to review, oh well - choose one, then remove it from the
	// list of available challenges so it doesn't get retried
	randIdx := weakrand.Intn(len(available))
	randomChallenge := available[randIdx]
	available = append(available[:randIdx], available[randIdx+1:]...)

	// clean the slate, since we reuse clients
	c.acmeClient.Challenge.Remove(challenge.HTTP01)
	c.acmeClient.Challenge.Remove(challenge.TLSALPN01)
	c.acmeClient.Challenge.Remove(challenge.DNS01)

	switch randomChallenge {
	case challenge.HTTP01:
		// figure out which ports we'll be serving the challenge on
		useHTTPPort := HTTPChallengePort
		if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
			useHTTPPort = HTTPPort
		}
		if c.config.AltHTTPPort > 0 {
			useHTTPPort = c.config.AltHTTPPort
		}

		// If this machine is already listening on the HTTP or TLS-ALPN port
		// designated for the challenges, then we need to handle the challenges
		// a little differently: for HTTP, we will answer the challenge request
		// using our own HTTP handler (the HandleHTTPChallenge function - this
		// works only because challenge info is written to storage associated
		// with c.config when the challenge is initiated); for TLS-ALPN, we will
		// add the challenge cert to our cert cache and serve it up during the
		// handshake. As for the default solvers...  we are careful to honor the
		// listener bind preferences by using c.config.ListenHost.
		var httpSolver challenge.Provider
		if listenerAddressInUse(net.JoinHostPort(c.config.ListenHost, fmt.Sprintf("%d", useHTTPPort))) {
			httpSolver = nil // assume that whatever's listening can solve the HTTP challenge
		} else {
			httpSolver = http01.NewProviderServer(c.config.ListenHost, fmt.Sprintf("%d", useHTTPPort))
		}

		// because of our nifty Storage interface, we can distribute the HTTP and
		// TLS-ALPN challenges across all instances that share the same storage -
		// in fact, this is required now for successful solving of the HTTP challenge
		// if the port is already in use, since we must write the challenge info
		// to storage for the HTTPChallengeHandler to solve it successfully
		c.acmeClient.Challenge.SetHTTP01Provider(distributedSolver{
			config:         c.config,
			providerServer: httpSolver,
		})

	case challenge.TLSALPN01:
		// figure out which ports we'll be serving the challenge on
		useTLSALPNPort := TLSALPNChallengePort
		if HTTPSPort > 0 && HTTPSPort != TLSALPNChallengePort {
			useTLSALPNPort = HTTPSPort
		}
		if c.config.AltTLSALPNPort > 0 {
			useTLSALPNPort = c.config.AltTLSALPNPort
		}

		// (see comments above for the HTTP challenge to gain an understanding of this chunk)
		var alpnSolver challenge.Provider
		if listenerAddressInUse(net.JoinHostPort(c.config.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))) {
			alpnSolver = tlsALPNSolver{certCache: c.config.certCache} // assume that our process is listening
		} else {
			alpnSolver = tlsalpn01.NewProviderServer(c.config.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))
		}

		// (see comments above for the HTTP challenge to gain an understanding of this chunk)
		c.acmeClient.Challenge.SetTLSALPN01Provider(distributedSolver{
			config:         c.config,
			providerServer: alpnSolver,
		})

	case challenge.DNS01:
		if c.config.DNSChallengeOption != nil {
			c.acmeClient.Challenge.SetDNS01Provider(c.config.DNSProvider, c.config.DNSChallengeOption)
		} else {
			c.acmeClient.Challenge.SetDNS01Provider(c.config.DNSProvider)
		}
	}

	return randomChallenge, available
}

func (c *acmeClient) throttle(ctx context.Context, op, name string) error {
	rateLimiterKey := c.config.CA + "," + c.config.Email
	rateLimitersMu.Lock()
	rl, ok := rateLimiters[rateLimiterKey]
	if !ok {
		rl = NewRateLimiter(RateLimitOrders, RateLimitOrdersWindow)
		rateLimiters[rateLimiterKey] = rl
		// TODO: stop rate limiter when it is garbage-collected...
	}
	rateLimitersMu.Unlock()
	log.Printf("[INFO][%s] %s: Waiting on rate limiter...", name, op)
	err := rl.Wait(ctx)
	if err != nil {
		return err
	}
	log.Printf("[INFO][%s] %s: Done waiting", name, op)
	return nil
}

func buildUAString() string {
	ua := "CertMagic"
	if UserAgent != "" {
		ua += " " + UserAgent
	}
	return ua
}

// These internal rate limits are designed to prevent accidentally
// firehosing a CA's ACME endpoints. They are not intended to
// replace or reimplement the CA's actual rate limits.
//
// Let's Encrypt's rate limits can be found here:
// https://letsencrypt.org/docs/rate-limits/
//
// Currently (as of December 2019), Let's Encrypt's most relevant
// rate limit for large deployments is 300 new orders per account
// per 3 hours (on average, or best case, that's about 1 every 36
// seconds, or 2 every 72 seconds, etc.); but it's not reasonable
// to try to assume that our internal state is the same as the CA's
// (due to process restarts, config changes, failed validations,
// etc.) and ultimately, only the CA's actual rate limiter is the
// authority. Thus, our own rate limiters do not attempt to enforce
// external rate limits. Doing so causes problems when the domains
// are not in our control (i.e. serving customer sites) and/or lots
// of domains fail validation: they clog our internal rate limiter
// and nearly starve out (or at least slow down) the other domains
// that need certificates. Failed transactions are already retried
// with exponential backoff, so adding in rate limiting can slow
// things down even more.
//
// Instead, the point of our internal rate limiter is to avoid
// hammering the CA's endpoint when there are thousands or even
// millions of certificates under management. Our goal is to
// allow small bursts in a relatively short timeframe so as to
// not block any one domain for too long, without unleashing
// thousands of requests to the CA at once.
var (
	rateLimiters   = make(map[string]*RingBufferRateLimiter)
	rateLimitersMu sync.RWMutex

	// RateLimitOrders is how many new ACME orders can be made per
	// account in RateLimitNewOrdersWindow.
	RateLimitOrders = 10

	// RateLimitOrdersWindow is the size of the sliding
	// window that throttles new ACME orders.
	RateLimitOrdersWindow = 1 * time.Minute
)

// Some default values passed down to the underlying lego client.
var (
	UserAgent   string
	HTTPTimeout = 30 * time.Second
)

// Interface guard
var _ Manager = (*acmeClient)(nil)
