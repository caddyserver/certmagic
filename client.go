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
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xenolf/lego/acme"
)

// acmeMu ensures that only one ACME challenge occurs at a time.
var acmeMu sync.Mutex

// acmeClient is a wrapper over acme.Client with
// some custom state attached. It is used to obtain,
// renew, and revoke certificates with ACME.
type acmeClient struct {
	config     *Config
	acmeClient *acme.Client
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

func (cfg *Config) newACMEClient(interactive bool) (*acmeClient, error) {
	// look up or create the user account
	leUser, err := cfg.getUser(cfg.Email)
	if err != nil {
		return nil, err
	}

	// ensure key type is set
	keyType := KeyType
	if cfg.KeyType != "" {
		keyType = cfg.KeyType
	}

	// ensure CA URL (directory endpoint) is set
	caURL := CA
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
	cfg.acmeClientsMu.Lock()
	client, ok := cfg.acmeClients[clientKey]
	if !ok {
		// the client facilitates our communication with the CA server
		client, err = acme.NewClient(caURL, &leUser, keyType)
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
				return nil, errors.New("user must agree to CA terms (use -agree flag)")
			}
		}

		reg, err := client.Register(cfg.Agreed)
		if err != nil {
			return nil, errors.New("registration error: " + err.Error())
		}
		leUser.Registration = reg

		// persist the user to storage
		err = cfg.saveUser(leUser)
		if err != nil {
			return nil, errors.New("could not save user: " + err.Error())
		}
	}

	c := &acmeClient{
		config:     cfg,
		acmeClient: client,
	}

	if cfg.DNSProvider == nil {
		// Use HTTP and TLS-ALPN challenges by default

		// figure out which ports we'll be serving the challenges on
		useHTTPPort := HTTPChallengePort
		useTLSALPNPort := TLSALPNChallengePort
		if cfg.AltHTTPPort > 0 {
			useHTTPPort = cfg.AltHTTPPort
		}
		if cfg.AltTLSALPNPort > 0 {
			useTLSALPNPort = cfg.AltTLSALPNPort
		}

		// If this machine is already listening on the HTTP or TLS-ALPN port
		// designated for the challenges, then we need to handle the challenges
		// a little differently: for HTTP, we will answer the challenge request
		// using our own HTTP handler (the HandleHTTPChallenge function - this
		// works only because challenge info is written to storage associated
		// with cfg when the challenge is initiated); for TLS-ALPN, we will add
		// the challenge cert to our cert cache and serve it up during the
		// handshake. As for the default solvers...  we are careful to honor the
		// listener bind preferences by using cfg.ListenHost.
		var httpSolver, alpnSolver acme.ChallengeProvider
		httpSolver = acme.NewHTTPProviderServer(cfg.ListenHost, fmt.Sprintf("%d", useHTTPPort))
		alpnSolver = acme.NewTLSALPNProviderServer(cfg.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))
		if listenerAddressInUse(net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", useHTTPPort))) {
			httpSolver = nil
		}
		if listenerAddressInUse(net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", useTLSALPNPort))) {
			alpnSolver = tlsALPNSolver{certCache: cfg.certCache}
		}

		// because of our nifty Storage interface, we can distribute the HTTP and
		// TLS-ALPN challenges across all instances that share the same storage -
		// in fact, this is required now for successful solving of the HTTP challenge
		// if the port is already in use, since we must write the challenge info
		// to storage for the HTTPChallengeHandler to solve it successfully
		c.acmeClient.SetChallengeProvider(acme.HTTP01, distributedSolver{
			config:         cfg,
			providerServer: httpSolver,
		})
		c.acmeClient.SetChallengeProvider(acme.TLSALPN01, distributedSolver{
			config:         cfg,
			providerServer: alpnSolver,
		})

		// disable any challenges that should not be used
		var disabledChallenges []acme.Challenge
		if cfg.DisableHTTPChallenge {
			disabledChallenges = append(disabledChallenges, acme.HTTP01)
		}
		if cfg.DisableTLSALPNChallenge {
			disabledChallenges = append(disabledChallenges, acme.TLSALPN01)
		}
		if len(disabledChallenges) > 0 {
			c.acmeClient.ExcludeChallenges(disabledChallenges)
		}
	} else {
		// Otherwise, use DNS challenge exclusively
		c.acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSALPN01})
		c.acmeClient.SetChallengeProvider(acme.DNS01, cfg.DNSProvider)
	}

	return c, nil
}

func (cfg *Config) lockKey(op, domainName string) string {
	return fmt.Sprintf("%s:%s:%s", op, domainName, cfg.CA)
}

// Obtain obtains a single certificate for name. It stores the certificate
// on the disk if successful. This function is safe for concurrent use.
//
// Right now our storage mechanism only supports one name per certificate,
// so this function (along with Renew and Revoke) only accepts one domain
// as input. It can be easily modified to support SAN certificates if our
// storage mechanism is upgraded later.
//
// Callers who have access to a Config value should use the ObtainCert
// method on that instead of this lower-level method.
func (c *acmeClient) Obtain(name string) error {
	if c.config.Sync != nil {
		lockKey := c.config.lockKey("cert_acme", name)
		waiter, err := c.config.Sync.TryLock(lockKey)
		if err != nil {
			return err
		}
		if waiter != nil {
			log.Printf("[INFO] Certificate for %s is already being obtained elsewhere and stored; waiting", name)
			waiter.Wait()
			return nil // we assume the process with the lock succeeded, rather than hammering this execution path again
		}
		defer func() {
			if err := c.config.Sync.Unlock(lockKey); err != nil {
				log.Printf("[ERROR] Unable to unlock obtain call for %s: %v", name, err)
			}
		}()
	}

	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		certificate, err := c.acmeClient.ObtainCertificate([]string{name}, true, nil, c.config.MustStaple)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if err != nil {
			// for a certain kind of error, we can enumerate the error per-domain
			if failures, ok := err.(acme.ObtainError); ok && len(failures) > 0 {
				var errMsg string // combine all the failures into a single error message
				for errDomain, obtainErr := range failures {
					if obtainErr == nil {
						continue
					}
					errMsg += fmt.Sprintf("[%s] failed to get certificate: %v\n", errDomain, obtainErr)
				}
				return errors.New(errMsg)
			}

			return fmt.Errorf("[%s] failed to obtain certificate: %v", name, err)
		}

		// double-check that we actually got a certificate, in case there's a bug upstream (see issue mholt/caddy#2121)
		if certificate.Domain == "" || certificate.Certificate == nil {
			return errors.New("returned certificate was empty; probably an unchecked error obtaining it")
		}

		// Success - immediately save the certificate resource
		err = c.config.saveCertResource(certificate)
		if err != nil {
			return fmt.Errorf("error saving assets for %v: %v", name, err)
		}

		break
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_obtained", name)
	}

	return nil
}

// Renew renews the managed certificate for name. It puts the renewed
// certificate into storage (not the cache). This function is safe for
// concurrent use.
//
// Callers who have access to a Config value should use the RenewCert
// method on that instead of this lower-level method.
func (c *acmeClient) Renew(name string) error {
	if c.config.Sync != nil {
		lockKey := c.config.lockKey("cert_acme", name)
		waiter, err := c.config.Sync.TryLock(lockKey)
		if err != nil {
			return err
		}
		if waiter != nil {
			log.Printf("[INFO] Certificate for %s is already being renewed elsewhere and stored; waiting", name)
			waiter.Wait()
			return nil // assume that the worker that renewed the cert succeeded; avoid hammering this path over and over
		}
		defer func() {
			if err := c.config.Sync.Unlock(lockKey); err != nil {
				log.Printf("[ERROR] Unable to unlock renew call for %s: %v", name, err)
			}
		}()
	}

	// Prepare for renewal (load PEM cert, key, and meta)
	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	// Perform renewal and retry if necessary, but not too many times.
	var newCertMeta *acme.CertificateResource
	var success bool
	for attempts := 0; attempts < 2; attempts++ {
		namesObtaining.Add([]string{name})
		acmeMu.Lock()
		newCertMeta, err = c.acmeClient.RenewCertificate(certRes, true, c.config.MustStaple)
		acmeMu.Unlock()
		namesObtaining.Remove([]string{name})
		if err == nil {
			// double-check that we actually got a certificate; check a couple fields, just in case
			if newCertMeta == nil || newCertMeta.Domain == "" || newCertMeta.Certificate == nil {
				err = errors.New("returned certificate was empty; probably an unchecked error renewing it")
			} else {
				success = true
				break
			}
		}

		// wait a little bit and try again
		wait := 10 * time.Second
		log.Printf("[ERROR] Renewing [%v]: %v; trying again in %s", name, err, wait)
		time.Sleep(wait)
	}

	if !success {
		return errors.New("too many renewal attempts; last error: " + err.Error())
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_renewed", name)
	}

	return c.config.saveCertResource(newCertMeta)
}

// Revoke revokes the certificate for name and deletes
// it from storage.
func (c *acmeClient) Revoke(name string) error {
	if !c.config.certCache.storage.Exists(prefixSiteKey(c.config.CA, name)) {
		return fmt.Errorf("private key not found for %s", name)
	}

	certRes, err := c.config.loadCertResource(name)
	if err != nil {
		return err
	}

	err = c.acmeClient.RevokeCertificate(certRes.Certificate)
	if err != nil {
		return err
	}

	if c.config.OnEvent != nil {
		c.config.OnEvent("acme_cert_revoked", name)
	}

	err = c.config.certCache.storage.Delete(prefixSiteCert(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate file: %v", err)
	}
	err = c.config.certCache.storage.Delete(prefixSiteKey(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete private key: %v", err)
	}
	err = c.config.certCache.storage.Delete(prefixSiteMeta(c.config.CA, name))
	if err != nil {
		return fmt.Errorf("certificate revoked, but unable to delete certificate metadata: %v", err)
	}

	return nil
}

// namesObtaining is a set of hostnames with thread-safe
// methods. A name should be in this set only while this
// package is in the process of obtaining a certificate
// for the name. ACME challenges that are received for
// names which are not in this set were not initiated by
// this package and probably should not be handled by
// this package.
var namesObtaining = nameCoordinator{names: make(map[string]struct{})}

type nameCoordinator struct {
	names map[string]struct{}
	mu    sync.RWMutex
}

// Add adds names to c. It is safe for concurrent use.
func (c *nameCoordinator) Add(names []string) {
	c.mu.Lock()
	for _, name := range names {
		c.names[strings.ToLower(name)] = struct{}{}
	}
	c.mu.Unlock()
}

// Remove removes names from c. It is safe for concurrent use.
func (c *nameCoordinator) Remove(names []string) {
	c.mu.Lock()
	for _, name := range names {
		delete(c.names, strings.ToLower(name))
	}
	c.mu.Unlock()
}

// Has returns true if c has name. It is safe for concurrent use.
func (c *nameCoordinator) Has(name string) bool {
	hostname, _, err := net.SplitHostPort(name)
	if err != nil {
		hostname = name
	}
	c.mu.RLock()
	_, ok := c.names[strings.ToLower(hostname)]
	c.mu.RUnlock()
	return ok
}

// KnownACMECAs is a list of ACME directory endpoints of
// known, public, and trusted ACME-compatible certificate
// authorities.
var KnownACMECAs = []string{
	"https://acme-v02.api.letsencrypt.org/directory",
}
