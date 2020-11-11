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
	"fmt"
	weakrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())
}

// acmeClient holds state necessary for us to perform
// ACME operations for certificate management. Call
// ACMEManager.newACMEClient() to get a valid one to .
type acmeClient struct {
	mgr        *ACMEManager
	acmeClient *acmez.Client
	account    acme.Account
}

// newACMEClient creates the underlying ACME library client type.
// If useTestCA is true, am.TestCA will be used if it is set;
// otherwise, the primary CA will still be used.
func (am *ACMEManager) newACMEClient(ctx context.Context, useTestCA, interactive bool) (*acmeClient, error) {
	// ensure defaults are filled in
	var caURL string
	if useTestCA {
		caURL = am.TestCA
	}
	if caURL == "" {
		caURL = am.CA
	}
	if caURL == "" {
		caURL = DefaultACME.CA
	}
	certObtainTimeout := am.CertObtainTimeout
	if certObtainTimeout == 0 {
		certObtainTimeout = DefaultACME.CertObtainTimeout
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

	// look up or create the ACME account
	account, err := am.getAccount(caURL, am.Email)
	if err != nil {
		return nil, fmt.Errorf("getting ACME account: %v", err)
	}

	// set up the dialers and resolver for the ACME client's HTTP client
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 2 * time.Minute,
	}
	if am.Resolver != "" {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout: 15 * time.Second,
				}).DialContext(ctx, network, am.Resolver)
			},
		}
	}

	// TODO: we could potentially reuse the HTTP transport and client
	hc := am.httpClient // TODO: is this racey?
	if am.httpClient == nil {
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
			ForceAttemptHTTP2:     true,
		}
		if am.TrustedRoots != nil {
			transport.TLSClientConfig = &tls.Config{
				RootCAs: am.TrustedRoots,
			}
		}

		hc = &http.Client{
			Transport: transport,
			Timeout:   HTTPTimeout,
		}

		am.httpClient = hc
	}

	client := &acmez.Client{
		Client: &acme.Client{
			Directory:   caURL,
			PollTimeout: certObtainTimeout,
			UserAgent:   buildUAString(),
			HTTPClient:  hc,
		},
		ChallengeSolvers: make(map[string]acmez.Solver),
	}
	if am.Logger != nil {
		l := am.Logger.Named("acme_client")
		client.Client.Logger, client.Logger = l, l
	}

	// configure challenges (most of the time, DNS challenge is
	// exclusive of other ones because it is usually only used
	// in situations where the default challenges would fail)
	if am.DNS01Solver == nil {
		// enable HTTP-01 challenge
		if !am.DisableHTTPChallenge {
			useHTTPPort := HTTPChallengePort
			if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
				useHTTPPort = HTTPPort
			}
			if am.AltHTTPPort > 0 {
				useHTTPPort = am.AltHTTPPort
			}
			client.ChallengeSolvers[acme.ChallengeTypeHTTP01] = distributedSolver{
				storage:                am.config.Storage,
				storageKeyIssuerPrefix: am.storageKeyCAPrefix(client.Directory),
				solver: &httpSolver{
					acmeManager: am,
					address:     net.JoinHostPort(am.ListenHost, strconv.Itoa(useHTTPPort)),
				},
			}
		}

		// enable TLS-ALPN-01 challenge
		if !am.DisableTLSALPNChallenge {
			useTLSALPNPort := TLSALPNChallengePort
			if HTTPSPort > 0 && HTTPSPort != TLSALPNChallengePort {
				useTLSALPNPort = HTTPSPort
			}
			if am.AltTLSALPNPort > 0 {
				useTLSALPNPort = am.AltTLSALPNPort
			}
			client.ChallengeSolvers[acme.ChallengeTypeTLSALPN01] = distributedSolver{
				storage:                am.config.Storage,
				storageKeyIssuerPrefix: am.storageKeyCAPrefix(client.Directory),
				solver: &tlsALPNSolver{
					config:  am.config,
					address: net.JoinHostPort(am.ListenHost, strconv.Itoa(useTLSALPNPort)),
				},
			}
		}
	} else {
		// use DNS challenge exclusively
		client.ChallengeSolvers[acme.ChallengeTypeDNS01] = am.DNS01Solver
	}

	// register account if it is new
	if account.Status == "" {
		if am.NewAccountFunc != nil {
			err = am.NewAccountFunc(ctx, am, account)
			if err != nil {
				return nil, fmt.Errorf("account pre-registration callback: %v", err)
			}
		}

		// agree to terms
		if interactive {
			if !am.Agreed {
				var termsURL string
				dir, err := client.GetDirectory(ctx)
				if err != nil {
					return nil, fmt.Errorf("getting directory: %w", err)
				}
				if dir.Meta != nil {
					termsURL = dir.Meta.TermsOfService
				}
				if termsURL != "" {
					am.Agreed = am.askUserAgreement(termsURL)
					if !am.Agreed {
						return nil, fmt.Errorf("user must agree to CA terms")
					}
				}
			}
		} else {
			// can't prompt a user who isn't there; they should
			// have reviewed the terms beforehand
			am.Agreed = true
		}
		account.TermsOfServiceAgreed = am.Agreed

		// associate account with external binding, if configured
		if am.ExternalAccount != nil {
			err := account.SetExternalAccountBinding(ctx, client.Client, *am.ExternalAccount)
			if err != nil {
				return nil, err
			}
		}

		// create account
		account, err = client.NewAccount(ctx, account)
		if err != nil {
			return nil, fmt.Errorf("registering account with server: %w", err)
		}

		// persist the account to storage
		err = am.saveAccount(caURL, account)
		if err != nil {
			return nil, fmt.Errorf("could not save account: %v", err)
		}
	}

	c := &acmeClient{
		mgr:        am,
		acmeClient: client,
		account:    account,
	}

	return c, nil
}

func (c *acmeClient) throttle(ctx context.Context, names []string) error {
	// throttling is scoped to CA + account email
	rateLimiterKey := c.acmeClient.Directory + "," + c.mgr.Email
	rateLimitersMu.Lock()
	rl, ok := rateLimiters[rateLimiterKey]
	if !ok {
		rl = NewRateLimiter(RateLimitEvents, RateLimitEventsWindow)
		rateLimiters[rateLimiterKey] = rl
		// TODO: stop rate limiter when it is garbage-collected...
	}
	rateLimitersMu.Unlock()
	if c.mgr.Logger != nil {
		c.mgr.Logger.Info("waiting on internal rate limiter", zap.Strings("identifiers", names))
	}
	err := rl.Wait(ctx)
	if err != nil {
		return err
	}
	if c.mgr.Logger != nil {
		c.mgr.Logger.Info("done waiting on internal rate limiter", zap.Strings("identifiers", names))
	}
	return nil
}

func (c *acmeClient) usingTestCA() bool {
	return c.mgr.TestCA != "" && c.acmeClient.Directory == c.mgr.TestCA
}

func (c *acmeClient) revoke(ctx context.Context, cert *x509.Certificate, reason int) error {
	return c.acmeClient.RevokeCertificate(ctx, c.account,
		cert, c.account.PrivateKey, reason)
}

func buildUAString() string {
	ua := "CertMagic"
	if UserAgent != "" {
		ua = UserAgent + " " + ua
	}
	return ua
}

// These internal rate limits are designed to prevent accidentally
// firehosing a CA's ACME endpoints. They are not intended to
// replace or replicate the CA's actual rate limits.
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

	// RateLimitEvents is how many new events can be allowed
	// in RateLimitEventsWindow.
	RateLimitEvents = 10

	// RateLimitEventsWindow is the size of the sliding
	// window that throttles events.
	RateLimitEventsWindow = 1 * time.Minute
)

// Some default values passed down to the underlying ACME client.
var (
	UserAgent   string
	HTTPTimeout = 30 * time.Second
)
