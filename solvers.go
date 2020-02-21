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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
)

// httpSolver solves the HTTP challenge. It must be
// associated with a config and an address to use
// for solving the challenge. If multiple httpSolvers
// are initialized concurrently, the first one to
// begin will start the server, and the last one to
// finish will stop the server. This solver must be
// wrapped by a distributedSolver to work properly,
// because the only way the HTTP challenge handler
// can access the keyAuth material is by loading it
// from storage, which is done by distributedSolver.
type httpSolver struct {
	closed      int32 // accessed atomically
	acmeManager *ACMEManager
	address     string
}

// Present starts an HTTP server if none is already listening on s.address.
func (s *httpSolver) Present(domain, token, keyAuth string) error {
	solversMu.Lock()
	defer solversMu.Unlock()

	si := getSolverInfo(s.address)
	si.count++
	if si.listener != nil {
		return nil
	}

	var err error
	si.listener, err = net.Listen("tcp", s.address)
	if err != nil {
		if listenerAddressInUse(s.address) {
			// if it failed just because the socket is already in use, we
			// have no choice but to assume that whatever is using the socket
			// can answer the challenge already
			return nil
		}
		// otherwise, if the socket is not in use, something is wrong
		return fmt.Errorf("could not start listener for HTTP challenge server: %v", err)
	}

	// successfully bound socket, so start key auth HTTP server
	go s.serve(si)

	return nil
}

// serve is an HTTP server that serves only HTTP challenge responses.
func (s *httpSolver) serve(si *solverInfo) {
	httpServer := &http.Server{Handler: s.acmeManager.HTTPChallengeHandler(http.NewServeMux())}
	httpServer.SetKeepAlivesEnabled(false)
	err := httpServer.Serve(si.listener)
	if err != nil && atomic.LoadInt32(&s.closed) != 1 {
		log.Printf("[ERROR] key auth HTTP server: %v", err)
	}
	close(si.done)
}

// CleanUp cleans up the HTTP server if it is the last one to finish.
func (s *httpSolver) CleanUp(domain, token, keyAuth string) error {
	solversMu.Lock()
	defer solversMu.Unlock()
	si := getSolverInfo(s.address)
	si.count--
	if si.count == 0 {
		// last one out turns off the lights
		atomic.StoreInt32(&s.closed, 1)
		if si.listener != nil {
			si.listener.Close()
		}
		delete(solvers, s.address)
		<-si.done
	}
	return nil
}

// tlsALPNSolver is a type that can solve TLS-ALPN challenges.
// It must have an associated config and address on which to
// serve the challenge.
type tlsALPNSolver struct {
	// closed  int32 // accessed atomically
	config  *Config
	address string
}

// Present adds the certificate to the certificate cache and, if
// needed, starts a TLS server for answering TLS-ALPN challenges.
func (s *tlsALPNSolver) Present(domain, token, keyAuth string) error {
	// load the certificate into the cache; this isn't strictly necessary
	// if we're using the distributed solver since our GetCertificate
	// function will check storage for the keyAuth anyway, but it seems
	// like loading it into the cache is the right thing to do
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}
	certHash := hashCertificateChain(cert.Certificate)
	s.config.certCache.mu.Lock()
	s.config.certCache.cache[tlsALPNCertKeyName(domain)] = Certificate{
		Certificate: *cert,
		Names:       []string{domain},
		hash:        certHash, // perhaps not necesssary
	}
	s.config.certCache.mu.Unlock()

	// the rest of this function increments the
	// challenge count for the solver at this
	// listener address, and if necessary, starts
	// a simple TLS server

	solversMu.Lock()
	defer solversMu.Unlock()

	si := getSolverInfo(s.address)
	si.count++
	if si.listener != nil {
		return nil
	}

	si.listener, err = tls.Listen("tcp", s.address, s.config.TLSConfig())
	if err != nil {
		if listenerAddressInUse(s.address) {
			// if it failed just because the socket is already in use, we
			// have no choice but to assume that whatever is using the socket
			// can answer the challenge already
			return nil
		}
		// otherwise, if the socket is not in use, something is wrong
		return fmt.Errorf("could not start listener for TLS-ALPN challenge server: %v", err)
	}

	go func() {
		for {
			conn, err := si.listener.Accept()
			if err != nil {
				if atomic.LoadInt32(&si.closed) == 1 {
					return
				}
				log.Printf("[ERROR] TLS-ALPN challenge server: accept: %v", err)
				continue
			}
			go s.handleConn(conn)
		}
	}()

	return nil
}

// handleConn completes the TLS handshake and then closes conn.
func (*tlsALPNSolver) handleConn(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("[ERROR] TLS-ALPN challenge server: expected tls.Conn but got %T: %#v", conn, conn)
		return
	}
	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("[ERROR] TLS-ALPN challenge server: handshake: %v", err)
		return
	}
}

// CleanUp removes the challenge certificate from the cache, and if
// it is the last one to finish, stops the TLS server.
func (s *tlsALPNSolver) CleanUp(domain, token, keyAuth string) error {
	s.config.certCache.mu.Lock()
	delete(s.config.certCache.cache, tlsALPNCertKeyName(domain))
	s.config.certCache.mu.Unlock()

	solversMu.Lock()
	defer solversMu.Unlock()
	si := getSolverInfo(s.address)
	si.count--
	if si.count == 0 {
		// last one out turns off the lights
		atomic.StoreInt32(&si.closed, 1)
		if si.listener != nil {
			si.listener.Close()
		}
		delete(solvers, s.address)
		close(si.done)
	}

	return nil
}

// tlsALPNCertKeyName returns the key to use when caching a cert
// for use with the TLS-ALPN ACME challenge. It is simply to help
// avoid conflicts (although at time of writing, there shouldn't
// be, since the cert cache is keyed by hash of certificate chain).
func tlsALPNCertKeyName(sniName string) string {
	return sniName + ":acme-tls-alpn"
}

// distributedSolver allows the ACME HTTP-01 and TLS-ALPN challenges
// to be solved by an instance other than the one which initiated it.
// This is useful behind load balancers or in other cluster/fleet
// configurations. The only requirement is that the instance which
// initiates the challenge shares the same storage and locker with
// the others in the cluster. The storage backing the certificate
// cache in distributedSolver.config is crucial.
//
// Obviously, the instance which completes the challenge must be
// serving on the HTTPChallengePort for the HTTP-01 challenge or the
// TLSALPNChallengePort for the TLS-ALPN-01 challenge (or have all
// the packets port-forwarded) to receive and handle the request. The
// server which receives the challenge must handle it by checking to
// see if the challenge token exists in storage, and if so, decode it
// and use it to serve up the correct response. HTTPChallengeHandler
// in this package as well as the GetCertificate method implemented
// by a Config support and even require this behavior.
//
// In short: the only two requirements for cluster operation are
// sharing sync and storage, and using the facilities provided by
// this package for solving the challenges.
type distributedSolver struct {
	// The config with a certificate cache
	// with a reference to the storage to
	// use which is shared among all the
	// instances in the cluster - REQUIRED.
	acmeManager *ACMEManager

	// Since the distributedSolver is only a
	// wrapper over an actual solver, place
	// the actual solver here.
	providerServer challenge.Provider

	// The CA endpoint URL associated with
	// this solver.
	caURL string
}

// Present invokes the underlying solver's Present method
// and also stores domain, token, and keyAuth to the storage
// backing the certificate cache of dhs.acmeManager.
func (dhs distributedSolver) Present(domain, token, keyAuth string) error {
	infoBytes, err := json.Marshal(challengeInfo{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	})
	if err != nil {
		return err
	}

	err = dhs.acmeManager.config.Storage.Store(dhs.challengeTokensKey(domain), infoBytes)
	if err != nil {
		return err
	}

	err = dhs.providerServer.Present(domain, token, keyAuth)
	if err != nil {
		return fmt.Errorf("presenting with embedded provider: %v", err)
	}
	return nil
}

// CleanUp invokes the underlying solver's CleanUp method
// and also cleans up any assets saved to storage.
func (dhs distributedSolver) CleanUp(domain, token, keyAuth string) error {
	err := dhs.acmeManager.config.Storage.Delete(dhs.challengeTokensKey(domain))
	if err != nil {
		return err
	}
	err = dhs.providerServer.CleanUp(domain, token, keyAuth)
	if err != nil {
		return fmt.Errorf("cleaning up embedded provider: %v", err)
	}
	return nil
}

// challengeTokensPrefix returns the key prefix for challenge info.
func (dhs distributedSolver) challengeTokensPrefix() string {
	return path.Join(dhs.acmeManager.storageKeyCAPrefix(dhs.caURL), "challenge_tokens")
}

// challengeTokensKey returns the key to use to store and access
// challenge info for domain.
func (dhs distributedSolver) challengeTokensKey(domain string) string {
	return path.Join(dhs.challengeTokensPrefix(), StorageKeys.Safe(domain)+".json")
}

type challengeInfo struct {
	Domain, Token, KeyAuth string
}

// solverInfo associates a listener with the
// number of challenges currently using it.
type solverInfo struct {
	closed   int32 // accessed atomically
	count    int
	listener net.Listener
	done     chan struct{} // used to signal when cleanup is finished
}

// getSolverInfo gets a valid solverInfo struct for address.
func getSolverInfo(address string) *solverInfo {
	si, ok := solvers[address]
	if !ok {
		si = &solverInfo{done: make(chan struct{})}
		solvers[address] = si
	}
	return si
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

// The active challenge solvers, keyed by listener address,
// and protected by a mutex. Note that the creation of
// solver listeners and the incrementing of their counts
// are atomic operations guarded by this mutex.
var (
	solvers   = make(map[string]*solverInfo)
	solversMu sync.Mutex
)
