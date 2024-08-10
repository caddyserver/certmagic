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
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mholt/acmez/v2/acme"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// Certificate is a tls.Certificate with associated metadata tacked on.
// Even if the metadata can be obtained by parsing the certificate,
// we are more efficient by extracting the metadata onto this struct,
// but at the cost of slightly higher memory use.
type Certificate struct {
	tls.Certificate

	// Names is the list of subject names this
	// certificate is signed for.
	Names []string

	// Optional; user-provided, and arbitrary.
	Tags []string

	// OCSP contains the certificate's parsed OCSP response.
	// It is not necessarily the response that is stapled
	// (e.g. if the status is not Good), it is simply the
	// most recent OCSP response we have for this certificate.
	ocsp *ocsp.Response

	// The hex-encoded hash of this cert's chain's DER bytes.
	hash string

	// Whether this certificate is under our management.
	managed bool

	// The unique string identifying the issuer of this certificate.
	issuerKey string

	// ACME Renewal Information, if available
	ari acme.RenewalInfo
}

// Empty returns true if the certificate struct is not filled out; at
// least the tls.Certificate.Certificate field is expected to be set.
func (cert Certificate) Empty() bool {
	return len(cert.Certificate.Certificate) == 0
}

// Hash returns a checksum of the certificate chain's DER-encoded bytes.
func (cert Certificate) Hash() string { return cert.hash }

// NeedsRenewal returns true if the certificate is expiring
// soon (according to ARI and/or cfg) or has expired.
func (cert Certificate) NeedsRenewal(cfg *Config) bool {
	return cfg.certNeedsRenewal(cert.Leaf, cert.ari, true)
}

// certNeedsRenewal consults ACME Renewal Info (ARI) and certificate expiration to determine
// whether the leaf certificate needs to be renewed yet. If true is returned, the certificate
// should be renewed as soon as possible. The reasoning for a true return value is logged
// unless emitLogs is false; this can be useful to suppress noisy logs in the case where you
// first call this to determine if a cert in memory needs renewal, and then right after you
// call it again to see if the cert in storage still needs renewal -- you probably don't want
// to log the second time for checking the cert in storage which is mainly for synchronization.
func (cfg *Config) certNeedsRenewal(leaf *x509.Certificate, ari acme.RenewalInfo, emitLogs bool) bool {
	expiration := expiresAt(leaf)

	var logger *zap.Logger
	if emitLogs {
		logger = cfg.Logger.With(
			zap.Strings("subjects", leaf.DNSNames),
			zap.Time("expiration", expiration),
			zap.String("ari_cert_id", ari.UniqueIdentifier),
			zap.Timep("next_ari_update", ari.RetryAfter),
			zap.Duration("renew_check_interval", cfg.certCache.options.RenewCheckInterval),
			zap.Time("window_start", ari.SuggestedWindow.Start),
			zap.Time("window_end", ari.SuggestedWindow.End))
	} else {
		logger = zap.NewNop()
	}

	if !cfg.DisableARI {
		// first check ARI: if it says it's time to renew, it's time to renew
		// (notice that we don't strictly require an ARI window to also exist; we presume
		// that if a time has been selected, a window does or did exist, even if it didn't
		// get stored/encoded for some reason - but also: this allows administrators to
		// manually or explicitly schedule a renewal time indepedently of ARI which could
		// be useful)
		selectedTime := ari.SelectedTime

		// if, for some reason a random time in the window hasn't been selected yet, but an ARI
		// window does exist, we can always improvise one... even if this is called repeatedly,
		// a random time is a random time, whether you generate it once or more :D
		// (code borrowed from our acme package)
		if selectedTime.IsZero() &&
			(!ari.SuggestedWindow.Start.IsZero() && !ari.SuggestedWindow.End.IsZero()) {
			start, end := ari.SuggestedWindow.Start.Unix()+1, ari.SuggestedWindow.End.Unix()
			selectedTime = time.Unix(rand.Int63n(end-start)+start, 0).UTC()
			logger.Warn("no renewal time had been selected with ARI; chose an ephemeral one for now",
				zap.Time("ephemeral_selected_time", selectedTime))
		}

		// if a renewal time has been selected, start with that
		if !selectedTime.IsZero() {
			// ARI spec recommends an algorithm that renews after the randomly-selected
			// time OR just before it if the next waking time would be after it; this
			// cutoff can actually be before the start of the renewal window, but the spec
			// author says that's OK: https://github.com/aarongable/draft-acme-ari/issues/71
			cutoff := ari.SelectedTime.Add(-cfg.certCache.options.RenewCheckInterval)
			if time.Now().After(cutoff) {
				logger.Info("certificate needs renewal based on ARI window",
					zap.Time("selected_time", selectedTime),
					zap.Time("renewal_cutoff", cutoff))
				return true
			}

			// according to ARI, we are not ready to renew; however, we do not rely solely on
			// ARI calculations... what if there is a bug in our implementation, or in the
			// server's, or the stored metadata? for redundancy, give credence to the expiration
			// date; ignore ARI if we are past a "dangerously close" limit, to avoid any
			// possibility of a bug in ARI compromising a site's uptime: we should always always
			// always give heed to actual validity period
			if currentlyInRenewalWindow(leaf.NotBefore, expiration, 1.0/20.0) {
				logger.Warn("certificate is in emergency renewal window; superceding ARI",
					zap.Duration("remaining", time.Until(expiration)),
					zap.Time("renewal_cutoff", cutoff))
				return true
			}
		}
	}

	// the normal check, in the absence of ARI, is to determine if we're near enough (or past)
	// the expiration date based on the configured remaining:lifetime ratio
	if currentlyInRenewalWindow(leaf.NotBefore, expiration, cfg.RenewalWindowRatio) {
		logger.Info("certificate is in configured renewal window based on expiration date",
			zap.Duration("remaining", time.Until(expiration)))
		return true
	}

	// finally, if the certificate is expiring imminently, always attempt a renewal;
	// we check both a (very low) lifetime ratio and also a strict difference between
	// the time until expiration and the interval at which we run the standard maintenance
	// routine to check for renewals, to accommodate both exceptionally long and short
	// cert lifetimes
	if currentlyInRenewalWindow(leaf.NotBefore, expiration, 1.0/50.0) ||
		time.Until(expiration) < cfg.certCache.options.RenewCheckInterval*5 {
		logger.Warn("certificate is in emergency renewal window; expiration imminent",
			zap.Duration("remaining", time.Until(expiration)))
		return true
	}

	return false
}

// Expired returns true if the certificate has expired.
func (cert Certificate) Expired() bool {
	if cert.Leaf == nil {
		// ideally cert.Leaf would never be nil, but this can happen for
		// "synthetic" certs like those made to solve the TLS-ALPN challenge
		// which adds a special cert directly  to the cache, since
		// tls.X509KeyPair() discards the leaf; oh well
		return false
	}
	return time.Now().After(expiresAt(cert.Leaf))
}

// currentlyInRenewalWindow returns true if the current time is within
// (or after) the renewal window, according to the given start/end
// dates and the ratio of the renewal window. If true is returned,
// the certificate being considered is due for renewal. The ratio
// is remaining:total time, i.e. 1/3 = 1/3 of lifetime remaining,
// or 9/10 = 9/10 of time lifetime remaining.
func currentlyInRenewalWindow(notBefore, notAfter time.Time, renewalWindowRatio float64) bool {
	if notAfter.IsZero() {
		return false
	}
	lifetime := notAfter.Sub(notBefore)
	if renewalWindowRatio == 0 {
		renewalWindowRatio = DefaultRenewalWindowRatio
	}
	renewalWindow := time.Duration(float64(lifetime) * renewalWindowRatio)
	renewalWindowStart := notAfter.Add(-renewalWindow)
	return time.Now().After(renewalWindowStart)
}

// HasTag returns true if cert.Tags has tag.
func (cert Certificate) HasTag(tag string) bool {
	for _, t := range cert.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// expiresAt return the time that a certificate expires. Account for the 1s
// resolution of ASN.1 UTCTime/GeneralizedTime by including the extra fraction
// of a second of certificate validity beyond the NotAfter value.
func expiresAt(cert *x509.Certificate) time.Time {
	if cert == nil {
		return time.Time{}
	}
	return cert.NotAfter.Truncate(time.Second).Add(1 * time.Second)
}

// CacheManagedCertificate loads the certificate for domain into the
// cache, from the TLS storage for managed certificates. It returns a
// copy of the Certificate that was put into the cache.
//
// This is a lower-level method; normally you'll call Manage() instead.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheManagedCertificate(ctx context.Context, domain string) (Certificate, error) {
	domain = cfg.transformSubject(ctx, nil, domain)
	cert, err := cfg.loadManagedCertificate(ctx, domain)
	if err != nil {
		return cert, err
	}
	cfg.certCache.cacheCertificate(cert)
	cfg.emit(ctx, "cached_managed_cert", map[string]any{"sans": cert.Names})
	return cert, nil
}

// loadManagedCertificate loads the managed certificate for domain from any
// of the configured issuers' storage locations, but it does not add it to
// the cache. It just loads from storage and returns it.
func (cfg *Config) loadManagedCertificate(ctx context.Context, domain string) (Certificate, error) {
	certRes, err := cfg.loadCertResourceAnyIssuer(ctx, domain)
	if err != nil {
		return Certificate{}, err
	}
	cert, err := cfg.makeCertificateWithOCSP(ctx, certRes.CertificatePEM, certRes.PrivateKeyPEM)
	if err != nil {
		return cert, err
	}
	cert.managed = true
	cert.issuerKey = certRes.issuerKey
	if ari, err := certRes.getARI(); err == nil && ari != nil {
		cert.ari = *ari
	}
	return cert, nil
}

// getARI unpacks ACME Renewal Information from the issuer data, if available.
// It is only an error if there is invalid JSON.
func (certRes CertificateResource) getARI() (*acme.RenewalInfo, error) {
	acmeData, err := certRes.getACMEData()
	if err != nil {
		return nil, err
	}
	return acmeData.RenewalInfo, nil
}

// getACMEData returns the ACME certificate metadata from the IssuerData, but
// note that a non-ACME-issued certificate may return an empty value and nil
// since the JSON may still decode successfully but just not match any or all
// of the fields. Remember that the IssuerKey is used to store and access the
// cert files in the first place (it is part of the path) so in theory if you
// load a CertificateResource from an ACME issuer it should work as expected.
func (certRes CertificateResource) getACMEData() (acme.Certificate, error) {
	if len(certRes.IssuerData) == 0 {
		return acme.Certificate{}, nil
	}
	var acmeCert acme.Certificate
	err := json.Unmarshal(certRes.IssuerData, &acmeCert)
	return acmeCert, err
}

// CacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// the in-memory cache and returns the hash, useful for removing from the cache.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMFile(ctx context.Context, certFile, keyFile string, tags []string) (string, error) {
	cert, err := cfg.makeCertificateFromDiskWithOCSP(ctx, certFile, keyFile)
	if err != nil {
		return "", err
	}
	cert.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	cfg.emit(ctx, "cached_unmanaged_cert", map[string]any{"sans": cert.Names})
	return cert.hash, nil
}

// CacheUnmanagedTLSCertificate adds tlsCert to the certificate cache
//
//	and returns the hash, useful for removing from the cache.
//
// It staples OCSP if possible.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedTLSCertificate(ctx context.Context, tlsCert tls.Certificate, tags []string) (string, error) {
	var cert Certificate
	err := fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return "", err
	}
	if time.Now().After(cert.Leaf.NotAfter) {
		cfg.Logger.Warn("unmanaged certificate has expired",
			zap.Time("not_after", cert.Leaf.NotAfter),
			zap.Strings("sans", cert.Names))
	} else if time.Until(cert.Leaf.NotAfter) < 24*time.Hour {
		cfg.Logger.Warn("unmanaged certificate expires within 1 day",
			zap.Time("not_after", cert.Leaf.NotAfter),
			zap.Strings("sans", cert.Names))
	}
	err = stapleOCSP(ctx, cfg.OCSP, cfg.Storage, &cert, nil)
	if err != nil {
		cfg.Logger.Warn("stapling OCSP", zap.Error(err))
	}
	cfg.emit(ctx, "cached_unmanaged_cert", map[string]any{"sans": cert.Names})
	cert.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	return cert.hash, nil
}

// CacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory,  and returns the hash,
// which is useful for removing from the cache.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMBytes(ctx context.Context, certBytes, keyBytes []byte, tags []string) (string, error) {
	cert, err := cfg.makeCertificateWithOCSP(ctx, certBytes, keyBytes)
	if err != nil {
		return "", err
	}
	cert.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	cfg.emit(ctx, "cached_unmanaged_cert", map[string]any{"sans": cert.Names})
	return cert.hash, nil
}

// makeCertificateFromDiskWithOCSP makes a Certificate by loading the
// certificate and key files. It fills out all the fields in
// the certificate except for the Managed and OnDemand flags.
// (It is up to the caller to set those.) It staples OCSP.
func (cfg Config) makeCertificateFromDiskWithOCSP(ctx context.Context, certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return cfg.makeCertificateWithOCSP(ctx, certPEMBlock, keyPEMBlock)
}

// makeCertificateWithOCSP is the same as makeCertificate except that it also
// staples OCSP to the certificate.
func (cfg Config) makeCertificateWithOCSP(ctx context.Context, certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	cert, err := makeCertificate(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}
	err = stapleOCSP(ctx, cfg.OCSP, cfg.Storage, &cert, certPEMBlock)
	if err != nil {
		cfg.Logger.Warn("stapling OCSP", zap.Error(err), zap.Strings("identifiers", cert.Names))
	}
	return cert, nil
}

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate with necessary metadata from parsing its bytes filled into
// its struct fields for convenience (except for the OnDemand and Managed
// flags; it is up to the caller to set those properties!). This function
// does NOT staple OCSP.
func makeCertificate(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	var cert Certificate

	// Convert to a tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}

	// Extract necessary metadata
	err = fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return cert, err
	}

	return cert, nil
}

// fillCertFromLeaf populates cert from tlsCert. If it succeeds, it
// guarantees that cert.Leaf is non-nil.
func fillCertFromLeaf(cert *Certificate, tlsCert tls.Certificate) error {
	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	cert.Certificate = tlsCert

	// the leaf cert should be the one for the site; we must set
	// the tls.Certificate.Leaf field so that TLS handshakes are
	// more efficient
	leaf := cert.Certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return err
		}
		cert.Certificate.Leaf = leaf
	}

	// for convenience, we do want to assemble all the
	// subjects on the certificate into one list
	if leaf.Subject.CommonName != "" { // TODO: CommonName is deprecated
		cert.Names = []string{strings.ToLower(leaf.Subject.CommonName)}
	}
	for _, name := range leaf.DNSNames {
		if name != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(name))
		}
	}
	for _, ip := range leaf.IPAddresses {
		if ipStr := ip.String(); ipStr != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(ipStr))
		}
	}
	for _, email := range leaf.EmailAddresses {
		if email != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(email))
		}
	}
	for _, u := range leaf.URIs {
		if u.String() != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, u.String())
		}
	}
	if len(cert.Names) == 0 {
		return fmt.Errorf("certificate has no names")
	}

	cert.hash = hashCertificateChain(cert.Certificate.Certificate)

	return nil
}

// managedCertInStorageNeedsRenewal returns true if cert (being a
// managed certificate) is expiring soon (according to cfg) or if
// ACME Renewal Information (ARI) is available and says that it is
// time to renew (it uses existing ARI; it does not update it).
// It returns false if there was an error, the cert is not expiring
// soon, and ARI window is still future. A certificate that is expiring
// soon in our cache but is not expiring soon in storage probably
// means that another instance renewed the certificate in the
// meantime, and it would be a good idea to simply load the cert
// into our cache rather than repeating the renewal process again.
func (cfg *Config) managedCertInStorageNeedsRenewal(ctx context.Context, cert Certificate) (bool, error) {
	certRes, err := cfg.loadCertResourceAnyIssuer(ctx, cert.Names[0])
	if err != nil {
		return false, err
	}
	_, _, needsRenew := cfg.managedCertNeedsRenewal(certRes, false)
	return needsRenew, nil
}

// reloadManagedCertificate reloads the certificate corresponding to the name(s)
// on oldCert into the cache, from storage. This also replaces the old certificate
// with the new one, so that all configurations that used the old cert now point
// to the new cert. It assumes that the new certificate for oldCert.Names[0] is
// already in storage. It returns the newly-loaded certificate if successful.
func (cfg *Config) reloadManagedCertificate(ctx context.Context, oldCert Certificate) (Certificate, error) {
	cfg.Logger.Info("reloading managed certificate", zap.Strings("identifiers", oldCert.Names))
	newCert, err := cfg.loadManagedCertificate(ctx, oldCert.Names[0])
	if err != nil {
		return Certificate{}, fmt.Errorf("loading managed certificate for %v from storage: %v", oldCert.Names, err)
	}
	cfg.certCache.replaceCertificate(oldCert, newCert)
	return newCert, nil
}

// SubjectQualifiesForCert returns true if subj is a name which,
// as a quick sanity check, looks like it could be the subject
// of a certificate. Requirements are:
// - must not be empty
// - must not start or end with a dot (RFC 1034; RFC 6066 section 3)
// - must not contain common accidental special characters
func SubjectQualifiesForCert(subj string) bool {
	// must not be empty
	return strings.TrimSpace(subj) != "" &&

		// must not start or end with a dot
		!strings.HasPrefix(subj, ".") &&
		!strings.HasSuffix(subj, ".") &&

		// if it has a wildcard, must be a left-most label (or exactly "*"
		// which won't be trusted by browsers but still technically works)
		(!strings.Contains(subj, "*") || strings.HasPrefix(subj, "*.") || subj == "*") &&

		// must not contain other common special characters
		!strings.ContainsAny(subj, "()[]{}<> \t\n\"\\!@#$%^&|;'+=")
}

// SubjectQualifiesForPublicCert returns true if the subject
// name appears eligible for automagic TLS with a public
// CA such as Let's Encrypt. For example: internal IP addresses
// and localhost are not eligible because we cannot obtain certs
// for those names with a public CA. Wildcard names are
// allowed, as long as they conform to CABF requirements (only
// one wildcard label, and it must be the left-most label).
func SubjectQualifiesForPublicCert(subj string) bool {
	// must at least qualify for a certificate
	return SubjectQualifiesForCert(subj) &&

		// loopback hosts and internal IPs are ineligible
		!SubjectIsInternal(subj) &&

		// only one wildcard label allowed, and it must be left-most, with 3+ labels
		(!strings.Contains(subj, "*") ||
			(strings.Count(subj, "*") == 1 &&
				strings.Count(subj, ".") > 1 &&
				len(subj) > 2 &&
				strings.HasPrefix(subj, "*.")))
}

// SubjectIsIP returns true if subj is an IP address.
func SubjectIsIP(subj string) bool {
	return net.ParseIP(subj) != nil
}

// SubjectIsInternal returns true if subj is an internal-facing
// hostname or address, including localhost/loopback hosts.
// Ports are ignored, if present.
func SubjectIsInternal(subj string) bool {
	subj = strings.ToLower(strings.TrimSuffix(hostOnly(subj), "."))
	return subj == "localhost" ||
		strings.HasSuffix(subj, ".localhost") ||
		strings.HasSuffix(subj, ".local") ||
		strings.HasSuffix(subj, ".internal") ||
		strings.HasSuffix(subj, ".home.arpa") ||
		isInternalIP(subj)
}

// isInternalIP returns true if the IP of addr
// belongs to a private network IP range. addr
// must only be an IP or an IP:port combination.
func isInternalIP(addr string) bool {
	privateNetworks := []string{
		"127.0.0.0/8", // IPv4 loopback
		"0.0.0.0/16",
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/7",          // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	}
	host := hostOnly(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, privateNetwork := range privateNetworks {
		_, ipnet, _ := net.ParseCIDR(privateNetwork)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly returns only the host portion of hostport.
// If there is no port or if there is an error splitting
// the port off, the whole input string is returned.
func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // OK; probably had no port to begin with
	}
	return host
}

// MatchWildcard returns true if subject (a candidate DNS name)
// matches wildcard (a reference DNS name), mostly according to
// RFC 6125-compliant wildcard rules. See also RFC 2818 which
// states that IP addresses must match exactly, but this function
// does not attempt to distinguish IP addresses from internal or
// external DNS names that happen to look like IP addresses.
// It uses DNS wildcard matching logic and is case-insensitive.
// https://tools.ietf.org/html/rfc2818#section-3.1
func MatchWildcard(subject, wildcard string) bool {
	subject, wildcard = strings.ToLower(subject), strings.ToLower(wildcard)
	if subject == wildcard {
		return true
	}
	if !strings.Contains(wildcard, "*") {
		return false
	}
	labels := strings.Split(subject, ".")
	for i := range labels {
		if labels[i] == "" {
			continue // invalid label
		}
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if candidate == wildcard {
			return true
		}
	}
	return false
}
