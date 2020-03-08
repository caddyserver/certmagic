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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Certificate is a tls.Certificate with associated metadata tacked on.
// Even if the metadata can be obtained by parsing the certificate,
// we are more efficient by extracting the metadata onto this struct,
// but at the cost of slightly higher memory use.
type Certificate struct {
	tls.Certificate

	// Names is the list of names this certificate is written for.
	// The first is the CommonName (if any), the rest are SAN.
	Names []string

	// The certificate's validity period.
	NotBefore, NotAfter time.Time

	// OCSP contains the certificate's parsed OCSP response.
	ocsp *ocsp.Response

	// The hex-encoded hash of this cert's chain's bytes.
	hash string

	// Whether this certificate is under our management
	managed bool

	// These fields are extracted to here mainly for custom
	// selection logic, which is optional; callers may wish
	// to use this information to choose a certificate when
	// more than one match the ClientHello
	CertMetadata
}

// NeedsRenewal returns true if the certificate is
// expiring soon (according to cfg) or has expired.
func (cert Certificate) NeedsRenewal(cfg *Config) bool {
	return currentlyInRenewalWindow(cert.NotBefore, cert.NotAfter, cfg.RenewalWindowRatio)
}

// currentlyInRenewalWindow returns true if the current time is
// within the renewal window, according to the given start/end
// dates and the ratio of the renewal window. If true is returned,
// the certificate being considered is due for renewal.
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

// CertMetadata is data extracted from a parsed x509
// certificate which is purely optional but can be
// useful when selecting which certificate to use
// if multiple match a ClientHello's ServerName.
// The more fields we add to this struct, the more
// memory use will increase at scale with large
// numbers of certificates in the cache.
type CertMetadata struct {
	Tags               []string // user-provided and arbitrary
	Subject            pkix.Name
	SerialNumber       *big.Int
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

// HasTag returns true if cm.Tags has tag.
func (cm CertMetadata) HasTag(tag string) bool {
	for _, t := range cm.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// CacheManagedCertificate loads the certificate for domain into the
// cache, from the TLS storage for managed certificates. It returns a
// copy of the Certificate that was put into the cache.
//
// This is a lower-level method; normally you'll call Manage() instead.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheManagedCertificate(domain string) (Certificate, error) {
	cert, err := cfg.loadManagedCertificate(domain)
	if err != nil {
		return cert, err
	}
	cfg.certCache.cacheCertificate(cert)
	cfg.emit("cached_managed_cert", cert.Names)
	return cert, nil
}

// loadManagedCertificate loads the managed certificate for domain,
// but it does not add it to the cache. It just loads from storage.
func (cfg *Config) loadManagedCertificate(domain string) (Certificate, error) {
	certRes, err := cfg.loadCertResource(domain)
	if err != nil {
		return Certificate{}, err
	}
	cert, err := makeCertificateWithOCSP(cfg.Storage, certRes.CertificatePEM, certRes.PrivateKeyPEM)
	if err != nil {
		return cert, err
	}
	cert.managed = true
	return cert, nil
}

// CacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// the in-memory cache.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMFile(certFile, keyFile string, tags []string) error {
	cert, err := makeCertificateFromDiskWithOCSP(cfg.Storage, certFile, keyFile)
	if err != nil {
		return err
	}
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	cfg.emit("cached_unmanaged_cert", cert.Names)
	return nil
}

// CacheUnmanagedTLSCertificate adds tlsCert to the certificate cache.
// It staples OCSP if possible.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedTLSCertificate(tlsCert tls.Certificate, tags []string) error {
	var cert Certificate
	err := fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return err
	}
	_, err = stapleOCSP(cfg.Storage, &cert, nil)
	if err != nil {
		log.Printf("[WARNING] Stapling OCSP: %v", err)
	}
	cfg.emit("cached_unmanaged_cert", cert.Names)
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	return nil
}

// CacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMBytes(certBytes, keyBytes []byte, tags []string) error {
	cert, err := makeCertificateWithOCSP(cfg.Storage, certBytes, keyBytes)
	if err != nil {
		return err
	}
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	cfg.emit("cached_unmanaged_cert", cert.Names)
	return nil
}

// makeCertificateFromDiskWithOCSP makes a Certificate by loading the
// certificate and key files. It fills out all the fields in
// the certificate except for the Managed and OnDemand flags.
// (It is up to the caller to set those.) It staples OCSP.
func makeCertificateFromDiskWithOCSP(storage Storage, certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return makeCertificateWithOCSP(storage, certPEMBlock, keyPEMBlock)
}

// makeCertificateWithOCSP is the same as makeCertificate except that it also
// staples OCSP to the certificate.
func makeCertificateWithOCSP(storage Storage, certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	cert, err := makeCertificate(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}
	_, err = stapleOCSP(storage, &cert, certPEMBlock)
	if err != nil {
		log.Printf("[WARNING] Stapling OCSP: %v", err)
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

// fillCertFromLeaf populates metadata fields on cert from tlsCert.
func fillCertFromLeaf(cert *Certificate, tlsCert tls.Certificate) error {
	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	cert.Certificate = tlsCert

	// the leaf cert should be the one for the site; it has what we need
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

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

	// save the hash of this certificate (chain) and
	// expiration date, for necessity and efficiency
	cert.hash = hashCertificateChain(cert.Certificate.Certificate)
	cert.NotBefore = leaf.NotBefore
	cert.NotAfter = leaf.NotAfter

	// these other fields are strictly optional to
	// store in their decoded forms, but they are
	// here for convenience in case the caller wishes
	// to select certificates using custom logic when
	// more than one may complete a handshake
	cert.Subject = leaf.Subject
	cert.SerialNumber = leaf.SerialNumber
	cert.PublicKeyAlgorithm = leaf.PublicKeyAlgorithm

	return nil
}

// managedCertInStorageExpiresSoon returns true if cert (being a
// managed certificate) is expiring within RenewDurationBefore.
// It returns false if there was an error checking the expiration
// of the certificate as found in storage, or if the certificate
// in storage is NOT expiring soon. A certificate that is expiring
// soon in our cache but is not expiring soon in storage probably
// means that another instance renewed the certificate in the
// meantime, and it would be a good idea to simply load the cert
// into our cache rather than repeating the renewal process again.
func (cfg *Config) managedCertInStorageExpiresSoon(cert Certificate) (bool, error) {
	certRes, err := cfg.loadCertResource(cert.Names[0])
	if err != nil {
		return false, err
	}
	tlsCert, err := tls.X509KeyPair(certRes.CertificatePEM, certRes.PrivateKeyPEM)
	if err != nil {
		return false, err
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return false, err
	}
	return currentlyInRenewalWindow(leaf.NotBefore, leaf.NotAfter, cfg.RenewalWindowRatio), nil
}

// reloadManagedCertificate reloads the certificate corresponding to the name(s)
// on oldCert into the cache, from storage. This also replaces the old certificate
// with the new one, so that all configurations that used the old cert now point
// to the new cert. It assumes that the new certificate for oldCert.Names[0] is
// already in storage.
func (cfg *Config) reloadManagedCertificate(oldCert Certificate) error {
	log.Printf("[INFO] Reloading managed certificate for %v", oldCert.Names)
	newCert, err := cfg.loadManagedCertificate(oldCert.Names[0])
	if err != nil {
		return fmt.Errorf("loading managed certificate for %v from storage: %v", oldCert.Names, err)
	}
	cfg.certCache.replaceCertificate(oldCert, newCert)
	return nil
}

// HostQualifiesForPublicCert returns true if the subject
// name appears eligible for automagic TLS with a public
// CA such as Let's Encrypt. For example: localhost, empty
// string, and IP addresses are not eligible because we
// cannot obtain certificates for those names with a public
// CA. Wildcard names are allowed, as long as they conform
// to CABF requirements (only one wildcard label, and it
// must be the left-most label). Names with certain special
// characters that are commonly accidental are also rejected.
func HostQualifiesForPublicCert(host string) bool {
	return host != "localhost" && // localhost is ineligible

		!strings.HasSuffix(host, ".localhost") && // localhost TLD is ineligible

		// hostname must not be empty
		strings.TrimSpace(host) != "" &&

		// only one wildcard label allowed, and it must be left-most
		(!strings.Contains(host, "*") ||
			(strings.Count(host, "*") == 1 &&
				strings.HasPrefix(host, "*."))) &&

		// must not start or end with a dot
		!strings.HasPrefix(host, ".") &&
		!strings.HasSuffix(host, ".") &&

		// must not contain other common special characters
		!strings.ContainsAny(host, "()[]{}<>\\/!@#$%^&|:;+='\"") &&

		// cannot be an IP address (as of yet), see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		net.ParseIP(host) == nil
}
