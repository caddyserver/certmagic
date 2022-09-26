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
	"reflect"
	"testing"
	"time"
)

func TestUnexportedGetCertificate(t *testing.T) {
	certCache := &Cache{cache: make(map[string]Certificate), cacheIndex: make(map[string][]string), logger: defaultTestLogger}
	cfg := &Config{Logger: defaultTestLogger, certCache: certCache}

	// When cache is empty
	if _, matched, defaulted := cfg.getCertificateFromCache(&tls.ClientHelloInfo{ServerName: "example.com"}); matched || defaulted {
		t.Errorf("Got a certificate when cache was empty; matched=%v, defaulted=%v", matched, defaulted)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}}
	certCache.cache["0xdeadbeef"] = firstCert
	certCache.cacheIndex["example.com"] = []string{"0xdeadbeef"}
	if cert, matched, defaulted := cfg.getCertificateFromCache(&tls.ClientHelloInfo{ServerName: "example.com"}); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for 'example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When retrieving wildcard certificate
	certCache.cache["0xb01dface"] = Certificate{Names: []string{"*.example.com"}}
	certCache.cacheIndex["*.example.com"] = []string{"0xb01dface"}
	if cert, matched, defaulted := cfg.getCertificateFromCache(&tls.ClientHelloInfo{ServerName: "sub.example.com"}); !matched || defaulted || cert.Names[0] != "*.example.com" {
		t.Errorf("Didn't get wildcard cert for 'sub.example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When no certificate matches and SNI is provided, return no certificate (should be TLS alert)
	if cert, matched, defaulted := cfg.getCertificateFromCache(&tls.ClientHelloInfo{ServerName: "nomatch"}); matched || defaulted {
		t.Errorf("Expected matched=false, defaulted=false; but got matched=%v, defaulted=%v (cert: %v)", matched, defaulted, cert)
	}
}

func TestCacheCertificate(t *testing.T) {
	certCache := &Cache{cache: make(map[string]Certificate), cacheIndex: make(map[string][]string), logger: defaultTestLogger}

	certCache.cacheCertificate(Certificate{Names: []string{"example.com", "sub.example.com"}, hash: "foobar", Certificate: tls.Certificate{Leaf: &x509.Certificate{NotAfter: time.Now()}}})
	if len(certCache.cache) != 1 {
		t.Errorf("Expected length of certificate cache to be 1")
	}
	if _, ok := certCache.cache["foobar"]; !ok {
		t.Error("Expected first cert to be cached by key 'foobar', but it wasn't")
	}
	if _, ok := certCache.cacheIndex["example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'example.com', but it wasn't")
	}
	if _, ok := certCache.cacheIndex["sub.example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'sub.example.com', but it wasn't")
	}

	// using same cache; and has cert with overlapping name, but different hash
	certCache.cacheCertificate(Certificate{Names: []string{"example.com"}, hash: "barbaz", Certificate: tls.Certificate{Leaf: &x509.Certificate{NotAfter: time.Now()}}})
	if _, ok := certCache.cache["barbaz"]; !ok {
		t.Error("Expected second cert to be cached by key 'barbaz.com', but it wasn't")
	}
	if hashes, ok := certCache.cacheIndex["example.com"]; !ok {
		t.Error("Expected second cert to be keyed by 'example.com', but it wasn't")
	} else if !reflect.DeepEqual(hashes, []string{"foobar", "barbaz"}) {
		t.Errorf("Expected second cert to map to 'barbaz' but it was %v instead", hashes)
	}
}

func TestSubjectQualifiesForCert(t *testing.T) {
	for i, test := range []struct {
		host   string
		expect bool
	}{
		{"hostname", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"Sub.Example.COM", true},
		{"127.0.0.1", true},
		{"127.0.1.5", true},
		{"69.123.43.94", true},
		{"::1", true},
		{"::", true},
		{"0.0.0.0", true},
		{"", false},
		{" ", false},
		{"*.example.com", true},
		{"*.*.example.com", true},
		{"sub.*.example.com", false},
		{"*sub.example.com", false},
		{"**.tld", false},
		{"*", true},
		{"*.tld", true},
		{".tld", false},
		{"example.com.", false},
		{"localhost", true},
		{"foo.localhost", true},
		{"local", true},
		{"192.168.1.3", true},
		{"10.0.2.1", true},
		{"169.112.53.4", true},
		{"$hostname", false},
		{"%HOSTNAME%", false},
		{"{hostname}", false},
		{"hostname!", false},
		{"<hostname>", false},
		{"# hostname", false},
		{"// hostname", false},
		{"user@hostname", false},
		{"hostname;", false},
		{`"hostname"`, false},
	} {
		actual := SubjectQualifiesForCert(test.host)
		if actual != test.expect {
			t.Errorf("Test %d: Expected SubjectQualifiesForCert(%s)=%v, but got %v",
				i, test.host, test.expect, actual)
		}
	}
}

func TestSubjectQualifiesForPublicCert(t *testing.T) {
	for i, test := range []struct {
		host   string
		expect bool
	}{
		{"hostname", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"Sub.Example.COM", true},
		{"127.0.0.1", false},
		{"127.0.1.5", false},
		{"69.123.43.94", false},
		{"::1", false},
		{"::", false},
		{"0.0.0.0", false},
		{"", false},
		{" ", false},
		{"*.example.com", true},
		{"*.*.example.com", false},
		{"sub.*.example.com", false},
		{"*sub.example.com", false},
		{"*", false},     // won't be trusted by browsers
		{"*.tld", false}, // won't be trusted by browsers
		{".tld", false},
		{"example.com.", false},
		{"localhost", false},
		{"foo.localhost", false},
		{"local", true},
		{"foo.local", false},
		{"foo.bar.local", false},
		{"192.168.1.3", false},
		{"10.0.2.1", false},
		{"169.112.53.4", false},
		{"$hostname", false},
		{"%HOSTNAME%", false},
		{"{hostname}", false},
		{"hostname!", false},
		{"<hostname>", false},
		{"# hostname", false},
		{"// hostname", false},
		{"user@hostname", false},
		{"hostname;", false},
		{`"hostname"`, false},
	} {
		actual := SubjectQualifiesForPublicCert(test.host)
		if actual != test.expect {
			t.Errorf("Test %d: Expected SubjectQualifiesForPublicCert(%s)=%v, but got %v",
				i, test.host, test.expect, actual)
		}
	}
}

func TestMatchWildcard(t *testing.T) {
	for i, test := range []struct {
		subject, wildcard string
		expect            bool
	}{
		{"hostname", "hostname", true},
		{"HOSTNAME", "hostname", true},
		{"hostname", "HOSTNAME", true},
		{"foo.localhost", "foo.localhost", true},
		{"foo.localhost", "bar.localhost", false},
		{"foo.localhost", "*.localhost", true},
		{"bar.localhost", "*.localhost", true},
		{"FOO.LocalHost", "*.localhost", true},
		{"Bar.localhost", "*.LOCALHOST", true},
		{"foo.bar.localhost", "*.localhost", false},
		{".localhost", "*.localhost", false},
		{"foo.localhost", "foo.*", false},
		{"foo.bar.local", "foo.*.local", false},
		{"foo.bar.local", "foo.bar.*", false},
		{"foo.bar.local", "*.bar.local", true},
		{"1.2.3.4.5.6", "*.2.3.4.5.6", true},
		{"1.2.3.4.5.6", "*.*.3.4.5.6", true},
		{"1.2.3.4.5.6", "*.*.*.4.5.6", true},
		{"1.2.3.4.5.6", "*.*.*.*.5.6", true},
		{"1.2.3.4.5.6", "*.*.*.*.*.6", true},
		{"1.2.3.4.5.6", "*.*.*.*.*.*", true},
		{"0.1.2.3.4.5.6", "*.*.*.*.*.*", false},
		{"1.2.3.4", "1.2.3.*", false}, // https://tools.ietf.org/html/rfc2818#section-3.1
	} {
		actual := MatchWildcard(test.subject, test.wildcard)
		if actual != test.expect {
			t.Errorf("Test %d: Expected MatchWildcard(%s, %s)=%v, but got %v",
				i, test.subject, test.wildcard, test.expect, actual)
		}
	}
}
