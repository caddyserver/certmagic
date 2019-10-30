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
	"reflect"
	"testing"
)

func TestUnexportedGetCertificate(t *testing.T) {
	certCache := &Cache{cache: make(map[string]Certificate), cacheIndex: make(map[string][]string)}
	cfg := &Config{certCache: certCache}

	// When cache is empty
	if _, matched, defaulted := cfg.getCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); matched || defaulted {
		t.Errorf("Got a certificate when cache was empty; matched=%v, defaulted=%v", matched, defaulted)
	}

	// When cache has one certificate in it
	firstCert := Certificate{Names: []string{"example.com"}}
	certCache.cache["0xdeadbeef"] = firstCert
	certCache.cacheIndex["example.com"] = []string{"0xdeadbeef"}
	if cert, matched, defaulted := cfg.getCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); !matched || defaulted || cert.Names[0] != "example.com" {
		t.Errorf("Didn't get a cert for 'example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When retrieving wildcard certificate
	certCache.cache["0xb01dface"] = Certificate{Names: []string{"*.example.com"}}
	certCache.cacheIndex["*.example.com"] = []string{"0xb01dface"}
	if cert, matched, defaulted := cfg.getCertificate(&tls.ClientHelloInfo{ServerName: "sub.example.com"}); !matched || defaulted || cert.Names[0] != "*.example.com" {
		t.Errorf("Didn't get wildcard cert for 'sub.example.com' or got the wrong one: %v, matched=%v, defaulted=%v", cert, matched, defaulted)
	}

	// When no certificate matches and SNI is provided, return no certificate (should be TLS alert)
	if cert, matched, defaulted := cfg.getCertificate(&tls.ClientHelloInfo{ServerName: "nomatch"}); matched || defaulted {
		t.Errorf("Expected matched=false, defaulted=false; but got matched=%v, defaulted=%v (cert: %v)", matched, defaulted, cert)
	}
}

func TestCacheCertificate(t *testing.T) {
	certCache := &Cache{cache: make(map[string]Certificate), cacheIndex: make(map[string][]string)}

	certCache.cacheCertificate(Certificate{Names: []string{"example.com", "sub.example.com"}, hash: "foobar"})
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
	certCache.cacheCertificate(Certificate{Names: []string{"example.com"}, hash: "barbaz"})
	if _, ok := certCache.cache["barbaz"]; !ok {
		t.Error("Expected second cert to be cached by key 'barbaz.com', but it wasn't")
	}
	if hashes, ok := certCache.cacheIndex["example.com"]; !ok {
		t.Error("Expected second cert to be keyed by 'example.com', but it wasn't")
	} else if !reflect.DeepEqual(hashes, []string{"foobar", "barbaz"}) {
		t.Errorf("Expected second cert to map to 'barbaz' but it was %v instead", hashes)
	}
}

func TestHostsQualifies(t *testing.T) {
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
		{".com", false},
		{"example.com.", false},
		{"localhost", false},
		{"local", true},
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
		{"hostname:", false},
	} {
		actual := HostsQualifies([]string{test.host})
		if actual != test.expect {
			t.Errorf("Test %d: Expected HostsQualifies(%s)=%v, but got %v",
				i, test.host, test.expect, actual)
		}
	}
}
