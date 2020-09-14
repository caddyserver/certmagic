package certmagic

// Code in this file adapted from go-acme/lego, July 2020:
// https://github.com/go-acme/lego
// by Ludovic Fernandez and Dominik Menke
//
// It has been modified.

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestLookupNameserversOK(t *testing.T) {
	testCases := []struct {
		fqdn string
		nss  []string
	}{
		{
			fqdn: "books.google.com.ng.",
			nss:  []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			fqdn: "www.google.com.",
			nss:  []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			fqdn: "physics.georgetown.edu.",
			nss:  []string{"ns4.georgetown.edu.", "ns5.georgetown.edu.", "ns6.georgetown.edu."},
		},
	}

	for i, test := range testCases {
		test := test
		t.Run(test.fqdn, func(t *testing.T) {
			t.Parallel()

			nss, err := lookupNameservers(test.fqdn, recursiveNameservers(nil))
			if err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}

			sort.Strings(nss)
			sort.Strings(test.nss)

			if !reflect.DeepEqual(test.nss, nss) {
				t.Errorf("Test %d: expected %+v but got %+v", i, test.nss, nss)
			}
		})
	}
}

func TestLookupNameserversErr(t *testing.T) {
	testCases := []struct {
		desc  string
		fqdn  string
		error string
	}{
		{
			desc:  "invalid tld",
			fqdn:  "_null.n0n0.",
			error: "could not determine the zone",
		},
	}

	for i, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			_, err := lookupNameservers(test.fqdn, nil)
			if err == nil {
				t.Errorf("expected error, got none")
			}
			if !strings.Contains(err.Error(), test.error) {
				t.Errorf("Test %d: Expected error to contain '%s' but got '%s'", i, test.error, err.Error())
			}
		})
	}
}

var findXByFqdnTestCases = []struct {
	desc          string
	fqdn          string
	zone          string
	primaryNs     string
	nameservers   []string
	expectedError string
}{
	{
		desc:        "domain is a CNAME",
		fqdn:        "mail.google.com.",
		zone:        "google.com.",
		primaryNs:   "ns1.google.com.",
		nameservers: recursiveNameservers(nil),
	},
	{
		desc:        "domain is a non-existent subdomain",
		fqdn:        "foo.google.com.",
		zone:        "google.com.",
		primaryNs:   "ns1.google.com.",
		nameservers: recursiveNameservers(nil),
	},
	{
		desc:        "domain is a eTLD",
		fqdn:        "example.com.ac.",
		zone:        "ac.",
		primaryNs:   "a0.nic.ac.",
		nameservers: recursiveNameservers(nil),
	},
	{
		desc:        "domain is a cross-zone CNAME",
		fqdn:        "cross-zone-example.assets.sh.",
		zone:        "assets.sh.",
		primaryNs:   "gina.ns.cloudflare.com.",
		nameservers: recursiveNameservers(nil),
	},
	{
		desc:          "NXDOMAIN",
		fqdn:          "test.loho.jkl.",
		zone:          "loho.jkl.",
		nameservers:   []string{"1.1.1.1:53"},
		expectedError: "could not find the start of authority for test.loho.jkl.: NXDOMAIN",
	},
	{
		desc:        "several non existent nameservers",
		fqdn:        "mail.google.com.",
		zone:        "google.com.",
		primaryNs:   "ns1.google.com.",
		nameservers: []string{":7053", ":8053", "1.1.1.1:53"},
	},
	{
		desc:          "only non existent nameservers",
		fqdn:          "mail.google.com.",
		zone:          "google.com.",
		nameservers:   []string{":7053", ":8053", ":9053"},
		expectedError: "could not find the start of authority for mail.google.com.: read udp",
	},
	{
		desc:          "no nameservers",
		fqdn:          "test.ldez.com.",
		zone:          "ldez.com.",
		nameservers:   []string{},
		expectedError: "could not find the start of authority for test.ldez.com.",
	},
}

func TestFindZoneByFqdn(t *testing.T) {
	for i, test := range findXByFqdnTestCases {
		t.Run(test.desc, func(t *testing.T) {
			clearFqdnCache()

			zone, err := findZoneByFQDN(test.fqdn, test.nameservers)
			if test.expectedError != "" {
				if err == nil {
					t.Errorf("test %d: expected error, got none", i)
					return
				}
				if !strings.Contains(err.Error(), test.expectedError) {
					t.Errorf("test %d: expected error to contain '%s' but got '%s'", i, test.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("test %d: expected no error, but got: %v", i, err)
				}
				if zone != test.zone {
					t.Errorf("test %d: expected zone '%s' but got '%s'", i, zone, test.zone)
				}
			}
		})
	}
}

func TestResolveConfServers(t *testing.T) {
	var testCases = []struct {
		fixture  string
		expected []string
		defaults []string
	}{
		{
			fixture:  "testdata/resolv.conf.1",
			defaults: []string{"127.0.0.1:53"},
			expected: []string{"10.200.3.249", "10.200.3.250:5353", "2001:4860:4860::8844", "[10.0.0.1]:5353"},
		},
		{
			fixture:  "testdata/resolv.conf.nonexistant",
			defaults: []string{"127.0.0.1:53"},
			expected: []string{"127.0.0.1:53"},
		},
	}

	for i, test := range testCases {
		t.Run(test.fixture, func(t *testing.T) {
			result := systemOrDefaultNameservers(test.fixture, test.defaults)

			sort.Strings(result)
			sort.Strings(test.expected)

			if !reflect.DeepEqual(test.expected, result) {
				t.Errorf("Test %d: Expected %v but got %v", i, test.expected, result)
			}
		})
	}
}

func TestRecursiveNameserversAddsPort(t *testing.T) {
	custom := []string{"127.0.0.1"}
	results := recursiveNameservers(custom)

	var hasCustom bool
	for i, res := range results {
		hasCustom = hasCustom || strings.HasPrefix(res, custom[0])
		if !strings.HasSuffix(res, ":53") {
			t.Errorf("%v Expected all results to have a port, but result %d doesn't: %s", results, i, res)
		}
	}
	if !hasCustom {
		t.Errorf("%v Expected custom resolvers to be included, but they weren't: %v", results, custom)
	}
}

func clearFqdnCache() {
	fqdnSOACacheMu.Lock()
	fqdnSOACache = make(map[string]*soaCacheEntry)
	fqdnSOACacheMu.Unlock()
}
