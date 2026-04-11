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
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

func Test_challengeKey(t *testing.T) {
	type args struct {
		chal acme.Challenge
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ok/dns-dns",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeDNS01,
					Identifier: acme.Identifier{
						Type:  "dns",
						Value: "*.example.com",
					},
				},
			},
			want: "*.example.com",
		},
		{
			name: "ok/http-dns",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeHTTP01,
					Identifier: acme.Identifier{
						Type:  "dns",
						Value: "*.example.com",
					},
				},
			},
			want: "*.example.com",
		},
		{
			name: "ok/tls-dns",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeTLSALPN01,
					Identifier: acme.Identifier{
						Type:  "dns",
						Value: "*.example.com",
					},
				},
			},
			want: "*.example.com",
		},
		{
			name: "ok/http-ipv4",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeHTTP01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "127.0.0.1",
					},
				},
			},
			want: "127.0.0.1",
		},
		{
			name: "ok/http-ipv6",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeHTTP01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "2001:db8::1",
					},
				},
			},
			want: "2001:db8::1",
		},
		{
			name: "ok/tls-ipv4",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeTLSALPN01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "127.0.0.1",
					},
				},
			},
			want: "1.0.0.127.in-addr.arpa",
		},
		{
			name: "ok/tls-ipv6",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeTLSALPN01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "2001:db8::1",
					},
				},
			},
			want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
		},
		{
			name: "fail/tls-ipv4",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeTLSALPN01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "127.0.0.1000",
					},
				},
			},
			want: "127.0.0.1000", // reversing this fails; default to identifier value
		},
		{
			name: "fail/tls-ipv6",
			args: args{
				chal: acme.Challenge{
					Type: acme.ChallengeTypeTLSALPN01,
					Identifier: acme.Identifier{
						Type:  "ip",
						Value: "2001:db8::10000",
					},
				},
			},
			want: "2001:db8::10000", // reversing this fails; default to identifier value
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := challengeKey(tt.args.chal); got != tt.want {
				t.Errorf("challengeKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetACMEChallenge_IPv6Brackets(t *testing.T) {
	// Store a challenge under a bare IPv6 identifier (as CertMagic does internally).
	bare := "::1"
	activeChallengesMu.Lock()
	activeChallenges[bare] = Challenge{}
	activeChallengesMu.Unlock()
	defer func() {
		activeChallengesMu.Lock()
		delete(activeChallenges, bare)
		activeChallengesMu.Unlock()
	}()

	// Lookup with bracketed IPv6 (as received from Go's HTTP server via r.Host).
	if _, ok := GetACMEChallenge("[::1]"); !ok {
		t.Error("GetACMEChallenge(\"[::1]\") should find challenge stored under \"::1\"")
	}
	// Lookup with bare IPv6 should still work.
	if _, ok := GetACMEChallenge("::1"); !ok {
		t.Error("GetACMEChallenge(\"::1\") should find challenge stored under \"::1\"")
	}
}
