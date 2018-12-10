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
	"path"
	"testing"
)

func TestPrefixAndKeyBuilders(t *testing.T) {
	const ca = "https://example.com/acme-ca/directory"

	for i, testcase := range []struct {
		in, folder, certFile, keyFile, metaFile string
	}{
		{
			in:       "example.com",
			folder:   path.Join("acme", "example.com", "sites", "example.com"),
			certFile: path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"),
			keyFile:  path.Join("acme", "example.com", "sites", "example.com", "example.com.key"),
			metaFile: path.Join("acme", "example.com", "sites", "example.com", "example.com.json"),
		},
		{
			in:       "*.example.com",
			folder:   path.Join("acme", "example.com", "sites", "wildcard_.example.com"),
			certFile: path.Join("acme", "example.com", "sites", "wildcard_.example.com", "wildcard_.example.com.crt"),
			keyFile:  path.Join("acme", "example.com", "sites", "wildcard_.example.com", "wildcard_.example.com.key"),
			metaFile: path.Join("acme", "example.com", "sites", "wildcard_.example.com", "wildcard_.example.com.json"),
		},
		{
			// prevent directory traversal! very important, esp. with on-demand TLS
			// see issue #2092
			in:       "a/../../../foo",
			folder:   path.Join("acme", "example.com", "sites", "afoo"),
			certFile: path.Join("acme", "example.com", "sites", "afoo", "afoo.crt"),
			keyFile:  path.Join("acme", "example.com", "sites", "afoo", "afoo.key"),
			metaFile: path.Join("acme", "example.com", "sites", "afoo", "afoo.json"),
		},
		{
			in:       "b\\..\\..\\..\\foo",
			folder:   path.Join("acme", "example.com", "sites", "bfoo"),
			certFile: path.Join("acme", "example.com", "sites", "bfoo", "bfoo.crt"),
			keyFile:  path.Join("acme", "example.com", "sites", "bfoo", "bfoo.key"),
			metaFile: path.Join("acme", "example.com", "sites", "bfoo", "bfoo.json"),
		},
		{
			in:       "c/foo",
			folder:   path.Join("acme", "example.com", "sites", "cfoo"),
			certFile: path.Join("acme", "example.com", "sites", "cfoo", "cfoo.crt"),
			keyFile:  path.Join("acme", "example.com", "sites", "cfoo", "cfoo.key"),
			metaFile: path.Join("acme", "example.com", "sites", "cfoo", "cfoo.json"),
		},
	} {
		if actual := prefixSite(ca, testcase.in); actual != testcase.folder {
			t.Errorf("Test %d: site folder: Expected '%s' but got '%s'", i, testcase.folder, actual)
		}
		if actual := prefixSiteCert(ca, testcase.in); actual != testcase.certFile {
			t.Errorf("Test %d: site cert file: Expected '%s' but got '%s'", i, testcase.certFile, actual)
		}
		if actual := prefixSiteKey(ca, testcase.in); actual != testcase.keyFile {
			t.Errorf("Test %d: site key file: Expected '%s' but got '%s'", i, testcase.keyFile, actual)
		}
		if actual := prefixSiteMeta(ca, testcase.in); actual != testcase.metaFile {
			t.Errorf("Test %d: site meta file: Expected '%s' but got '%s'", i, testcase.metaFile, actual)
		}
	}
}
