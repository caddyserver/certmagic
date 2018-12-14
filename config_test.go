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
	"os"
	"reflect"
	"testing"

	"github.com/xenolf/lego/certificate"
)

func TestSaveCertResource(t *testing.T) {
	defer func() {
		fs := testConfig.certCache.storage.(*FileStorage)
		err := os.RemoveAll(fs.Path)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", fs.Path, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := &certificate.Resource{
		Domain:        domain,
		CertURL:       "https://example.com/cert",
		CertStableURL: "https://example.com/cert/stable",
		PrivateKey:    []byte(keyContents),
		Certificate:   []byte(certContents),
	}

	err := testConfig.saveCertResource(cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := testConfig.loadCertResource(domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	if !reflect.DeepEqual(*cert, siteData) {
		t.Errorf("Expected '%+v' to match '%+v'", cert, siteData)
	}
}

// TODO: use a more locally-scoped config and storage for each test,
// and clean up storage more safely than RemoveAll like we do in
// certain tests, OR use an in-memory storage for tests instead

var testConfig = NewWithCache(NewCache(&FileStorage{Path: "./_testdata_tmp"}),
	Config{
		CA: "https://example.com/acme/directory",
	})

var testStorageDir = testConfig.certCache.storage.(*FileStorage).Path
