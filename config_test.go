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

	"github.com/go-acme/lego/v3/certificate"
)

func TestSaveCertResource(t *testing.T) {
	testConfig := &Config{
		CA:        "https://example.com/acme/directory",
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		certCache: new(Cache),
	}

	testStorageDir := testConfig.Storage.(*FileStorage).Path

	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
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
