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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHTTPChallengeHandlerNoOp(t *testing.T) {
	testConfig := &Config{
		CA:      "https://example.com/acme/directory",
		Storage: &FileStorage{Path: "./_testdata_tmp"},
	}
	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer os.RemoveAll(testStorageDir)

	// try base paths and host names that aren't
	// handled by this handler
	for _, url := range []string{
		"http://localhost/",
		"http://localhost/foo.html",
		"http://localhost/.git",
		"http://localhost/.well-known/",
		"http://localhost/.well-known/acme-challenging",
		"http://other/.well-known/acme-challenge/foo",
	} {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Could not craft request, got error: %v", err)
		}
		rw := httptest.NewRecorder()
		if testConfig.HandleHTTPChallenge(rw, req) {
			t.Errorf("Got true with this URL, but shouldn't have: %s", url)
		}
	}
}
