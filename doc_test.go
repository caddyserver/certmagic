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
	"fmt"
	"log"
	"net/http"
)

// This is the simplest way for HTTP servers to use this package.
// Call HTTPS() with your domain names and your handler (or nil
// for the http.DefaultMux), and CertMagic will do the rest.
func ExampleHTTPS() {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello, HTTPS visitor!")
	})

	err := HTTPS([]string{"example.com", "www.example.com"}, nil)
	if err != nil {
		log.Fatal(err)
	}
}
