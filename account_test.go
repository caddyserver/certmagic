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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewAccount(t *testing.T) {
	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	email := "me@foobar.com"
	account, err := am.newAccount(email)
	if err != nil {
		t.Fatalf("Error creating account: %v", err)
	}
	if account.PrivateKey == nil {
		t.Error("Private key is nil")
	}
	if account.Contact[0] != "mailto:"+email {
		t.Errorf("Expected email to be %s, but was %s", email, account.Contact[0])
	}
	if account.Status != "" {
		t.Error("New account already has a status; it shouldn't")
	}
}

func TestSaveAccount(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata1_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	email := "me@foobar.com"
	account, err := am.newAccount(email)
	if err != nil {
		t.Fatalf("Error creating account: %v", err)
	}

	err = am.saveAccount(ctx, am.CA, account)
	if err != nil {
		t.Fatalf("Error saving account: %v", err)
	}
	_, err = am.getAccount(ctx, am.CA, email)
	if err != nil {
		t.Errorf("Cannot access account data, error: %v", err)
	}
}

func TestGetAccountDoesNotAlreadyExist(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	account, err := am.getAccount(ctx, am.CA, "account_does_not_exist@foobar.com")
	if err != nil {
		t.Fatalf("Error getting account: %v", err)
	}

	if account.PrivateKey == nil {
		t.Error("Expected account to have a private key, but it was nil")
	}
}

func TestGetAccountAlreadyExists(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata2_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	email := "me@foobar.com"

	// Set up test
	account, err := am.newAccount(email)
	if err != nil {
		t.Fatalf("Error creating account: %v", err)
	}
	err = am.saveAccount(ctx, am.CA, account)
	if err != nil {
		t.Fatalf("Error saving account: %v", err)
	}

	// Expect to load account from disk
	loadedAccount, err := am.getAccount(ctx, am.CA, email)
	if err != nil {
		t.Fatalf("Error getting account: %v", err)
	}

	// Assert keys are the same
	if !privateKeysSame(account.PrivateKey, loadedAccount.PrivateKey) {
		t.Error("Expected private key to be the same after loading, but it wasn't")
	}

	// Assert emails are the same
	if !reflect.DeepEqual(account.Contact, loadedAccount.Contact) {
		t.Errorf("Expected contacts to be equal, but was '%s' before and '%s' after loading", account.Contact, loadedAccount.Contact)
	}
}

func TestGetEmailFromPackageDefault(t *testing.T) {
	ctx := context.Background()

	DefaultACME.Email = "tEsT2@foo.com"
	defer func() {
		DefaultACME.Email = ""
		discoveredEmail = ""
	}()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata2_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	err := am.setEmail(ctx, true)
	if err != nil {
		t.Fatalf("getEmail error: %v", err)
	}
	lowerEmail := strings.ToLower(DefaultACME.Email)
	if am.getEmail() != lowerEmail {
		t.Errorf("Did not get correct email from memory; expected '%s' but got '%s'", lowerEmail, am.Email)
	}
}

func TestGetEmailFromUserInput(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata3_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	// let's not clutter up the output
	origStdout := os.Stdout
	os.Stdout = nil
	agreementTestURL = "(none - testing)"
	defer func() {
		os.Stdout = origStdout
		agreementTestURL = ""
	}()

	email := "test3@foo.com"
	stdin = bytes.NewBufferString(email + "\n")
	err := am.setEmail(ctx, true)
	if err != nil {
		t.Fatalf("getEmail error: %v", err)
	}
	if am.email != email {
		t.Errorf("Did not get correct email from user input prompt; expected '%s' but got '%s'", email, am.Email)
	}
	if !am.isAgreed() {
		t.Error("Expect Config.agreed to be true, but got false")
	}
}

func TestGetEmailFromRecent(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata4_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	DefaultACME.Email = ""
	discoveredEmail = ""

	for i, eml := range []string{
		"test4-1@foo.com",
		"test4-2@foo.com",
		"TEST4-3@foo.com", // test case insensitivity
	} {
		account, err := am.newAccount(eml)
		if err != nil {
			t.Fatalf("Error creating user %d: %v", i, err)
		}
		err = am.saveAccount(ctx, am.CA, account)
		if err != nil {
			t.Fatalf("Error saving user %d: %v", i, err)
		}

		// Change modified time so they're all different and the test becomes more deterministic
		fs := testConfig.Storage.(*FileStorage)
		userFolder := filepath.Join(fs.Path, am.storageKeyUserPrefix(am.CA, eml))
		f, err := os.Stat(userFolder)
		if err != nil {
			t.Fatalf("Could not access user folder for '%s': %v", eml, err)
		}
		chTime := f.ModTime().Add(time.Duration(i) * time.Hour) // 1 second isn't always enough spacing!
		if err := os.Chtimes(userFolder, chTime, chTime); err != nil {
			t.Fatalf("Could not change user folder mod time for '%s': %v", eml, err)
		}
	}
	err := am.setEmail(ctx, true)
	if err != nil {
		t.Fatalf("getEmail error: %v", err)
	}
	if am.getEmail() != "test4-3@foo.com" {
		t.Errorf("Did not get correct email from storage; expected '%s' but got '%s'", "test4-3@foo.com", am.Email)
	}
}

// agreementTestURL is set during tests to skip requiring
// setting up an entire ACME CA endpoint.
var agreementTestURL string
