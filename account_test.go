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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// memoryStorage is an in-memory storage implementation with known contents *and* fixed iteration order for List.
type memoryStorage struct {
	contents []memoryStorageItem
}

type memoryStorageItem struct {
	key  string
	data []byte
}

func (m *memoryStorage) lookup(_ context.Context, key string) *memoryStorageItem {
	for _, item := range m.contents {
		if item.key == key {
			return &item
		}
	}
	return nil
}
func (m *memoryStorage) Delete(ctx context.Context, key string) error {
	for i, item := range m.contents {
		if item.key == key {
			m.contents = append(m.contents[:i], m.contents[i+1:]...)
			return nil
		}
	}
	return fs.ErrNotExist
}
func (m *memoryStorage) Store(ctx context.Context, key string, value []byte) error {
	m.contents = append(m.contents, memoryStorageItem{key: key, data: value})
	return nil
}
func (m *memoryStorage) Exists(ctx context.Context, key string) bool {
	return m.lookup(ctx, key) != nil
}
func (m *memoryStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	if recursive {
		panic("unimplemented")
	}

	result := []string{}
nextitem:
	for _, item := range m.contents {
		if !strings.HasPrefix(item.key, path+"/") {
			continue
		}
		name := strings.TrimPrefix(item.key, path+"/")
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[:i]
		}

		for _, existing := range result {
			if existing == name {
				continue nextitem
			}
		}
		result = append(result, name)
	}
	return result, nil
}
func (m *memoryStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if item := m.lookup(ctx, key); item != nil {
		return item.data, nil
	}
	return nil, fs.ErrNotExist
}
func (m *memoryStorage) Stat(ctx context.Context, key string) (KeyInfo, error) {
	if item := m.lookup(ctx, key); item != nil {
		return KeyInfo{Key: key, Size: int64(len(item.data))}, nil
	}
	return KeyInfo{}, fs.ErrNotExist
}
func (m *memoryStorage) Lock(ctx context.Context, name string) error   { panic("unimplemented") }
func (m *memoryStorage) Unlock(ctx context.Context, name string) error { panic("unimplemented") }

var _ Storage = (*memoryStorage)(nil)

type recordingStorage struct {
	Storage
	calls []recordedCall
}

func (r *recordingStorage) Delete(ctx context.Context, key string) error {
	r.record("Delete", key)
	return r.Storage.Delete(ctx, key)
}
func (r *recordingStorage) Exists(ctx context.Context, key string) bool {
	r.record("Exists", key)
	return r.Storage.Exists(ctx, key)
}
func (r *recordingStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	r.record("List", path, recursive)
	return r.Storage.List(ctx, path, recursive)
}
func (r *recordingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	r.record("Load", key)
	return r.Storage.Load(ctx, key)
}
func (r *recordingStorage) Lock(ctx context.Context, name string) error {
	r.record("Lock", name)
	return r.Storage.Lock(ctx, name)
}
func (r *recordingStorage) Stat(ctx context.Context, key string) (KeyInfo, error) {
	r.record("Stat", key)
	return r.Storage.Stat(ctx, key)
}
func (r *recordingStorage) Store(ctx context.Context, key string, value []byte) error {
	r.record("Store", key)
	return r.Storage.Store(ctx, key, value)
}
func (r *recordingStorage) Unlock(ctx context.Context, name string) error {
	r.record("Unlock", name)
	return r.Storage.Unlock(ctx, name)
}

type recordedCall struct {
	name string
	args []interface{}
}

func (r *recordingStorage) record(name string, args ...interface{}) {
	r.calls = append(r.calls, recordedCall{name: name, args: args})
}

var _ Storage = (*recordingStorage)(nil)

func TestNewAccount(t *testing.T) {
	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

func TestGetAccountAlreadyExistsSkipsBroken(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &memoryStorage{},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	email := "me@foobar.com"

	// Create a "corrupted" account
	am.config.Storage.Store(ctx, am.storageKeyUserReg(am.CA, "notmeatall@foobar.com"), []byte("this is not a valid account"))

	// Create the actual account
	account, err := am.newAccount(email)
	if err != nil {
		t.Fatalf("Error creating account: %v", err)
	}
	err = am.saveAccount(ctx, am.CA, account)
	if err != nil {
		t.Fatalf("Error saving account: %v", err)
	}

	// Expect to load account from disk
	keyBytes, err := PEMEncodePrivateKey(account.PrivateKey)
	if err != nil {
		t.Fatalf("Error encoding private key: %v", err)
	}

	loadedAccount, err := am.GetAccount(ctx, keyBytes)
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

func TestGetAccountWithEmailAlreadyExists(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &recordingStorage{Storage: &memoryStorage{}},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

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

	// Set the expected email:
	am.Email = email
	err = am.setEmail(ctx, true)
	if err != nil {
		t.Fatalf("setEmail error: %v", err)
	}

	// Expect to load account from disk
	keyBytes, err := PEMEncodePrivateKey(account.PrivateKey)
	if err != nil {
		t.Fatalf("Error encoding private key: %v", err)
	}

	loadedAccount, err := am.GetAccount(ctx, keyBytes)
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

	// Assert that this was found without listing all accounts
	rs := testConfig.Storage.(*recordingStorage)
	for _, call := range rs.calls {
		if call.name == "List" {
			t.Error("Unexpected List call")
		}
	}
}

func TestGetEmailFromPackageDefault(t *testing.T) {
	ctx := context.Background()

	DefaultACME.Email = "tEsT2@foo.com"
	defer func() {
		DefaultACME.Email = ""
		discoveredEmail = ""
	}()

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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

	am := &ACMEIssuer{CA: dummyCA, Logger: zap.NewNop(), mu: new(sync.Mutex)}
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
