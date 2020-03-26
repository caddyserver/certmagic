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
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/registration"
)

// user represents a Let's Encrypt user account.
type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// GetEmail gets u's email.
func (u user) GetEmail() string {
	return u.Email
}

// GetRegistration gets u's registration resource.
func (u user) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey gets u's private key.
func (u user) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// newUser creates a new User for the given email address
// with a new private key. This function does NOT save the
// user to disk or register it via ACME. If you want to use
// a user account that might already exist, call getUser
// instead. It does NOT prompt the user.
func (*ACMEManager) newUser(email string) (*user, error) {
	user := &user{Email: email}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return user, fmt.Errorf("generating private key: %v", err)
	}
	user.key = privateKey
	return user, nil
}

// getEmail does everything it can to obtain an email address
// from the user within the scope of memory and storage to use
// for ACME TLS. If it cannot get an email address, it does nothing
// (If user is prompted, it will warn the user of
// the consequences of an empty email.) This function MAY prompt
// the user for input. If allowPrompts is false, the user
// will NOT be prompted and an empty email may be returned.
func (am *ACMEManager) getEmail(allowPrompts bool) error {
	leEmail := am.Email

	// First try package default email
	if leEmail == "" {
		leEmail = DefaultACME.Email // TODO: racey with line 108
	}

	// Then try to get most recent user email from storage
	var gotRecentEmail bool
	if leEmail == "" {
		leEmail, gotRecentEmail = am.mostRecentUserEmail(am.CA)
	}
	if !gotRecentEmail && leEmail == "" && allowPrompts {
		// Looks like there is no email address readily available,
		// so we will have to ask the user if we can.
		var err error
		leEmail, err = am.promptUserForEmail()
		if err != nil {
			return err
		}

		// User might have just signified their agreement
		am.Agreed = DefaultACME.Agreed
	}

	// save the email for later and ensure it is consistent
	// for repeated use; then update cfg with the email
	DefaultACME.Email = strings.TrimSpace(strings.ToLower(leEmail)) // TODO: this is racey with line 85
	am.Email = DefaultACME.Email

	return nil
}

func (am *ACMEManager) getAgreementURL() (string, error) {
	if agreementTestURL != "" {
		return agreementTestURL, nil
	}
	caURL := am.CA
	if caURL == "" {
		caURL = DefaultACME.CA
	}
	response, err := http.Get(caURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var dir acme.Directory
	err = json.NewDecoder(response.Body).Decode(&dir)
	if err != nil {
		return "", err
	}
	return dir.Meta.TermsOfService, nil
}

// promptUserForEmail prompts the user for an email address
// and returns the email address they entered (which could
// be the empty string). If no error is returned, then Agreed
// will also be set to true, since continuing through the
// prompt signifies agreement.
func (am *ACMEManager) promptUserForEmail() (string, error) {
	agreementURL, err := am.getAgreementURL()
	if err != nil {
		return "", fmt.Errorf("get Agreement URL: %v", err)
	}
	// prompt the user for an email address and terms agreement
	reader := bufio.NewReader(stdin)
	am.promptUserAgreement(agreementURL)
	fmt.Println("Please enter your email address to signify agreement and to be notified")
	fmt.Println("in case of issues. You can leave it blank, but we don't recommend it.")
	fmt.Print("  Email address: ")
	leEmail, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("reading email address: %v", err)
	}
	leEmail = strings.TrimSpace(leEmail)
	DefaultACME.Agreed = true
	return leEmail, nil
}

// getUser loads the user with the given email from disk
// using the provided storage. If the user does not exist,
// it will create a new one, but it does NOT save new
// users to the disk or register them via ACME. It does
// NOT prompt the user.
func (am *ACMEManager) getUser(ca, email string) (*user, error) {
	regBytes, err := am.config.Storage.Load(am.storageKeyUserReg(ca, email))
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// create a new user
			return am.newUser(email)
		}
		return nil, err
	}
	keyBytes, err := am.config.Storage.Load(am.storageKeyUserPrivateKey(ca, email))
	if err != nil {
		if _, ok := err.(ErrNotExist); ok {
			// create a new user
			return am.newUser(email)
		}
		return nil, err
	}

	var u *user
	err = json.Unmarshal(regBytes, &u)
	if err != nil {
		return u, err
	}
	u.key, err = decodePrivateKey(keyBytes)
	return u, err
}

// saveUser persists a user's key and account registration
// to the file system. It does NOT register the user via ACME
// or prompt the user. You must also pass in the storage
// wherein the user should be saved. It should be the storage
// for the CA with which user has an account.
func (am *ACMEManager) saveUser(ca string, user *user) error {
	regBytes, err := json.MarshalIndent(&user, "", "\t")
	if err != nil {
		return err
	}
	keyBytes, err := encodePrivateKey(user.key)
	if err != nil {
		return err
	}
	all := []keyValue{
		{
			key:   am.storageKeyUserReg(ca, user.Email),
			value: regBytes,
		},
		{
			key:   am.storageKeyUserPrivateKey(ca, user.Email),
			value: keyBytes,
		},
	}
	return storeTx(am.config.Storage, all)
}

// promptUserAgreement simply outputs the standard user
// agreement prompt with the given agreement URL.
// It outputs a newline after the message.
func (am *ACMEManager) promptUserAgreement(agreementURL string) {
	const userAgreementPrompt = `Your sites will be served over HTTPS automatically using Let's Encrypt.
By continuing, you agree to the Let's Encrypt Subscriber Agreement at:`
	fmt.Printf("\n\n%s\n  %s\n", userAgreementPrompt, agreementURL)
}

// askUserAgreement prompts the user to agree to the agreement
// at the given agreement URL via stdin. It returns whether the
// user agreed or not.
func (am *ACMEManager) askUserAgreement(agreementURL string) bool {
	am.promptUserAgreement(agreementURL)
	fmt.Print("Do you agree to the terms? (y/n): ")

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
}

func (am *ACMEManager) storageKeyCAPrefix(caURL string) string {
	return path.Join(prefixACME, StorageKeys.Safe(am.issuerKey(caURL)))
}

func (am *ACMEManager) storageKeyUsersPrefix(caURL string) string {
	return path.Join(am.storageKeyCAPrefix(caURL), "users")
}

func (am *ACMEManager) storageKeyUserPrefix(caURL, email string) string {
	if email == "" {
		email = emptyEmail
	}
	return path.Join(am.storageKeyUsersPrefix(caURL), StorageKeys.Safe(email))
}

func (am *ACMEManager) storageKeyUserReg(caURL, email string) string {
	return am.storageSafeUserKey(caURL, email, "registration", ".json")
}

func (am *ACMEManager) storageKeyUserPrivateKey(caURL, email string) string {
	return am.storageSafeUserKey(caURL, email, "private", ".key")
}

// storageSafeUserKey returns a key for the given email, with the default
// filename, and the filename ending in the given extension.
func (am *ACMEManager) storageSafeUserKey(ca, email, defaultFilename, extension string) string {
	if email == "" {
		email = emptyEmail
	}
	email = strings.ToLower(email)
	filename := am.emailUsername(email)
	if filename == "" {
		filename = defaultFilename
	}
	filename = StorageKeys.Safe(filename)
	return path.Join(am.storageKeyUserPrefix(ca, email), filename+extension)
}

// emailUsername returns the username portion of an email address (part before
// '@') or the original input if it can't find the "@" symbol.
func (*ACMEManager) emailUsername(email string) string {
	at := strings.Index(email, "@")
	if at == -1 {
		return email
	} else if at == 0 {
		return email[1:]
	}
	return email[:at]
}

// mostRecentUserEmail finds the most recently-written user file
// in storage. Since this is part of a complex sequence to get a user
// account, errors here are discarded to simplify code flow in
// the caller, and errors are not important here anyway.
func (am *ACMEManager) mostRecentUserEmail(caURL string) (string, bool) {
	userList, err := am.config.Storage.List(am.storageKeyUsersPrefix(caURL), false)
	if err != nil || len(userList) == 0 {
		return "", false
	}

	// get all the key infos ahead of sorting, because
	// we might filter some out
	stats := make(map[string]KeyInfo)
	for i, u := range userList {
		keyInfo, err := am.config.Storage.Stat(u)
		if err != nil {
			continue
		}
		if keyInfo.IsTerminal {
			// I found a bug when macOS created a .DS_Store file in
			// the users folder, and CertMagic tried to use that as
			// the user email because it was newer than the other one
			// which existed... sure, this isn't a perfect fix but
			// frankly one's OS shouldn't mess with the data folder
			// in the first place.
			userList = append(userList[:i], userList[i+1:]...)
			continue
		}
		stats[u] = keyInfo
	}

	sort.Slice(userList, func(i, j int) bool {
		iInfo := stats[userList[i]]
		jInfo := stats[userList[j]]
		return jInfo.Modified.Before(iInfo.Modified)
	})

	user, err := am.getUser(caURL, path.Base(userList[0]))
	if err != nil {
		return "", false
	}

	return user.Email, true
}

// agreementTestURL is set during tests to skip requiring
// setting up an entire ACME CA endpoint.
var agreementTestURL string

// stdin is used to read the user's input if prompted;
// this is changed by tests during tests.
var stdin = io.ReadWriter(os.Stdin)

// The name of the folder for accounts where the email
// address was not provided; default 'username' if you will,
// but only for local/storage use, not with the CA.
const emptyEmail = "default"
