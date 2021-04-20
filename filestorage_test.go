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
	"testing"
)

func TestFileStorage(t *testing.T) {
	tempDir := t.TempDir()
	var testStore = &FileStorage{Path: tempDir}

	err := testStore.Store("test.key", []byte{})
	if err != nil {
		t.Fatalf("Error creating test key: %v", err)
	}

	fileInfo, err := os.Stat(testStore.Filename("test.key"))
	if err != nil {
		t.Fatalf("Error getting key file stat: %v", err)
	}
	if fileInfo.Mode() != 0600 {
		t.Fatalf("Test key has wrong permissions: %v", fileInfo.Mode())
	}
}

func TestFileStorage_GroupRead(t *testing.T) {
	tempDir := t.TempDir()
	var testStore = &FileStorage{Path: tempDir, AllowGroupRead: true}

	err := testStore.Store("test.key", []byte{})
	if err != nil {
		t.Fatalf("Error creating test key: %v", err)
	}

	fileInfo, err := os.Stat(testStore.Filename("test.key"))
	if err != nil {
		t.Fatalf("Error getting key file stat: %v", err)
	}
	if fileInfo.Mode() != 0640 {
		t.Fatalf("Test key has wrong permissions: %v", fileInfo.Mode())
	}
}
