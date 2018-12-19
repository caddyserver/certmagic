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

import "testing"

func TestNewCache(t *testing.T) {
	c := NewCache(&FileStorage{Path: "./foo"})
	if c.RenewInterval != DefaultRenewInterval {
		t.Errorf("Expected RenewInterval to be set to default value, but it wasn't: %s", c.RenewInterval)
	}
	if c.OCSPInterval != DefaultOCSPInterval {
		t.Errorf("Expected OCSPInterval to be set to default value, but it wasn't: %s", c.OCSPInterval)
	}
	if c.storage == nil {
		t.Error("Expected storage to be set, but it was nil")
	}
	if c.cache == nil {
		t.Error("Expected cache to be set, but it was nil")
	}
	if c.stopChan == nil {
		t.Error("Expected stopChan to be set, but it was nil")
	}
}
