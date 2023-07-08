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
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{GetConfigForCert: noop})
	defer c.Stop()

	c.optionsMu.RLock()
	defer c.optionsMu.RUnlock()

	if c.options.RenewCheckInterval != DefaultRenewCheckInterval {
		t.Errorf("Expected RenewCheckInterval to be set to default value, but it wasn't: %s", c.options.RenewCheckInterval)
	}
	if c.options.OCSPCheckInterval != DefaultOCSPCheckInterval {
		t.Errorf("Expected OCSPCheckInterval to be set to default value, but it wasn't: %s", c.options.OCSPCheckInterval)
	}
	if c.options.GetConfigForCert == nil {
		t.Error("Expected GetConfigForCert to be set, but it was nil")
	}
	if c.cache == nil {
		t.Error("Expected cache to be set, but it was nil")
	}
	if c.stopChan == nil {
		t.Error("Expected stopChan to be set, but it was nil")
	}
}
