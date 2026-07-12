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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type loadResultStorage struct {
	Storage
	data []byte
	err  error
}

func (s loadResultStorage) Load(context.Context, string) ([]byte, error) {
	return s.data, s.err
}

func TestHTTPChallengeHandlerNoOp(t *testing.T) {
	am := &ACMEIssuer{CA: "https://example.com/acme/directory", Logger: defaultTestLogger}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
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
		if am.HandleHTTPChallenge(rw, req) {
			t.Errorf("Got true with this URL, but shouldn't have: %s", url)
		}
	}
}

func TestHTTPChallengeLookupLogLevel(t *testing.T) {
	tests := []struct {
		name          string
		storage       Storage
		cancelRequest bool
		wantLevel     zapcore.Level
	}{
		{
			name:      "no active challenge",
			storage:   &memoryStorage{},
			wantLevel: zap.DebugLevel,
		},
		{
			name: "empty challenge data",
			storage: loadResultStorage{
				Storage: &memoryStorage{},
				data:    []byte{},
			},
			wantLevel: zap.WarnLevel,
		},
		{
			name: "request canceled",
			storage: loadResultStorage{
				Storage: &memoryStorage{},
				err:     context.Canceled,
			},
			cancelRequest: true,
			wantLevel:     zap.DebugLevel,
		},
		{
			name: "storage operation canceled",
			storage: loadResultStorage{
				Storage: &memoryStorage{},
				err:     context.Canceled,
			},
			wantLevel: zap.WarnLevel,
		},
		{
			name: "storage failure",
			storage: loadResultStorage{
				Storage: &memoryStorage{},
				err:     errors.New("storage unavailable"),
			},
			wantLevel: zap.WarnLevel,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			logger := zap.New(core)
			am := &ACMEIssuer{
				CA:     "https://example.com/acme/directory",
				Logger: logger,
			}
			am.config = &Config{
				Issuers: []Issuer{am},
				Storage: tt.storage,
				Logger:  logger,
			}

			req := httptest.NewRequest(
				http.MethodGet,
				"http://example.com/.well-known/acme-challenge/token",
				nil,
			)
			if tt.cancelRequest {
				ctx, cancel := context.WithCancel(req.Context())
				cancel()
				req = req.WithContext(ctx)
			}
			if am.HandleHTTPChallenge(httptest.NewRecorder(), req) {
				t.Fatal("expected challenge request not to be handled")
			}

			entries := logs.FilterMessage("looking up info for HTTP challenge").All()
			if len(entries) != 1 {
				t.Fatalf("expected one challenge lookup log, got %d", len(entries))
			}
			if entries[0].Level != tt.wantLevel {
				t.Fatalf("expected log level %s, got %s", tt.wantLevel, entries[0].Level)
			}
		})
	}
}
