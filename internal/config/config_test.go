// Copyright 2022 Cockroach Labs Inc.
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

package config

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata
var testData embed.FS

// TestCacheCreation starts an HTTP server with the contents of the
// testdata directory to perform an all-up test of configuration
// loading.
func TestCacheCreation(t *testing.T) {
	a := assert.New(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if !a.NoError(err) {
		return
	}

	srv := &http.Server{
		Handler: http.FileServer(http.FS(testData)),
	}
	go srv.Serve(l)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{
		additionalPaths: []string{"./testdata/additional.pub"},
		backendFile:     "./testdata/backend.json",
		insecure:        true,
		oidcDiscovery:   fmt.Sprintf("http://%s/testdata/discovery.json", l.Addr().String()),
	}

	cache, err := cfg.Cache(ctx)
	if a.NoError(err) {
		a.Len(cache.Backends, 1)
		a.Len(cache.PublicKeys, 3)
	}
}
