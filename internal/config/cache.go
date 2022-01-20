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
	"crypto"
	"crypto/tls"
	"net/url"
)

// A Cache wraps a Config to save expensive computations and network
// fetching. Configuration reloading can be accomplished by simply
// discarding and recreating the Cache.
type Cache struct {
	*Config

	Backends   BackendMap
	Discovery  *url.URL
	PublicKeys []crypto.PublicKey
	TLSConfig  *tls.Config
}
