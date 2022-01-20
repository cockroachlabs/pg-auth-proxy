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
	"crypto"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// fetchJWKS downloads a JWKS file and parses out the PublicKeys.
func fetchJWKS(ctx context.Context, from *url.URL) ([]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, from.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct JWKS request")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "could not fetch JWKS document from %q", from)
	}
	defer resp.Body.Close()

	log.WithField("url", from).Trace("fetched JWKS document")

	var doc jwks
	if err := (json.NewDecoder(resp.Body)).Decode(&doc); err != nil {
		return nil, errors.Wrapf(err, "could not decode JWKS at %q", from)
	}

	ret := make([]crypto.PublicKey, 0, len(doc.Keys))
	for _, jwk := range doc.Keys {
		key, ok, err := jwk.Reify()
		if err != nil {
			return nil, err
		}
		if ok {
			log.WithField("kid", jwk.ID).Debug("loaded key")
			ret = append(ret, key)
		} else {
			log.WithField("kid", jwk.ID).Debug("ignoring key")
		}
	}
	return ret, nil
}

// fetchJWKSLocation downloads the OIDC discovery document and extracts the
// URL to
func fetchJWKSLocation(ctx context.Context, discovery *url.URL) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct OIDC query")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not download OIDC discovery document")
	}
	defer resp.Body.Close()

	log.WithField("url", req.URL).Trace("fetched discovery document")

	var doc struct {
		URI string `json:"jwks_uri"`
	}
	if err := (json.NewDecoder(resp.Body)).Decode(&doc); err != nil {
		return nil, errors.Wrap(err, "could not decode OIDC discovery document")
	}

	if doc.URI == "" {
		return nil, errors.New("OIDC discovery document did not have a jwks_uri field")
	}

	rel, err := url.Parse(doc.URI)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse jwks_uri value %q", doc.URI)
	}

	return discovery.ResolveReference(rel), nil
}
