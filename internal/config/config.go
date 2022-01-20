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

// Package config contains CLI configuration components.
package config

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/jackc/pgconn"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

// BackendMap matches incoming principals to database connection
// configurations.
type BackendMap map[*regexp.Regexp]*pgconn.Config

// Config encapsulates the command-line configurations and the logic
// necessary to make those values usable.
type Config struct {
	additionalPaths   []string      // Paths to additional public keys.
	backendFile       string        // Path to backend.json file.
	BindAddr          string        // Address to bind the proxy to.
	bindCert, bindKey string        // Paths to TLS configurations.
	insecure          bool          // Sanity check to ensure that the operator really means it.
	GracePeriod       time.Duration // The amount of time to wait for open connections to drain.
	JwtField          string        // The JWT claim field to use when selecting a backend.
	MetricsAddr       string        // Address to bind the prometheus metrics server to.
	Refresh           time.Duration // Duration between refreshing configuration data.
	oidcDiscovery     string        // A URL to an OIDC discovery document.
}

// additionalKeys returns public keys to use in addition to those found
// via OIDC.
func (c *Config) additionalKeys() ([]crypto.PublicKey, error) {
	if len(c.additionalPaths) == 0 {
		return nil, nil
	}

	var ret []crypto.PublicKey
	var err error
	for _, path := range c.additionalPaths {
		ret, err = readKeys(path, ret)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

// Bind adds flags to the set.
func (c *Config) Bind(f *pflag.FlagSet) {
	f.StringSliceVar(&c.additionalPaths, "signingKeys", nil,
		"additional PEM-formatted public key or certificate files")
	f.StringVar(&c.backendFile, "backends", "",
		"the path to a JSON-formatted backends configuration")
	f.StringVar(&c.BindAddr, "bindAddr", "127.0.0.1:13013", "a network address and port to bind to")
	f.StringVar(&c.bindKey, "bindCert", "",
		"the path to a PEM-encoded certificate chain to present to incoming connections")
	f.StringVar(&c.bindKey, "bindKey", "",
		"the path to a PEM-encoded private key to encrypt incoming connections with")
	f.StringVar(&c.JwtField, "jwtField", "sub",
		"the JWT claim field to use when selecting backend configurations")
	f.DurationVar(&c.GracePeriod, "gracePeriod", 30*time.Second,
		"the amount of time to wait for SQL connections to become idle when shutting down")
	f.BoolVar(&c.insecure, "insecure", false, "this flag must be set if no TLS configuration is provided")
	f.DurationVar(&c.Refresh, "refresh", 24*time.Hour,
		"how often to refresh configuration data; set to 0 to disable; kill -HUP to manually refresh")
	f.StringVar(&c.MetricsAddr, "metricsAddr", "", "an address to bind a metrics HTTP server to")
	f.StringVar(&c.oidcDiscovery, "oidcDiscovery", "",
		"the URL of an OIDC discovery document to bootstrap public signing keys")
}

// Cache returns a memoized view of the Config.
func (c *Config) Cache(ctx context.Context) (*Cache, error) {
	var err error

	ret := &Cache{Config: c}

	if ret.PublicKeys, err = c.additionalKeys(); err != nil {
		return nil, err
	}
	discovery, err := c.discovery()
	if err != nil {
		return nil, err
	}
	if discovery != nil {
		loc, err := fetchJWKSLocation(ctx, discovery)
		if err != nil {
			return nil, err
		}
		fetched, err := fetchJWKS(ctx, loc)
		if err != nil {
			return nil, err
		}
		ret.PublicKeys = append(ret.PublicKeys, fetched...)
	}

	if ret.Backends, err = c.backends(); err != nil {
		return nil, err
	}
	if ret.Discovery, err = c.discovery(); err != nil {
		return nil, err
	}
	if ret.TLSConfig, err = c.tlsConfig(); err != nil {
		return nil, err
	}

	return ret, nil
}

// backends returns a map of expressions to match against the incoming
// claims and the connection configurations to use.
func (c *Config) backends() (BackendMap, error) {
	if c.backendFile == "" {
		return nil, errors.New("a --backends configuration file must be provided")
	}

	f, err := os.Open(c.backendFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	temp := make(map[string]string)

	dec := json.NewDecoder(f)
	if err := dec.Decode(&temp); err != nil {
		return nil, errors.WithStack(err)
	}

	ret := make(BackendMap, len(temp))
	for k, v := range temp {
		if k == "" || v == "" {
			return nil, errors.New("empty string is not allowed in backend configuration")
		}
		if k[0] == '/' {
			k = k[1:]
		} else {
			// Create an exact-match regexp.
			k = "^" + regexp.QuoteMeta(k) + "$"
		}

		pat, err := regexp.Compile(k)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		cfg, err := pgconn.ParseConfig(v)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		ret[pat] = cfg
	}

	return ret, nil
}

// discovery returns the address of an OIDC discovery document, if one
// is configured.
func (c *Config) discovery() (*url.URL, error) {
	if c.oidcDiscovery == "" {
		return nil, nil
	}
	u, err := url.Parse(c.oidcDiscovery)
	return u, errors.Wrapf(err, "could not parse %q as URL", c.oidcDiscovery)
}

// tlsConfig returns the TLS configuration to use for incoming SQL
// connections. It will return nil if TLS should not be used for
// incoming connections.
func (c *Config) tlsConfig() (*tls.Config, error) {
	if c.bindCert != "" && c.bindKey != "" {
		cert, err := tls.LoadX509KeyPair(c.bindCert, c.bindKey)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	if (c.bindKey == "") != (c.bindCert == "") {
		return nil, errors.New("both or neither of --bindKey and --bindCert must be specified")
	}
	if c.insecure {
		return nil, nil
	}
	return nil, errors.New("no --bindKey or --bindCert provided, must specify --insecure")
}

// readKey adds all PEM-formatted public keys in the file to the slice
// and returns it. This function will return an error if no public keys
// were found in the file.
func readKeys(path string, to []crypto.PublicKey) ([]crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	foundSomething := false
	for {
		// Decode doesn't return an error, just the rest of the bytes.
		block, data = pem.Decode(data)
		if block == nil {
			if foundSomething {
				return to, nil
			}
			return nil, errors.Errorf("did find any PEM data in %q", path)
		}

		switch block.Type {
		case "PUBLIC KEY":
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "while parsing %q", path)
			}
			to = append(to, parsed)

		case "CERTIFICATE":
			certs, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "while parsing %q", path)
			}
			for _, cert := range certs {
				to = append(to, cert.PublicKey)
			}

		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			return nil, errors.Errorf("found private key in %q; only public keys or certificates accepted", path)

		default:
			return nil, errors.Errorf("unexpected PEM block %q encountered in %q", block.Type, path)
		}
		foundSomething = true
	}
}
