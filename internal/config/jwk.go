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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/pkg/errors"
)

// A JWK Set document, per
// https://datatracker.ietf.org/doc/html/rfc7517#section-5
type jwks struct {
	// https://datatracker.ietf.org/doc/html/rfc7517#section-5.1
	Keys []*jwk `json:"keys"`
}

// A JSON Web Key, per
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
//
// with additional key parameters incorporated from
// https://datatracker.ietf.org/doc/html/rfc7518#section-6
//
// This type only implements the minimum number of fields necessary.
// Unimplemented: kid, x5*, private-key fields
type jwk struct {
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
	Type string `json:"kty"`

	// If present, we want the "sig" value.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	Use string `json:"use"`

	// If present, we want the "verify" value to be present.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	Ops []string `json:"key_ops"`

	// RSA or EC supported.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	Algorithm string `json:"alg"`

	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
	ID string `json:"kid"`

	// Elliptic Curve public key components.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
	Curve  string `json:"crv"`
	CurveX string `json:"x"`
	CurveY string `json:"y"`

	// RSA public key modulus and exponent.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
	RSAMod string `json:"n"`
	RSAExp string `json:"e"`
}

// Reify returns the JWK entry as a public key which may be used for
// signature verification.
func (k *jwk) Reify() (crypto.PublicKey, bool, error) {
	if k.Use != "" && k.Use != "sig" {
		return nil, false, nil
	}
	if len(k.Ops) > 0 {
		ok := false
		for _, op := range k.Ops {
			if op == "verify" {
				ok = true
				break
			}
		}
		if !ok {
			return nil, false, nil
		}
	}

	switch k.Type {
	case "EC":
		// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
		var err error
		ret := &ecdsa.PublicKey{}
		ret.X, err = decodeBase64UrlUInt(k.CurveX)
		if err != nil {
			return nil, false, errors.Wrapf(err, "key %q", k.ID)
		}
		ret.Y, err = decodeBase64UrlUInt(k.CurveY)
		if err != nil {
			return nil, false, errors.Wrapf(err, "key %q", k.ID)
		}

		// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
		switch k.Curve {
		case "P-256":
			ret.Curve = elliptic.P256()
		case "P-384":
			ret.Curve = elliptic.P384()
		case "P-521":
			ret.Curve = elliptic.P521()
		default:
			return nil, false, errors.Errorf("key %q uses unsupported curve %q", k.ID, k.Curve)
		}
		return ret, true, nil

	case "RSA":
		// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
		var err error
		ret := &rsa.PublicKey{}
		ret.N, err = decodeBase64UrlUInt(k.RSAMod)
		if err != nil {
			return nil, false, errors.Wrapf(err, "key %q cannot decode n", k.ID)
		}

		temp, err := decodeBase64UrlUInt(k.RSAExp)
		if err != nil {
			return nil, false, errors.Wrapf(err, "key %q cannot decode e", k.ID)
		}
		ret.E = int(temp.Int64())
		return ret, true, nil

	default:
		return nil, false, nil
	}
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-2
func decodeBase64UrlUInt(data string) (*big.Int, error) {
	buf, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	var ret big.Int
	ret.SetBytes(buf)
	return &ret, nil
}
