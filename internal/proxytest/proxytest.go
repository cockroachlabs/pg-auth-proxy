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

// Package proxytest contains test support code.
package proxytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	golog "log"
	"math/big"
	"net"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// ConfigureLogging should be called from TestMain to achieve consistent
// output from tests versus production.
func ConfigureLogging() {
	// Hijack anything that uses the standard go logger, like http.
	pw := log.WithField("golog", true).Writer()
	// logrus will provide timestamp info.
	golog.SetFlags(0)
	golog.SetOutput(pw)

	log.DeferExitHandler(func() { _ = pw.Close() })
	log.SetLevel(log.TraceLevel)
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.Stamp,
	})
}

// SelfSignedConfig returns a trivial tls.Config that contains a
// self-signed certificate.
func SelfSignedConfig() (*tls.Config, error) {
	// Loosely based on https://golang.org/src/crypto/tls/generate_cert.go
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}

	now := time.Now().UTC()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptoRand.Int(cryptoRand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate serial number")
	}

	cert := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
		},
	}

	bytes, err := x509.CreateCertificate(cryptoRand.Reader, &cert, &cert, &priv.PublicKey, priv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{bytes},
			PrivateKey:  priv,
		}}}, nil
}

// TokenSigningKey This is a trivial key for signing tokens.
var TokenSigningKey *ecdsa.PrivateKey

func init() {
	var err error
	TokenSigningKey, err = ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		log.WithError(err).Fatal("could not initialize dummy signing key")
	}
}

// MakeToken creates a token signed with TokenSigningKey.
func MakeToken(username string) string {
	tkn := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": username,
	})
	signed, err := tkn.SignedString(TokenSigningKey)
	if err != nil {
		log.Fatal(err)
	}
	return signed
}
