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

package conn

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/cockroachlabs/pg-auth-proxy/internal/config"
	"github.com/cockroachlabs/pg-auth-proxy/internal/proxytest"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

var (
	serverTLSConfig *tls.Config
	targetConfig    *pgconn.Config
)

func TestMain(m *testing.M) {
	proxytest.ConfigureLogging()

	var err error
	serverTLSConfig, err = proxytest.SelfSignedConfig()
	if err != nil {
		log.Fatal(err)
	}

	connString := os.Getenv("TEST_CONNECT_STRING")
	if connString == "" {
		connString = "postgres://root@127.0.0.1:26257/?sslmode=disable"
	}

	targetConfig, err = pgconn.ParseConfig(connString)
	if err != nil {
		log.Fatal(err)
	}

	// Smoke test the target db configuration
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, err := pgconn.ConnectConfig(ctx, targetConfig)
	if err != nil {
		log.Fatal(err)
	}
	_ = conn.Close(ctx)
	cancel()

	os.Exit(m.Run())
}

// This is a simple smoke-test of a single Conn instance, which uses a
// net.Pipe between the pgx client and the Conn. We use a real
// connection to the supporting target database.
func TestGoldenPath(t *testing.T) {
	a := assert.New(t)

	a.NoError(runTest(func(ctx context.Context, proxy *Conn, db *pgx.Conn) error {
		var resp string
		a.NoError(db.QueryRow(ctx, "SELECT current_user").Scan(&resp))
		a.Equal(targetConfig.User, resp)

		a.NoError(db.Close(ctx))
		return nil
	}))
}

func TestActiveFlag(t *testing.T) {
	a := assert.New(t)

	// BEGIN; command; COMMIT
	a.NoError(runTest(func(ctx context.Context, proxy *Conn, db *pgx.Conn) error {
		// An open transaction will force the active state.
		tx, err := db.Begin(ctx)
		a.NoError(err)
		a.NotNil(tx)
		a.True(proxy.IsActive())

		// Running a command in a transaction won't clear the flag.
		var resp string
		a.NoError(tx.QueryRow(ctx, "SELECT current_user").Scan(&resp))
		a.Equal(targetConfig.User, resp)
		a.True(proxy.IsActive())

		// Committing will.
		a.NoError(tx.Commit(ctx))
		a.False(proxy.IsActive())
		return nil
	}))

	// BEGIN; command; ROLLBACK
	a.NoError(runTest(func(ctx context.Context, proxy *Conn, db *pgx.Conn) error {
		// An open transaction will force the active state.
		tx, err := db.Begin(ctx)
		a.NoError(err)
		a.NotNil(tx)
		a.True(proxy.IsActive())

		// Running a command in a transaction won't clear the flag.
		var resp string
		a.NoError(tx.QueryRow(ctx, "SELECT current_user").Scan(&resp))
		a.Equal(targetConfig.User, resp)
		a.True(proxy.IsActive())

		// Rolling back will.
		a.NoError(tx.Rollback(ctx))
		a.False(proxy.IsActive())
		return nil
	}))

	// BEGIN; error command; ROLLBACK
	a.NoError(runTest(func(ctx context.Context, proxy *Conn, db *pgx.Conn) error {
		// An open transaction will force the active state.
		tx, err := db.Begin(ctx)
		a.NoError(err)
		a.NotNil(tx)
		a.True(proxy.IsActive())

		// Running a command in a transaction won't clear the flag.
		var resp string
		a.Error(tx.QueryRow(ctx, "BAD COMMAND current_user").Scan(&resp))
		a.True(proxy.IsActive())

		// Committing will.
		a.NoError(tx.Rollback(ctx))
		a.False(proxy.IsActive())
		return nil
	}))
}

func TestDrainInTransaction(t *testing.T) {
	a := assert.New(t)
	a.NoError(runTest(func(ctx context.Context, proxy *Conn, db *pgx.Conn) error {
		tx, err := db.Begin(ctx)
		a.NoError(err)
		a.NotNil(tx)
		a.True(proxy.IsActive())

		a.NoError(proxy.markDraining())
		a.True(proxy.IsActive())
		a.True(proxy.IsDraining())
		a.False(proxy.IsClosed())

		// We should still be able to work with the transaction.
		var resp string
		a.NoError(tx.QueryRow(ctx, "SELECT current_user").Scan(&resp))
		a.Equal(targetConfig.User, resp)

		// Now, the connection should close out.
		a.NoError(tx.Commit(ctx))

		// Verify that brining the connection out of idle fails.
		_, err = db.Begin(ctx)
		a.Error(err)

		a.True(proxy.IsActive())
		a.True(proxy.IsDraining())
		a.True(proxy.IsClosed())

		return nil
	}))
}

func runTest(fn func(ctx context.Context, proxy *Conn, db *pgx.Conn) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	left, right := net.Pipe()

	proxy := New(&config.Cache{
		Config: &config.Config{JwtField: "sub"},
		Backends: config.BackendMap{
			regexp.MustCompile("^testy$"): targetConfig,
		},
		PublicKeys: []crypto.PublicKey{proxytest.TokenSigningKey.Public()},
		TLSConfig:  serverTLSConfig,
	}, right)
	// Execute the proxy code in one goroutine.
	grp, ctx := errgroup.WithContext(ctx)
	grp.Go(func() error {
		return proxy.Run(ctx)
	})

	// And the client code in another.
	grp.Go(func() error {
		fakeConfig, err := pgx.ParseConfig(fmt.Sprintf(
			"postgresql://ignored:%s@127.0.0.1:1/postgres?sslmode=require",
			proxytest.MakeToken("testy")))
		if err != nil {
			return err
		}
		fakeConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) { return left, nil }

		conn, err := pgx.ConnectConfig(ctx, fakeConfig)
		if err != nil {
			return err
		}
		defer conn.Close(context.Background())

		return fn(ctx, proxy, conn)
	})

	return grp.Wait()
}
