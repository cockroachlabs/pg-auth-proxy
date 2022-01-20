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

// Package conn contains code that supports a single pgwire proxy
// connection.
package conn

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/cockroachlabs/pg-auth-proxy/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/chunkreader/v2"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgproto3/v2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

//go:generate go run golang.org/x/tools/cmd/stringer -type=closeReason
type closeReason int

const (
	terminateFromClient closeReason = iota
	drainConnection
	generalError
)

// Conn represents a single proxy connection between an incoming SQL
// caller and the target database.
type Conn struct {
	cfg *config.Cache

	clientConn net.Conn          // Network socket tho the SQL client.
	clientMsg  *pgproto3.Backend // Messages from the SQL client.

	targetConn net.Conn           // Network socket to the target database.
	targetMsg  *pgproto3.Frontend // Messages to the target database.

	mu struct {
		sync.Mutex
		active bool // Set by client messages, cleared by server's idle-channel message.
		closed bool // Makes closeLocked() a one-shot.
		drain  bool // Async request for the connection to be dropped.
	}
}

// New constructs a proxy connection around the incoming network stream.
func New(cfg *config.Cache, clientConn net.Conn) *Conn {
	return &Conn{
		cfg:        cfg,
		clientConn: clientConn,
	}
}

// IsActive returns true if the client has sent data to the target,
// and no ReadyForQuery message has been sent back.
func (c *Conn) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mu.active
}

// IsClosed returns true if the proxy connection is closed.
func (c *Conn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mu.closed
}

// IsDraining returns true if the connection has been placed into a
// drain mode.
func (c *Conn) IsDraining() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mu.drain
}

// Run is called after the connection has been constructed. Canceling
// the context will trigger a graceful drain of the connection.
func (c *Conn) Run(ctx context.Context) error {
	startup, err := c.startup()
	if err != nil {
		return c.sendError(err)
	}

	connCfg, err := c.authenticate()
	if err != nil {
		authFails.Inc()
		return c.sendError(err)
	}
	authSuccesses.Inc()

	if err := c.dialTarget(ctx, connCfg, startup); err != nil {
		dialFails.WithLabelValues(connCfg.Host).Inc()
		return c.sendError(err)
	}
	dialSuccesses.WithLabelValues(connCfg.Host).Inc()

	c.copy(ctx)
	return nil
}

// authenticate requests a password from the client, extracts a valid
// JWT token from it, then chooses a matching backend configuration.
func (c *Conn) authenticate() (*pgconn.Config, error) {
	// Demand a password.
	if err := c.clientMsg.Send(&pgproto3.AuthenticationCleartextPassword{}); err != nil {
		return nil, errors.WithStack(err)
	}

	// Await a returned password message.
	msg, err := c.clientMsg.Receive()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	passwd, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return nil, errors.Errorf("received unexpected message type %T", msg)
	}

	// Validate the token and extract the principal.
	principal, ok := c.getPrincipal(passwd.Password)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Match the extracted principal name against the configuration map.
	for pattern, cfg := range c.cfg.Backends {
		if pattern.MatchString(principal) {
			log.Tracef("accepted connection for %q", principal)
			return cfg, nil
		}
	}

	log.Tracef("no backend configuration for valid principal %q", principal)
	return nil, ErrInvalidToken
}

// closeLocked attempts to send a graceful shutdown message to both the
// client and the target database. The underlying network connections
// will also be closed.
func (c *Conn) closeLocked(reason closeReason) error {
	if c.mu.closed {
		return nil
	}
	c.mu.closed = true
	log.Tracef("closing: %s", reason)

	// If we got a Terminate message from the client, it will have shut
	// down the network connection.
	if reason != terminateFromClient {
		if c.clientMsg != nil {
			_ = c.clientMsg.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR",
				Code:     pgerrcode.AdminShutdown,
				Message:  "proxy shutting down",
			})
			log.Trace("sent shutdown message")
		}

		if c.clientConn != nil {
			_ = c.clientConn.Close()
			log.Trace("closed client connection")
		}
	}

	if c.targetMsg != nil {
		_ = c.targetMsg.Send(&pgproto3.Terminate{})
		log.Trace("sent Terminate to target")
	}

	if c.targetConn != nil {
		_ = c.targetConn.Close()
		log.Trace("closed target connection")
	}

	log.Trace("closed")
	return nil
}

// copy is the steady-state loop for a connection. It starts additional
// goroutines that delegate to the other copy methods in this type. When
// the context is canceled, the connection will go into a draining state
// and terminate only once the SQL interaction is in an idle state.
func (c *Conn) copy(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	work, ctx := errgroup.WithContext(ctx)

	// When the context shuts down, close the connection if we're idle,
	// otherwise, set the drain-intent flag.
	work.Go(func() error {
		<-ctx.Done()
		return c.markDraining()
	})

	// Copy messages from the SQL client to the target database.
	work.Go(func() error {
		for {
			if err := c.copyFromClientToTarget(); err != nil {
				return err
			}
		}
	})

	// Copy responses from the target database back to the client.
	work.Go(func() error {
		for {
			if err := c.copyFromTargetToClient(); err != nil {
				return err
			}
		}
	})
	_ = work.Wait()
}

// copyFromClientToTarget reads and proxies a single message from the
// SQL client to the backend database. If a Terminate message is
// received, it will cleanly shut down the connection.
func (c *Conn) copyFromClientToTarget() error {
	msg, err := c.clientMsg.Receive()
	if err != nil {
		return errors.WithStack(err)
	}
	log.WithField("msg", msg).Trace("client -> target")

	if _, stop := msg.(*pgproto3.Terminate); stop {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.closeLocked(terminateFromClient)
	}

	// Ensure we're unlocked before calling Send below.
	c.mu.Lock()
	c.mu.active = true
	c.mu.Unlock()

	return errors.WithStack(c.targetMsg.Send(msg))
}

// copyFromTargetToClient reads and proxies a single message from the
// backend database to the client. If the drain flag is set, the channel
// will be closed upon receipt of an idle message.
func (c *Conn) copyFromTargetToClient() error {
	msg, err := c.targetMsg.Receive()
	if err != nil {
		return errors.WithStack(err)
	}
	log.WithField("msg", msg).Trace("client <- target")

	switch t := msg.(type) {
	case *pgproto3.ReadyForQuery:
		// https://www.postgresql.org/docs/current/protocol-message-formats.html
		// 'I' means idle and not in a transaction block.
		if t.TxStatus == 'I' {
			if c.mu.drain {
				_ = c.clientMsg.Send(msg)
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.closeLocked(drainConnection)
			}

			// Ensure we're unlocked before calling Send below.
			c.mu.Lock()
			c.mu.active = false
			c.mu.Unlock()
		}
	}

	return errors.WithStack(c.clientMsg.Send(msg))
}

// dialTarget establishes a connection to the target database. It will
// proxy the startup message, decorating it as appropriate.
func (c *Conn) dialTarget(
	ctx context.Context, config *pgconn.Config, startup *pgproto3.StartupMessage,
) error {
	// Copy default run-time params
	for k, v := range config.RuntimeParams {
		startup.Parameters[k] = v
	}
	if config.User != "" {
		startup.Parameters["user"] = config.User
	}
	if config.Database != "" {
		startup.Parameters["database"] = config.Database
	}
	log.WithField("params", startup.Parameters).Trace("startup")

	pgConn, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return errors.Wrap(err, "could not connect")
	}
	h, err := pgConn.Hijack()
	if err != nil {
		return errors.Wrap(err, "could not hijack")
	}

	c.targetConn = h.Conn
	c.targetMsg = h.Frontend.(*pgproto3.Frontend)

	for k, v := range h.ParameterStatuses {
		if err := c.clientMsg.Send(&pgproto3.ParameterStatus{Name: k, Value: v}); err != nil {
			return errors.Wrap(err, "could not proxy parameter status")
		}
	}
	if err := c.clientMsg.Send(&pgproto3.BackendKeyData{ProcessID: h.PID, SecretKey: h.SecretKey}); err != nil {
		return errors.Wrap(err, "could not proxy backend key data")
	}

	if err := c.clientMsg.Send(&pgproto3.ReadyForQuery{TxStatus: h.TxStatus}); err != nil {
		return errors.Wrap(err, "could not go into idle mode")
	}

	return nil
}

// getPrincipal parses and validates the incoming password. It will
// return the principal that the incoming request acts as.
func (c *Conn) getPrincipal(password string) (string, bool) {
	// Attempt to parse the password as a JWT token. We'll extract the
	// claim data into a free-form map, rather than into a specific
	// struct type.
	var found jwt.MapClaims
	for _, pubKey := range c.cfg.PublicKeys {
		claimData := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(password, &claimData,
			func(tkn *jwt.Token) (interface{}, error) {
				return pubKey, nil
			},
		); err == nil {
			found = claimData
			break
		}
	}
	if found == nil {
		return "", false
	}

	// This will generally extract the "sub" field, but it's configurable.
	// TODO: Allow dotted-path notation?
	prn, ok := found[c.cfg.JwtField]
	if !ok {
		log.Tracef("the jwt field %q was not present in the incoming claim", c.cfg.JwtField)
		return "", false
	}

	principal, ok := prn.(string)
	if !ok {
		log.Tracef("unexpected principal data received %T", prn)
		return "", false
	}
	return principal, true
}

// markDraining will place the proxy connection into a draining mode.
// If the connection is idle, it will be closed immediately.
func (c *Conn) markDraining() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mu.drain = true
	if !c.mu.active {
		return c.closeLocked(drainConnection)
	}
	return nil
}

// sendError will construct a wire message describing the given error.
// If the error is a WrappedError, the enclosed message will be sent
// instead. In all cases, the error argument is returned.
func (c *Conn) sendError(err error) error {
	if err == nil {
		return nil
	}
	log.WithError(err).Error("proxy connection failed")
	_ = c.clientMsg.Send(AsErrorResponse(err))
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.closeLocked(generalError)

	return err
}

// startup receives the initial message from the client and performs
// any necessary protocol switching.
func (c *Conn) startup() (*pgproto3.StartupMessage, error) {
	c.clientMsg = pgproto3.NewBackend(pgproto3.NewChunkReader(c.clientConn), c.clientConn)
	for {
		var msg pgproto3.FrontendMessage
		msg, err := c.clientMsg.ReceiveStartupMessage()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		log.WithField("msg", msg).Info("startup")

		switch t := msg.(type) {
		case *pgproto3.StartupMessage:
			return t, nil

		case *pgproto3.SSLRequest:
			// https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.11
			// We'll send a single byte to indicate SSL support (or not).
			if c.cfg.TLSConfig == nil {
				if _, err = c.clientConn.Write([]byte{'N'}); err != nil {
					return nil, errors.WithStack(err)
				}
				continue
			}
			if _, err = c.clientConn.Write([]byte{'S'}); err != nil {
				return nil, errors.WithStack(err)
			}

			// Swap out the underlying connections, then start up again.
			tlsConn := tls.Server(c.clientConn, c.cfg.TLSConfig)
			c.clientConn = tlsConn
			c.clientMsg = pgproto3.NewBackend(chunkreader.New(tlsConn), tlsConn)

		default:
			return nil, errors.Errorf("unsupported startup message: %T", t)
		}
	}
}
