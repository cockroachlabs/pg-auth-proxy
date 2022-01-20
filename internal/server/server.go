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

// Package server contains the top-level network listener.
package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bobvawter/latch"
	"github.com/cockroachlabs/pg-auth-proxy/internal/config"
	"github.com/cockroachlabs/pg-auth-proxy/internal/conn"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Server is a pgwire-compatible proxy server.
type Server struct {
	activeConns     *latch.Counter
	metricsListener net.Listener
	sqlListener     net.Listener

	mu struct {
		sync.RWMutex
		cfg *config.Cache
	}
}

// New constructs a proxy server.
func New(ctx context.Context, cfg *config.Config) (_ *Server, cancel func(), _ error) {
	var err error

	s := &Server{
		activeConns: latch.New(),
	}

	// Initialize all expensive configuration options.
	s.mu.cfg, err = cfg.Cache(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	refreshTime.SetToCurrentTime()
	go s.refreshLoop(ctx, cfg)

	// Open SQL listener
	if s.sqlListener, err = net.Listen("tcp", cfg.BindAddr); err != nil {
		return nil, func() {}, errors.Wrapf(err, "could not bind to %q", cfg.BindAddr)
	}

	if cfg.MetricsAddr != "" {
		if s.metricsListener, err = net.Listen("tcp", cfg.MetricsAddr); err != nil {
			return nil, func() {}, errors.Wrapf(err, "could not bind to %q", cfg.MetricsAddr)
		}
	}

	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "open_connection_count",
		Help: "the number of currently-active connections",
	}, func() float64 { return float64(s.activeConns.Count()) })

	ctx, stop := context.WithCancel(ctx)
	// Goroutine to accept incoming connections.
	go s.serveMetrics(ctx)
	go s.serveSQL(ctx)

	return s, func() {
		// Stop accepting new connections.
		_ = s.sqlListener.Close()
		// Cancel the running context.
		stop()
		// Wait for connections to drain or to time out.
		select {
		case <-s.activeConns.Wait():
			log.Info("server drained cleanly")
		case <-time.After(cfg.GracePeriod):
			log.Warn("shutdown grace period expired")
		}
		if s.metricsListener != nil {
			_ = s.metricsListener.Close()
		}
	}, nil
}

func (s *Server) refreshLoop(ctx context.Context, cfg *config.Config) {
	ch := make(chan os.Signal, 1)
	defer close(ch)

	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.Refresh):
		case <-ch:
		}
		next, err := cfg.Cache(ctx)
		if err != nil {
			log.WithError(err).Warn("could not refresh configuration")
			continue
		}
		s.mu.Lock()
		s.mu.cfg = next
		s.mu.Unlock()
		refreshTime.SetToCurrentTime()
		log.Info("configuration refresh complete")
	}
}

func (s *Server) serveMetrics(ctx context.Context) {
	if s.metricsListener == nil {
		return
	}
	log.WithField("addr", s.metricsListener.Addr()).Info("metrics started")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.Handle("/vars", promhttp.Handler())
	mux.Handle("/", http.NotFoundHandler())

	metrics := &http.Server{
		BaseContext: func(net.Listener) context.Context { return ctx },
		Handler:     mux,
		TLSConfig:   s.mu.cfg.TLSConfig,
	}
	_ = metrics.Serve(s.metricsListener)
}

// run accepts incoming connections and creates new goroutines to
// service them.
func (s *Server) serveSQL(ctx context.Context) {
	log.WithField("addr", s.sqlListener.Addr()).Info("sql proxy started")
	for {
		netConn, err := s.sqlListener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.WithError(err).Fatal("unable to accept incoming connection")
		}

		s.activeConns.Hold()
		go func() {
			s.mu.RLock()
			cache := s.mu.cfg
			s.mu.RUnlock()

			c := conn.New(cache, netConn)
			defer s.activeConns.Release()
			if err := c.Run(ctx); err != nil {
				log.WithError(err).Error("error in connection")
			}
		}()
	}
}
