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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	authFails = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sql_auth_failures_total",
		Help: "the number of failed authentications",
	})
	authSuccesses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sql_auth_successes_total",
		Help: "the number of successful authentications",
	})
	dialFails = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "target_dial_failures_total",
		Help: "the number of times a backend connection failed",
	}, []string{"host"})
	dialSuccesses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "target_dial_successes_total",
		Help: "the number of times a backend connection succeeded",
	}, []string{"host"})
)
