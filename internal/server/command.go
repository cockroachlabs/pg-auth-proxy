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

package server

import (
	"context"

	"github.com/cockroachlabs/pg-auth-proxy/internal/config"
	"github.com/spf13/cobra"
)

// Command runs the server.
func Command() *cobra.Command {
	cfg := &config.Config{}
	c := &cobra.Command{
		Use:  "start",
		Args: cobra.NoArgs,
		Example: `
The backend configuration is a JSON file that maps a value extracted
from the JWT claim to a connection URL. If the key begins with a forward
slash, it is interpreted as a regular expression.

{
  "user@example.com": "postgres://....",
  "/^(.*)@example.com$": "postgres://...."
}
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Run the server in a separate context, so that we can
			// control the shutdown process.
			_, cancel, err := New(context.Background(), cfg)
			defer cancel()
			if err != nil {
				return err
			}

			// Wait to be shut down.
			<-cmd.Context().Done()
			return nil
		},
	}
	cfg.Bind(c.Flags())
	return c
}
