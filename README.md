# PG Auth Proxy

This is an experimental toolkit for injecting alternate authentication strategies into a
PostgreSQL-compatible wire format.

***This is a prototype and is not officially supported by Cockroach Labs.***

## Current state

In its present incarnation, pg-auth-proxy adds support for using JSON Web Tokens (JWT) as a source
of authentication (i.e. establishing the identity of an incoming connection). A JWT bearer token is
presented to the proxy via cleartext password authentication. The proxy validates the token's
signature against a list of public keys that are retrieved from a JWKS document referenced by an
OIDC discovery document or which are explicitly configured.

Upon receipt of a valid JWT claim, the proxy will consult a configuration file to map the `sub`
field to a database connection string. This connection string may use password-based authentication,
or it may use TLS-certificate based authentication.

End-to-end TLS is supported for incoming SQL connections as well as outgoing connections to the
target database.

The proxy supports gracefully draining connections by waiting for the SQL session to be in an idle
state before dropping the connection.

The automated tests run against multiple versions of CockroachDB and PostgreSQL.

## Flags

```
% ./pg-auth-proxy start --help
Usage:
  pg-auth-proxy start [flags]

Examples:

The backend configuration is a JSON file that maps a value extracted
from the JWT claim to a connection URL. If the key begins with a forward
slash, it is interpreted as a regular expression.

{
  "user@example.com": "postgres://....",
  "/^(.*)@example.com$": "postgres://...."
}


Flags:
      --backends string        the path to a JSON-formatted backends configuration
      --bindAddr string        a network address and port to bind to (default "127.0.0.1:13013")
      --bindCert string        the path to a PEM-encoded certificate chain to present to incoming connections
      --bindKey string         the path to a PEM-encoded private key to encrypt incoming connections with
      --gracePeriod duration   the amount of time to wait for SQL connections to become idle when shutting down (default 30s)
  -h, --help                   help for start
      --insecure               this flag must be set if no TLS configuration is provided
      --jwtField string        the JWT claim field to use when selecting backend configurations (default "sub")
      --metricsAddr string     an address to bind a metrics HTTP server to
      --oidcDiscovery string   the URL of an OIDC discovery document to bootstrap public signing keys
      --refresh duration       how often to refresh configuration data; set to 0 to disable; kill -HUP to manually refresh (default 24h0m0s)
      --reportRemoteAddr       if true, set the crdb:remote_addr connection parameter; requires COCKROACH_TRUST_CLIENT_PROVIDED_SQL_REMOTE_ADDR=true in the CRDB cluster environment
      --signingKeys strings    additional PEM-formatted public key or certificate files

Global Flags:
      --logDestination string   write logs to a file, instead of stdout
      --logFormat string        choose log output format [ fluent, text ] (default "text")
  -v, --verbose count           increase logging verbosity to debug; repeat for trace
```

## Monitoring

The `--metricsAddr` flag will start an HTTP server that provides a Prometheus-compatible endpoint
at `/vars`. There is also a `/health` endpoint which always return OK.

## Future work

The proxy does not support authorizing connections. That it, it does not perform user management or
dynamic role assignments to SQL users in the backend. This would be relatively straightforward to
implement via custom claims in the JWT token, or by implementing the SCIM protocol.

If presenting the JWT token via cleartext password authentication is infeasible, perhaps due to
string-length restrictions, an alternate means of passing the token could be performed by requiring
the client to issue a "magic" `SELECT proxy_login(....)` statement.