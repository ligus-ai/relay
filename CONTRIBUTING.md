# Contributing to the Langstroth relay

Thanks for helping. Questions and ideas go to
[Discussions](https://github.com/langstroth-ai/langstroth-relay/discussions),
bugs to [Issues](https://github.com/langstroth-ai/langstroth-relay/issues).
Security problems: see [SECURITY.md](SECURITY.md), not a public issue.

## Before you open a pull request

```sh
gofmt -l .          # must print nothing
go vet ./...
go test -race ./... # chart render tests run when helm is installed
helm lint --strict deploy/helm/langstroth-relay
```

CI runs the same checks and builds both images (`Dockerfile`,
`deploy/container/Dockerfile.langstroth-auth`).

## Repository layout

```
cmd/langstroth-relay/    the relay binary: subcommands (keygen, issue, bootstrap-agent, help), then relay.Serve
cmd/langstroth-auth/     the optional sign-in service binary
internal/relay/          the relay server package; files grouped by prefix
                         (blobs_*, contacts_*, tunnel_*, tenancy_*, limits_*, store_*),
                         tests beside the code, fixtures in internal/relay/testdata
internal/langstrothauth/ the sign-in service (OIDC, SCIM, token minting)
internal/apns/           the APNs client used for tunnel push
internal/envalias/       former-name environment variable handling
deploy/                  Helm charts, compose files, systemd unit, container files,
                         agent scripts; deploy/*_test.go test these artefacts
docs/                    operator reference
```

`/v1` and `hrt1` compatibility is pinned by the golden tests in
`internal/relay/golden_routes_test.go` and `golden_contacts_test.go`; their
fixtures in `internal/relay/testdata` change only for an intended wire change.

## Rules

- **Keep the wire stable.** The `/v1` routes and JSON, `hrt1` tokens, the
  `X-Hive-*` / `X-Ligus-*` headers, the `hive-tunnel.1` subprotocol, metric
  names, table names and crypto domain-separation strings are protocol
  identifiers. Don't rename them; add rather than change.
- **Stay content-blind.** The relay must never need a workspace key,
  plaintext, or a forge token.
- **Refuse, don't evict.** New limits answer `429` or `507` with
  `Retry-After` and a stable `error` code (`internal/relay/refusal.go`), and never drop
  stored envelopes.
- **Fail closed.** Settings that gate access must not silently turn off; an
  unreadable secret file stops the relay at startup.
- New settings are `LANGSTROTH_RELAY_*`, documented in
  [docs/reference.md](docs/reference.md), with a test.
- Behaviour changes get a [CHANGELOG.md](CHANGELOG.md) entry with upgrade
  notes for self-hosters.

Deploying or operating with a coding agent: [AGENTS.md](AGENTS.md).

By contributing you agree your work is licensed under the repository's
[MIT licence](LICENSE).
