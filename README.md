# ai-certmint

**certmint** is a small mint for agent identity certificates. An AI agent
(a "muse") holds an Ed25519 keypair. To get certified, the agent opens a
minting session with its public key; its human clicks one link, signs in
at a consumer identity provider (Meta/Facebook, Slack) in their own
browser, and the mint issues a short signed text certificate binding
that human login to the agent's key:

```
kwid: 1
key: ssh-ed25519 <agent public key>
key-fingerprint: SHA256:<fingerprint>
name: <name from the provider>
identity: provider=slack team=<team-id> email=<email> sub=<user-id>
authenticated: 2026-10-15T18:53:46Z
issued: 2026-10-15T18:53:46Z
expires: 2026-11-14T18:53:46Z
serial: 7
issuer: certmint.ai
signature: <mint Ed25519 signature over all lines above>
```

The prose is UX; the signed key/value block is canonical. Relying
parties verify the mint's signature against its published public key,
check expiry and the revocation list, and can demand a fresh
possession proof (sign a challenge with the certified key).

REST surface: [API.md](API.md) — every route, grouped by plane, with
the trust model for each.

Lifecycle: [LIFECYCLE.md](LIFECYCLE.md) — how a cert is born, lives,
refreshes, and dies, with every policy parameter in one table.

Design document: [SPEC.md](SPEC.md) — the full spec, including the
refresh rules (30-day sliding window, 12-month absolute cap from the
last human authentication), revocation, provider policy notes, and
the direct-to-provider enrollment flow (the agent preselects the
provider; the human's click in chat lands directly on the provider's
login page; the agent reports the result).

## Files

- `cm-web.py` — the mint service (Python 3, stdlib HTTP server).
  Routes: provider logins (`/auth/meta`, `/auth/slack` + callbacks),
  session API (`POST /v1/sessions`, `GET /v1/sessions/<id>` with
  long-poll `?wait=N`, human page `/s/<id>`), refresh
  (`GET /v1/refresh/challenge`, `POST /v1/refresh`), `GET /pubkey`,
  `GET /revoked`.
- `cm-client.py` — a reference agent-side client
  (genkey / open / claim / await / refresh / verify / show). Uses the
  system `openssl` CLI for Ed25519 so it needs no Python crypto libs.

## Running a mint

The service expects, on the host:

- A mint signing key (Ed25519 PEM) — generated on the host, never
  distributed; its public key is published at `/pubkey`.
- `/etc/certmint/meta.env` — `META_APP_ID`, `META_APP_SECRET`.
- `/etc/certmint/slack.env` — `SLACK_APP_ID`, `SLACK_CLIENT_ID`,
  `SLACK_CLIENT_SECRET`, and optionally `SLACK_TEAM_ID`: when set,
  Slack sign-in is pinned to that workspace (sent on the authorize
  request and enforced on the verified id_token claims); when unset,
  any workspace may sign in.
- State (serial counter, sessions, challenges, revoked serials) is a
  single JSON file the service owns.

Site values (provider app credentials, the pinned workspace, keys)
are deployment config supplied through those files — never literals
in the code.

Slack sign-in uses only the OpenID Connect leg (scopes
`openid profile email`); the id_token is verified against Slack's
published JWKS (signature, issuer, audience, expiry, nonce, team).
No bot token, signing secret, or Socket Mode is involved.

## Status

Live and tested end to end at certmint.ai with two providers (Meta,
Slack). Certificates are valid 30 days; refresh slides the window on
a possession proof without a new login, up to 12 months from the
last human authentication.
