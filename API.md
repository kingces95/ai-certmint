# certmint — REST surface

The whole HTTP surface of the mint service (`cm-web.py`), grouped by
plane. There are no accounts and no API tokens anywhere: security is
unguessable IDs, single-use challenges, possession proofs, and
provider-side token verification.

## Public read plane — no auth, safe to expose

| Route | Returns |
|---|---|
| `GET /pubkey` | The mint's public key line, its fingerprint, and the issuer |
| `GET /revoked` | Plain text, one revoked serial per line |

## Agent API plane — bearer-by-knowledge

| Route | Shape |
|---|---|
| `POST /v1/sessions` | In: `{key, provider?}` → `201 {session_id, url, provider, fingerprint, expires}`. A session lives 600s. `400` on a bad key or an unknown provider |
| `GET /v1/sessions/<id>` | The claim. `200 {status: pending\|expired}` or `{status: issued, serial, cert}`. `?wait=N` (clamped 0–60s) long-polls until issuance, expiry, or timeout. `404` on an unknown ID. Anyone holding the session ID can claim — it is a capability URL |
| `GET /v1/refresh/challenge?serial=N` | `200 {nonce, signing_string}`. The nonce is single-use with a 300s life |
| `POST /v1/refresh` | In: `{cert, nonce, signature}` → `200 {cert, serial}`. Rejects, in order: unparseable cert → bad mint signature → unknown/replayed/expired challenge (`400`); revoked serial → expired cert → authentication older than 365 days → possession proof fails (`403`). Identity lines and `authenticated:` are copied verbatim; only the validity window slides |
| `GET /v1/guids/challenge?serial=N` | `200 {nonce, signing_string}` for a guid operation authorized by cert serial N. Kind-bound (`guid-auth`): a refresh challenge cannot be spent here, nor this one at refresh |
| `POST /v1/guids` | **Issue new.** In: `{cert, nonce, signature}` where cert is a live identity cert → `201 {cert, serial, guid}`. The mint generates the GUID; the raw value appears only in this response and is never stored or logged. `400` when the authorizer is a guid cert or lacks identity lines; `403` on revoked/expired authorizer or a failed possession proof |
| `POST /v1/guids/renew` | **Renew.** In: `{cert, nonce, signature}` where cert is a live guid cert → `201 {cert, serial}`: a new peer, same `guid-hash:`, same key. `400` when the authorizer is an identity cert. There is no operation that binds a GUID to a different key — a GUID's key is fixed at issue-new |

## Human browser plane — HTML + cookies

Exists only to put the human in front of their identity provider.

| Route | Behavior |
|---|---|
| `GET /s/<id>` | The session page. Issued → a blank "Done" page (which also attempts `window.close()`); expired → a notice; pending with a preselected provider → `302` straight to that provider's auth start; pending without one → a chooser page showing the key fingerprint and provider buttons |
| `GET /auth/meta` · `GET /auth/slack` · `GET /auth/google` | Bind `state` (and `nonce` for OIDC providers) to the session when `?s=` names a pending one, set the `cm_state`/`cm_nonce` cookies, and `302` to the provider. Slack requests carry the workspace pin when the deployment configures one. `503` when the provider is not configured |
| `GET /auth/meta/callback` · `GET /auth/slack/callback` · `GET /auth/google/callback` | State-vs-cookie check (`400` on mismatch), authorization-code exchange, then identity fetch/verify: Graph `/me` for Meta; for Slack and Google, the `id_token` verified against the provider's JWKS (signature, issuer, audience, expiry, nonce, plus Slack's pinned team or Google's verified email). On success: issue into the bound session if any, set a 24-hour web-login cookie, `302` to `/s/<id>` or `/`. Provider failures surface as `502` |
| `GET /` · `GET /logout` | Apex status page (who you are web-signed-in as, or the provider buttons); logout clears the web session |

## Agent enrollment sequence

1. Generate and retain an Ed25519 keypair on the agent.
2. `POST /v1/sessions` with the SSH-format public key and, for a direct
   Google flow, `provider: "google"`.
3. Give the returned `url` to the human. Treat it as a ten-minute bearer
   capability; never include the private key.
4. Long-poll `GET /v1/sessions/<id>?wait=60` until `status` is `issued`
   or `expired`.
5. Verify the returned certificate's mint signature with `GET /pubkey`,
   verify its `key-fingerprint` against the agent's local key, check the
   validity window, and consult `GET /revoked` before relying on it.

The reference `cm-client.py` implements this sequence as `genkey`,
`open google`, and `await`. The human's browser sees Google; the agent
never receives the Google password, OAuth authorization code, or the
deployment's Google client secret.

## Cross-cutting properties

- **State** is one JSON file (serial counter, sessions, challenges,
  revoked serials), lock-guarded with atomic replace. Web-login
  sessions are memory-only — a restart forgets them, by design.
  GUIDs add **no state at all**: the raw GUID is returned once at
  issue-new and never persisted; its hash exists only inside issued
  certs (see [GUID.md](GUID.md)).
- **Errors** speak two vocabularies: JSON `{error}` on the API plane,
  HTML pages on the browser plane. Everything unmatched is a plain
  `404`; `HEAD` works everywhere `GET` does.
- **No rate limiting, no CORS, no request auth headers.** The security
  model rests on: 192-bit session IDs, single-use challenges,
  possession proofs, provider-side token verification, and the mint
  signing key never leaving the host.
- The cert format version (`kwid: 1`) is the only versioning on the
  surface; the API itself is unversioned beyond the `/v1/` prefix.
