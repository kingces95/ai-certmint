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

## Human browser plane — HTML + cookies

Exists only to put the human in front of their identity provider.

| Route | Behavior |
|---|---|
| `GET /s/<id>` | The session page. Issued → a blank "Done" page (which also attempts `window.close()`); expired → a notice; pending with a preselected provider → `302` straight to that provider's auth start; pending without one → a chooser page showing the key fingerprint and provider buttons |
| `GET /auth/meta` · `GET /auth/slack` | Bind `state` (and `nonce` for Slack) to the session when `?s=` names a pending one, set the `cm_state`/`cm_nonce` cookies, and `302` to the provider. Slack requests carry the workspace pin when the deployment configures one. `503` when the provider is not configured |
| `GET /auth/meta/callback` · `GET /auth/slack/callback` | State-vs-cookie check (`400` on mismatch), authorization-code exchange, then identity fetch/verify: Graph `/me` for Meta; for Slack, the `id_token` verified against Slack's JWKS (signature, issuer, audience, expiry, nonce, pinned team). On success: issue into the bound session if any, set a 24-hour web-login cookie, `302` to `/s/<id>` or `/`. Provider failures surface as `502` |
| `GET /` · `GET /logout` | Apex status page (who you are web-signed-in as, or the provider buttons); logout clears the web session |

## Cross-cutting properties

- **State** is one JSON file (serial counter, sessions, challenges,
  revoked serials), lock-guarded with atomic replace. Web-login
  sessions are memory-only — a restart forgets them, by design.
- **Errors** speak two vocabularies: JSON `{error}` on the API plane,
  HTML pages on the browser plane. Everything unmatched is a plain
  `404`; `HEAD` works everywhere `GET` does.
- **No rate limiting, no CORS, no request auth headers.** The security
  model rests on: 192-bit session IDs, single-use challenges,
  possession proofs, provider-side token verification, and the mint
  signing key never leaving the host.
- The cert format version (`kwid: 1`) is the only versioning on the
  surface; the API itself is unversioned beyond the `/v1/` prefix.
