# certmint — certificate lifecycle policy

How a certificate is born, lives, renews, and dies, as implemented in
`cm-web.py`. (The prose rendering of a cert is UX; the signed block is
canonical.)

## Birth — issuance

- A cert is born only inside a mint session: the agent's public key is
  bound to the session *before* the human logs in, so there is no
  substitution window. The provider callback's verified identity plus
  that key is what the mint signs.
- Contents: the key and its fingerprint, the human's name, identity
  lines, `authenticated:` (the login instant), `issued:`,
  `expires:` = issued + **30 days**, a **serial** from a global
  monotonic counter, the issuer, and the mint's signature over all of
  it.
- v1 reality: one provider line per cert. Accumulation across
  providers means multiple certs on one key, not multiple identity
  lines on one cert — the spec's multi-line form is design intent the
  code has not reached yet.

## Life — validity

A cert is alive iff all three hold:

1. the mint signature verifies against the key published at `/pubkey`,
2. now < `expires`,
3. the serial is not on the revocation list at `/revoked`.

Anything beyond that (a possession challenge, an `authenticated:`
age floor) is the relying party's own policy layered on top.

## Refresh — the slide

- A possession proof (signing a fresh challenge nonce — single-use,
  300s life) plus a still-valid cert yields a **new cert with a new
  serial**, with the identity lines and `authenticated:` copied
  **verbatim**. Refresh never restamps `authenticated:` — holding a
  key is not being present.
- Two hard walls:
  - the cert must be **unexpired** at refresh time — there is no
    grace period; an expired cert is dead, not refreshable;
  - `authenticated:` + **365 days** is an absolute cap. Past it, the
    only path is a fresh login.
- A refresh **supersedes but does not kill** its predecessor: the old
  cert lives out its own window unless revoked. Overlapping validity
  is accepted behavior, not a leak.

## Death — two ways

- **Expiry** — automatic at `expires:`. Dead for every purpose;
  refresh refuses it ("a fresh login is required").
- **Revocation** — the serial is added to the mint's revoked list,
  published at `/revoked`. Immediate, permanent, per-serial: there is
  no un-revoke and no bulk operation; in v1 it is an operator edit to
  the mint's state file. The serial counter **never resets**, so a
  revoked serial can never be reborn on a different cert.

## Parameters

| Knob | Value | Meaning |
|---|---|---|
| Cert TTL | 30 days | Validity window per issuance or refresh |
| Auth cap | 365 days | Max age of `authenticated:` for refresh |
| Session TTL | 600 s | Time to complete a login |
| Challenge TTL | 300 s, single-use | Refresh possession proof |
| Serials | Monotonic, never reused | Revocation stays unambiguous forever |

In one sentence: a cert is a 30-day claim about a login, renewable by
possession for up to a year, killable instantly by serial, and never
resurrectable once dead.
