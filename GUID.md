# certmint — GUID certificates

A second class of certificate the mint issues: not *who you are* but
*where you can be reached*. A GUID cert binds an unguessable address —
a GUID — to a key, so traffic (a knockwire knock, a webhook) can be
addressed to exactly one holder and to no one else, **with no
registry anywhere**. The association function has a working name,
*certlink*; it ships as part of certmint, not as a separate service.

## The model

- **The mint generates the GUID.** At issue-new, the mint draws 32
  random bytes. Because the mint is the sole generator, a signed guid
  cert attests that its GUID is **unique and original** — a GUID
  copied from elsewhere can never be certified, because the mint only
  ever signs hashes of GUIDs it generated itself.
- **The raw GUID leaves the server exactly once**, in the issue-new
  response, and is never written to state, to the log, or anywhere
  else. What persists is only its hash — `guid-hash:`, a
  fingerprint-style SHA-256 of the raw GUID bytes — inside the issued
  certs. A compromised mint yields hashes and certs: nothing that can
  create a knock and nothing that can impersonate a holder.
- **Security does not derive from the GUID.** The GUID is an address,
  not a credential: knowing it lets a caller deliver a pointer (a
  knock), and nothing more. Authority derives from cert possession —
  knocks for a GUID are delivered only to the holder who proved
  possession of a live guid cert for it.
- **Certs are peers, not a chain.** Any number of guid certs may bind
  the same `guid-hash:` to the **same key**. Issuing one never
  supersedes or revokes another. Staggered expiry across peers is
  the resilience mechanism: the GUID is stranded only if **every**
  peer lapses (expires or is revoked) at once — or the key itself is
  lost. Recovery after stranding is a fresh issue-new — and
  reconfiguring every webhook that carried the old GUID.
- **One key per GUID.** An earlier design let a guid cert bind the
  hash to *additional* keys (issue-another). It was dropped
  (2026-10-15): consumers such as knockwire authenticate with the
  one guid cert, and extra key edges were surface without a need.
  A GUID's key is fixed at issue-new for the GUID's whole life.

## The cert

The identity-cert format minus identity, plus one line:

```
kwid: 1
key: ssh-ed25519 <holder public key>
key-fingerprint: SHA256:<fingerprint>
guid-hash: SHA256:<hash of the raw GUID>
authenticated: <copied verbatim from the authorizing cert>
issued: <mint instant>
expires: <issued + 30 days>
serial: <global monotonic serial>
issuer: certmint.ai
signature: <mint Ed25519 signature over all lines above>
```

`authenticated:` is inherited, never restamped: it records the human
authentication at the root of the peer set, exactly as refresh does
for identity certs.

## The two operations

Every operation is gated on a single-use challenge (300s life) and a
possession proof. Challenges are kind-bound: a refresh challenge
cannot authorize a guid operation, and vice versa.

| Operation | Authorizer | Effect |
|---|---|---|
| **Issue new** — `POST /v1/guids` | A live **identity cert** | The mint generates a fresh GUID and mints the first peer: `guid-hash:` → the identity cert's key. Response `201 {cert, serial, guid}` — the only place the raw GUID ever appears |
| **Renew** — `POST /v1/guids/renew` | A live **guid cert** | Mints another peer: same hash, same key, new serial, fresh 30-day expiry |

The invariant across both: **the mint never signs a guid cert
except on a possession proof of the authorizing cert's key** — and
the key a GUID is bound to never changes.

## Verification

Entirely local, identical to identity certs: verify the mint
signature against `/pubkey`, check `expires:`, check the serial
against `/revoked`. There is no registry call to make — the address
book of the whole system is the set of certs bearers hold, and
nothing else exists.

## Lifecycle notes

- Guid certs share the identity machinery: **30-day TTL**, serials
  from the same global monotonic counter, revocation by serial —
  permanent and per-serial, exactly as for identity certs.
- Revoking one peer does not strand the GUID while another peer
  lives; revoking or losing all of them does.
- No separate cap is imposed on guid operations: authorization is a
  *live* peer, and every peer set traces back to an identity cert
  whose own 365-day authentication cap governed its refresh life.
- A guid cert authorizes only guid operations for its own hash. It
  is not an identity and certifies nothing about a human.
