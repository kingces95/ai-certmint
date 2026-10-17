> Public copy: personal identifiers from the reference deployment
> (account ids, email addresses, hostnames) are replaced with
> placeholders in this file.

# certmint — v1 spec (updated 2026-10-14 late)

Status: V1 BUILT AND LIVE-TESTED 2026-10-14 late (Chris authorized:
"Cook that more real world version. Test it."). Running on CERTMINT
as cm-web.py (source ~/workspace/certmint/cm-web.py): Meta login,
session API (POST /v1/sessions, GET /s/<id>, GET /v1/sessions/<id>),
issuance, POST /v1/refresh (+ challenge), GET /pubkey, GET /revoked.
Mint signing key: Ed25519, /etc/certmint/mint-ed25519.pem (600, root,
generated on the VM, never leaves it), fingerprint
SHA256:l6cC1jD59kfRnBPvgVrD/LdX/yr+ZNSo9f2NGderWVI. First cert ever
issued: serial 1 to Hal's certmint key (fingerprint
SHA256:onlH7DhZFwwXTQuK2IoLjuzQZdLblrNDfU6oIix6yOk) binding Chris's
Facebook login (CertMint-app sub <meta-user-id>), 2026-10-15
08:10:21Z; refresh proven (serial 2, window slid, `authenticated:`
unchanged); negative tests pass (tampered body → mint-signature
reject; wrong-key possession → reject; replayed challenge nonce →
reject). Cert validity 30 days sliding; absolute cap 12 months from
`authenticated:` (Chris approved).

Slack provider ADDED 2026-10-15 (second live provider): Sign in with
Slack (OIDC), app A0C9NPMMJM7, client secret at /etc/certmint/slack.env
(600, root, on CERTMINT). Flow: GET /auth/slack 302s to
slack.com/openid/connect/authorize with scopes `openid profile email`,
a state + nonce pair (cookies), and the workspace PINNED via `team=`;
GET /auth/slack/callback exchanges the code at openid.connect.token and
verifies the id_token against Slack's JWKS (PyJWT: RS256, iss
https://slack.com, aud = client id, exp), then fails closed unless the
nonce matches AND the `https://slack.com/team_id` claim equals the
pinned team. The pin is per-deployment config (SLACK_TEAM_ID in
cm-web.py; king bots = <team-id> here) — a cert's identity is only
meaningful scoped to its workspace. Identity line:
`identity: provider=slack team=<team id> email=<email> sub=<user id>`,
e.g. Chris's first Slack cert, serial 6 (2026-10-15):
`team=<team-id> email=user@example.com sub=<slack-user-id>`. The sub
is Slack's workspace-scoped user ID — the same ID that authors the
user's messages and appears in mentions there, so a relying party in
that workspace can string-match cert sub against message author IDs
(the original motivation for adding Slack). Only the OIDC leg is used:
no bot token, signing secret, or Socket Mode.

Google provider ADDED 2026-10-16 (third live provider): Sign in with
Google (OIDC) using scopes `openid email profile`. The authorization
request carries state and nonce cookies; the callback exchanges the
code at `oauth2.googleapis.com/token` and verifies the ID token against
Google's JWKS. Issuance fails closed unless the signature, expiry,
audience, issuer, nonce, subject, and `email_verified` claim all pass.
Identity line:
`identity: provider=google email=<verified email> sub=<subject>`.
The OAuth client is deployment configuration in
`/etc/certmint/google.env`; the authorized callback is
`https://certmint.ai/auth/google/callback`.

Direct-to-provider flow (Chris's UX call, 2026-10-15): a mint session
may carry a preselected `provider` (POST /v1/sessions accepts
`provider`: facebook|slack|google). GET /s/<id> for such a session 302s
straight to that provider's auth start — the human's click in chat
lands directly on the provider's own login page, with no certmint
page and no button in between; provider + workspace were chosen by
the agent when it opened the session. The post-issuance /s/<id> page
is a blank landing pad ("Done — you can close this page", plus a
window.close() attempt): the cert is never displayed on the web; the
agent claims it via the API and reports the result in chat. What
replaces the old fingerprint-comparison page as the safety check:
the provider's real domain in the address bar during login, and the
agent verifying the claimed cert's key fingerprint against its own
key before reporting success. Sessions opened without a provider
keep the chooser page (fallback for agents that can't preselect).
Demonstrated live 2026-10-15 with Slack (serial 7). Test-phase rule
(Chris): the little test certs are purged as created — serials 1–7
are all on the revoked list; the serial counter never resets.

Supersedes `keymint-spec-v1.md` (kept alongside, banner-marked
superseded). The name changed during the
2026-10-14 evening session: credmint.ai was taken, keymint.ai was the
working pick, then Chris settled the mint-naming question — a mint is
named for what comes *out* of it, and this one spits out certificates /
credentials, not keys — and bought **certmint.ai** instead.

## Domain — DONE, no longer blocked

- certmint.ai registered at Porkbun by Chris in his own browser
  (Porkbun's API refuses registrations over $100, and .ai's 2-year
  minimum makes every .ai registration $165.40, so .ai names are
  website-checkout-only; the API remains good for DNS/settings after).
- Paid from the funded Porkbun balance: $175.00 → $9.60.
- **Expires Oct 15, 2028** (2-year term), WHOIS privacy **on**.
- **Auto-renew OFF**, set via the API and read back as off — same
  posture as knockwire.ai.
- DNS hosting moved to Cloudflare (Free plan, nameservers elinore +
  norman), registration stays at Porkbun.
- Dedicated VM **CERTMINT** provisioned via the Nursery on hyperv
  (<mint-host>, LAN <lan-ip>, host cert signed
  by the house CA) — Chris chose its own VM over co-hosting on
  KNOCKWIRE, so the mint's CA key, when it exists, lives somewhere
  with exactly one job.
- Cloudflare Tunnel "certmint" with apex + www ingress to the VM's
  :18080 hello-world listener ("certmint.ai is listening."). Zone
  activation was the only outstanding step at provision time; a
  one-shot verify is scheduled for 2026-10-14 20:45 HST
  (cron `certmint-zone-verify`).

## What it is

A global agent cert mint: a standalone identity layer that sits *below*
knockwire. Agents (Muse, Codex/Dot, any similarly constructed agent)
arrive with no platform-issued ID, no certified credential, and no
address — verified live for both Hal (Muse) and Dot (Codex) on
2026-10-14. certmint issues the missing identity instead of fighting
the platforms for one.

knockwire demotes to a *relying party*: present a certmint cert plus a
possession proof, and knockwire enrollment shrinks to registry work
(destination, port, streams).

## The certificate

Plain text, newline-separated `key: value` pairs, one Ed25519 signature
over the canonical block above it. Parseable by any agent on any
runtime; no X.509 / OpenSSH machinery needed just to *carry* an
identity.

```
kwid: 1
key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
key-fingerprint: SHA256:...
identity: provider=google email=<verified email> sub=<provider subject>
identity: provider=facebook email=<verified email> sub=<provider subject>
issued: 2026-10-14T19:27:00Z
expires: 2027-01-12T19:27:00Z
serial: 1042
issuer: certmint.ai (exact issuer hostname TBD)
signature: <base64 Ed25519 over everything above>
```

- One `identity:` line per IdP login. Repeated lines are the format —
  accumulation needs no schema change.
- The claim is deliberately minimal (Chris): not "who authenticated"
  but "the bearer of this public key proved ownership of this email
  address via this provider." Each IdP vouches `email_verified` for
  its own account at login time; the line records what was actually
  vouched (relay/hidden addresses, e.g. Apple private relay or GitHub
  noreply, are recorded as-is). Email is the human-readable
  cross-provider join key; the provider `sub` is the durable one.

## Issuance

1. The agent generates its keypair locally. The private key never moves.
2. The human (or the agent's operator) logs in with any major consumer
   IdP — Google, Facebook/Meta, GitHub, Apple, Microsoft; Meta is
   provider #1 only because knockwire's Facebook Login already works.
3. The agent presents: public key + a possession proof (signature over
   a mint-supplied nonce) + the verified login.
4. The mint signs and returns the cert. The mint is a signing
   function, not an account database.

## Service-directed enrollment (added 2026-10-14 evening)

Chris's flow sketch, not yet built:

- A service that needs an agent to have an ID states, in its bot
  instructions, that the agent should send its user to get a cert —
  and **which provider(s) it wants** (Google, Facebook, …).
- The agent reads those instructions, coordinates the trip, and can
  instruct the user through it; the mint's login page offers only the
  providers matching the service's spec.
- After issuance the agent presents the cert to the service. The only
  reason to log in again after that is **billing**.
- Simplest relying-party posture (Chris): accept all certs, start
  relaying, and stick an ad or an error after the user exceeds their
  quota.

## 2FA: require it only where the provider attests it

You cannot uniformly require 2FA, because the evidence is patchy
across providers (checked in-session, 2026-10-14):

- **Microsoft** — yes, properly: the ID token carries `amr`
  (e.g. `["pwd","mfa"]`), and MFA can be demanded up front with
  `acr_values`.
- **Apple** — structural: Sign in with Apple requires the Apple ID to
  have two-factor on, so a completed Apple login *implies* 2FA.
- **Google** — no dependable MFA signal in the consumer ID token.
  Login freshness (`max_age`/`auth_time`) is available but is not the
  same claim.
- **Facebook** — nothing. No claim, no field, no way to ask.

Design consequence: the cert carries the *evidence*, not the
requirement — an `auth:` stamp recording whatever the provider
attested (e.g. `amr=mfa`). Where a provider attests, the mint can
refuse to issue without an MFA method. Where it can't attest, "no
2FA" is unverifiable rather than false. The relying service reads the
stamp and sets its own floor — policy lives with the verifier, as
with revocation below.

## Presentation: the QR, the photo, and the prose layer

The human-facing ceremony Chris settled on, 2026-10-14 evening:

- **The cert is public by nature.** All security lives in the mint's
  signature and in the private key the cert never contains, so the
  cert can sit at a public URL and lose nothing.
- **QR = the cert's URL.** The mint page renders a graphic of the cert
  metadata with a QR code linking to the cert. The agent fetches it,
  verifies the mint's signature, and checks the fingerprint against
  the key it generated at the start.
- **The photo is the envelope, not the proof.** The user takes a
  picture of the graphic/QR and presents the picture to the agent.
  What attests anything is what the QR binds — the cert fingerprint
  (and, in the earlier sketch, a one-time nonce the agent generated
  when it opened the ceremony). The user's camera roll becomes the
  receipt drawer.
- **The graphic is also the anti-swap mechanism:** the agent shows the
  key fingerprint in chat, the mint page renders the same fingerprint
  visually, and the user compares — that stops a cert meant for one
  key landing on another.
- **Disclosure dial:** a public cert at a guessable URL publishes the
  linked emails. Unguessable, hash-addressed URLs (reachable only via
  the handed-over link/QR) plus claim-subset certs keep disclosure
  bearer-controlled in practice.
- **Prose is a rendering, never the protocol.** The signed bytes stay
  the dull canonical key-value block. A human-readable prose version —
  expiration and all, templates AI-authored once — is rendered *from*
  the signed claims, in the reader's language and register. The agent
  never parses the prose; it goes QR → canonical cert → signature.
  Template drift therefore cannot break verification, and a rendering
  bug cannot forge anything.
- **Prose wording must be event language, not capability language.**
  The mint witnessed an event; it cannot promise the future. Template
  shape Chris approved:

  > "This certifies that the holder of the private key corresponding
  > to this public key authenticated as **foo@bar.com** at **Google**,
  > using **two-factor authentication**, on 14 October 2026. This
  > certificate is valid through 12 January 2027."

- The UX point (Chris): normal federated login makes the user a
  bystander; here there is a document with their name on it and *they*
  hand it over — bearer presents, verifier inspects, like a passport
  at a desk. A credential the user can see, photograph, and keep is
  one they can actually reason about.

## Completion notification (the gap Chris spotted, 2026-10-14 late)

V1 has NO push: the mint issued Hal's cert at 08:10:21Z and it sat
waiting; Hal learned of completion only because Chris came back and
said so, then polled the claim endpoint. Three grades of fix:

1. **Polling** (v1, works today): the agent polls
   `GET /v1/sessions/<id>` with backoff inside the session TTL.
   Adequate when the agent runtime can wait in-loop; a chat-turn
   agent cannot block across turns, which is exactly the failure
   Chris observed.
1b. **Long polling** (IMPLEMENTED 2026-10-14 late, Chris: "That's
   the way"): `GET /v1/sessions/<id>?wait=N`, N clamped to 60s
   (under Cloudflare's ~100s proxy read timeout), holds the request
   open and returns the instant the session issues or expires; the
   agent re-asks on a pending reply. Proven live the same evening:
   the client's first held wait returned `issued` and claimed serial
   4 in the same breath. This is the default claim pattern now
   (`cm-client.py await`). The knock (3) remains the answer only
   when the agent isn't waiting at all.
2. **`callback_url` at session open**: for agents that HAVE a public
   endpoint (server-side agents), the mint POSTs a pointer
   ({session_id}) on issuance. Trivial to add; useless for muses,
   which have no address (the Dot-probe finding).
3. **A knockwire knock** (the muse-native answer): the agent's one
   persistent knockwire connection IS its address. The mint sends a
   knock tagged with the session; the frame carries only the
   session id (pointer discipline); the agent wakes and pulls the
   cert (pull = truth). Composition note: identity bootstraps the
   channel that then notifies about identity — the first enrollment
   polls, every later one can knock.

## Accumulation (stateless)

To add a login later: present the existing cert (the mint verifies
its own signature) plus a fresh IdP login. The mint re-issues a
superset cert with a new serial. The agent carries its own dossier;
the mint stores nothing about anyone's linked identities.

## Expiry and revocation

The mint can never observe key compromise or an email changing hands,
so revocation cannot be its job (Chris: "that's policy it would never
know").

- **Short validity is the real revocation** — the window bounds the
  damage; expiry does the work.
- Renewal requires a fresh login, or possession proof + a still-valid
  cert.
- The mint publishes a revoked-serials list for the cases it *does*
  learn about; relying parties check it at their own freshness
  tolerance. Policy lives with the verifier.

## Privacy knob (decide before v1 ships)

A whole-dossier cert shows every linked identity to every verifier.
The same machinery can issue claim-subset certs (present only the
Google line to a service that only needs Google). Cheap to support
from day one, expensive to retrofit.

## Verification (relying party)

1. Check the mint's signature over the canonical block.
2. Check `expires` and the serial against the revoked list (at the
   verifier's freshness tolerance).
3. Challenge the presenter to sign a nonce with the cert's key —
   possession, not just presentation.
4. Read only the `identity:` lines the service's policy requires.

## Relation to the OpenSSH cert design

Not rivals. The text cert is the portable *identity* credential
(pre-knockwire, cross-service). The OpenSSH cert remains what
knockwire's sshd consumes at connection time. A relying-party adapter
maps one to the other (certmint cert + possession → knockwire CA signs
the SSH cert with key-id = the verified identity).

## Refresh endpoint (decided 2026-10-14 late)

Chris: the refresh UX is **"remember me"** — a 30-day sliding window.

- `POST /v1/refresh` with the current cert text + a possession proof
  (signature over a mint-issued challenge nonce, keyed by the cert's
  serial).
- The mint verifies: its own signature on the presented cert, cert
  still unexpired, serial not on the revoked list, possession
  signature valid against the cert's key.
- On success it issues a new cert: identity lines copied **verbatim**
  (refresh never adds claims and never restamps authentication
  evidence — adding an identity always requires a fresh human login),
  new `issued`/`expires` (now + 30 days), new serial.
- Lapse = the "remember me" has run out: refresh refuses, and the
  only path back is a fresh human login session.
- Format consequence: the cert needs a field for the last human
  authentication distinct from `issued:` (which refresh moves) — an
  `authenticated:` line, so a verifier can see the age of the human
  attestation itself and set its own floor.
- Proposed (Hal, not yet decided): an absolute cap from the last
  human login (e.g. 12 months) after which refresh stops working
  even for an active holder, forcing periodic human re-attestation —
  the way banks bound a remembered device.

## Open decisions for Chris

1. ~~Validity window~~ DECIDED 2026-10-14 late: 30-day sliding
   window via the refresh endpoint ("remember me" UX) — see Refresh
   section above. Still open: the absolute cap from last human
   login (proposed 12 months).
2. Claim-subset certs in v1, or whole-dossier only?
3. First IdP set: Google + Facebook only, or add GitHub/Apple at
   launch?
4. Anchor granularity (carried over from the Dot brief): one cert per
   verified identity, or per (identity, agent) when one human runs
   several agents?
5. Public cert URL addressing: hash-addressed/unguessable by default?
   (Evening lean: yes — see the disclosure dial above.)
6. Does the QR bind a one-time agent-generated nonce in addition to
   the cert URL, or is fingerprint-matching alone sufficient?
