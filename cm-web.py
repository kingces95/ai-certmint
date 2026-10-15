import http.server, datetime, os, secrets, json, base64, hashlib, struct, threading, time
import urllib.parse, urllib.request
from http.cookies import SimpleCookie
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

CONFIG_PATH = '/etc/certmint/meta.env'
SLACK_CONFIG_PATH = '/etc/certmint/slack.env'
MINT_KEY_PATH = '/etc/certmint/mint-ed25519.pem'
STATE_PATH = '/var/lib/certmint/state.json'
GRAPH_VERSION = 'v23.0'
REDIRECT_URI = 'https://certmint.ai/auth/meta/callback'
SLACK_REDIRECT_URI = 'https://certmint.ai/auth/slack/callback'
# The pinned Slack workspace (team id) lives in the deployment's
# slack.env as SLACK_TEAM_ID — site values are config, never literals.
# When set, it is sent on every authorize request and enforced on the
# returned id_token claims; when unset, any workspace may sign in.
SLACK_ISSUER = 'https://slack.com'
SLACK_JWKS_URL = 'https://slack.com/openid/connect/keys'
ISSUER = 'certmint.ai'
CERT_TTL_DAYS = 30
AUTH_CAP_DAYS = 365
SESSION_TTL_SECS = 600
CHALLENGE_TTL_SECS = 300

def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)

def ts(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def parse_ts(s):
    return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)

def load_env_file(path):
    cfg = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg

def load_config():
    return load_env_file(CONFIG_PATH)

def load_slack_config():
    return load_env_file(SLACK_CONFIG_PATH)

# ---------- slack oidc ----------
SLACK_JWK_CLIENT = None

def slack_verify_id_token(id_token, client_id, nonce, pinned_team=''):
    """Verify a Slack Sign-in id_token (RS256, Slack JWKS) and return its
    claims. Raises on any failure: bad signature, wrong issuer/audience,
    expired token, nonce mismatch, or — when the deployment pins a
    workspace — a team other than the pinned one. Signing keys are
    cached by PyJWKClient and refreshed on unknown kid."""
    import jwt
    global SLACK_JWK_CLIENT
    if SLACK_JWK_CLIENT is None:
        SLACK_JWK_CLIENT = jwt.PyJWKClient(SLACK_JWKS_URL)
    signing_key = SLACK_JWK_CLIENT.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(id_token, signing_key.key, algorithms=['RS256'],
                        audience=client_id, issuer=SLACK_ISSUER)
    if claims.get('nonce') != nonce:
        raise ValueError('nonce mismatch')
    if pinned_team and claims.get('https://slack.com/team_id') != pinned_team:
        raise ValueError('unexpected team')
    return claims

# ---------- keys ----------
def openssh_blob(raw_pub32):
    return struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + raw_pub32

def fingerprint_of_blob(blob):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')

def parse_openssh_key(line):
    """'ssh-ed25519 <b64>' -> (blob, raw32) or raise ValueError"""
    parts = line.strip().split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519':
        raise ValueError('not an ssh-ed25519 key')
    blob = base64.b64decode(parts[1])
    ln, = struct.unpack('>I', blob[:4])
    if blob[4:4+ln] != b'ssh-ed25519':
        raise ValueError('bad blob')
    off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off+4])
    raw = blob[off+4:off+4+ln2]
    if len(raw) != 32:
        raise ValueError('bad key length')
    return blob, raw

def load_mint_key():
    with open(MINT_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

MINT_KEY = load_mint_key()
MINT_RAW = MINT_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
MINT_BLOB = openssh_blob(MINT_RAW)
MINT_KEY_LINE = 'ssh-ed25519 ' + base64.b64encode(MINT_BLOB).decode()
MINT_FP = fingerprint_of_blob(MINT_BLOB)

# ---------- state ----------
LOCK = threading.Lock()
def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {'serial_counter': 0, 'sessions': {}, 'challenges': {}, 'revoked': []}

def save_state(st):
    tmp = STATE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, STATE_PATH)

SESSIONS_WEB = {}  # web login sessions: token -> {'id','name'} (Meta) or {'provider':'slack','team','sub','name','email'}

# ---------- certs ----------
def issue_cert(st, key_line, name, identity_lines, authenticated_dt):
    blob, raw = parse_openssh_key(key_line)
    st['serial_counter'] += 1
    serial = st['serial_counter']
    issued = now_utc()
    lines = ['kwid: 1',
             f'key: {key_line}']
    lines.append(f'key-fingerprint: {fingerprint_of_blob(blob)}')
    if name:
        lines.append(f'name: {name}')
    lines.extend(identity_lines)
    lines.append(f'authenticated: {ts(authenticated_dt)}')
    lines.append(f'issued: {ts(issued)}')
    lines.append(f'expires: {ts(issued + datetime.timedelta(days=CERT_TTL_DAYS))}')
    lines.append(f'serial: {serial}')
    lines.append(f'issuer: {ISSUER}')
    body = ('\n'.join(lines) + '\n').encode()
    sig = base64.b64encode(MINT_KEY.sign(body)).decode()
    return body.decode() + f'signature: {sig}\n', serial

def parse_cert(text):
    lines = text.strip().split('\n')
    sig_line = lines[-1]
    if not sig_line.startswith('signature: '):
        raise ValueError('no signature line')
    body = ('\n'.join(lines[:-1]) + '\n').encode()
    fields = {}
    identities = []
    for ln in lines[:-1]:
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            if k == 'identity':
                identities.append(v)
            else:
                fields[k] = v
    return fields, identities, body, sig_line.split(': ', 1)[1]

def verify_mint_sig(body, sig_b64):
    try:
        MINT_KEY.public_key().verify(base64.b64decode(sig_b64), body)
        return True
    except Exception:
        return False

def human_date(iso):
    return parse_ts(iso).strftime('%d %B %Y')

CSS = "body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:40rem;padding:0 1rem}h1{font-weight:600}p{color:#555}.btn{display:inline-block;background:#0081fb;color:#fff;padding:.7rem 1.4rem;border-radius:.5rem;text-decoration:none;font-weight:600}code{background:#f0f0f0;padding:.15rem .4rem;border-radius:.3rem}pre{background:#f7f7f7;padding:1rem;border-radius:.5rem;overflow-x:auto;font-size:.8rem}.fp{font-size:1.05rem;word-break:break-all}"

def page(title, inner):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
{inner}
</body>
</html>
""".encode()

class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        t = ts(now_utc())
        src = self.headers.get('CF-Connecting-IP', self.client_address[0])
        ray = self.headers.get('CF-Ray', '-')
        host = self.headers.get('Host', '-')
        with open('/var/log/cm-test.log', 'a') as f:
            f.write(f'{t} {self.command} {self.path} host={host} from {src} ray={ray}\n')
        return t

    def _send(self, code, body, ctype='text/html; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), 'application/json')

    def _redirect(self, location, extra=None):
        self.send_response(302)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _cookies(self):
        c = SimpleCookie()
        raw = self.headers.get('Cookie')
        if raw:
            c.load(raw)
        return {k: morsel.value for k, morsel in c.items()}

    def _session_user(self):
        tok = self._cookies().get('cm_session')
        return SESSIONS_WEB.get(tok) if tok else None

    def _body_json(self):
        ln = int(self.headers.get('Content-Length') or 0)
        if ln <= 0 or ln > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(ln).decode())
        except Exception:
            return {}

    # ---------- mint: sessions ----------
    def _create_session(self):
        req = self._body_json()
        key_line = (req.get('key') or '').strip()
        provider = (req.get('provider') or '').strip()
        if provider and provider not in ('facebook', 'slack'):
            self._json(400, {'error': 'provider must be facebook or slack'})
            return
        try:
            blob, raw = parse_openssh_key(key_line)
        except Exception:
            self._json(400, {'error': 'key must be an ssh-ed25519 public key line'})
            return
        sid = secrets.token_urlsafe(24)
        with LOCK:
            st = load_state()
            sess = {
                'key': key_line,
                'fingerprint': fingerprint_of_blob(blob),
                'status': 'pending',
                'created': ts(now_utc()),
                'expires': ts(now_utc() + datetime.timedelta(seconds=SESSION_TTL_SECS)),
            }
            if provider:
                sess['provider'] = provider
            st['sessions'][sid] = sess
            save_state(st)
        self._json(201, {'session_id': sid,
                         'url': f'https://certmint.ai/s/{sid}',
                         'provider': provider or None,
                         'fingerprint': fingerprint_of_blob(blob),
                         'expires': ts(now_utc() + datetime.timedelta(seconds=SESSION_TTL_SECS))})

    def _get_session(self, sid, qs=None):
        # Long poll: ?wait=N (clamped 0..60) holds the request open until
        # the session issues, expires, or the wait runs out — the agent
        # re-asks on a pending reply. 60s stays under Cloudflare's ~100s
        # proxy read timeout.
        wait = 0
        if qs:
            try:
                wait = max(0, min(60, int((qs.get('wait') or ['0'])[0])))
            except ValueError:
                wait = 0
        deadline = time.time() + wait
        while True:
            with LOCK:
                st = load_state()
                s = st['sessions'].get(sid)
            if not s:
                self._json(404, {'error': 'no such session'})
                return
            if s['status'] == 'issued':
                self._json(200, {'status': 'issued', 'serial': s.get('serial'), 'cert': s.get('cert')})
                return
            if s['status'] == 'pending' and parse_ts(s['expires']) < now_utc():
                self._json(200, {'status': 'expired'})
                return
            if time.time() >= deadline:
                self._json(200, {'status': 'pending'})
                return
            time.sleep(0.25)

    def _session_page(self, sid):
        with LOCK:
            st = load_state()
            s = st['sessions'].get(sid)
        if not s:
            self._send(404, page('certmint', '<h1>certmint</h1><p>No such minting session.</p>'))
            return
        if s['status'] == 'issued':
            # The agent reports the result in chat; this page is only a
            # landing pad. It shows nothing about the cert and tries to
            # close itself (browsers only allow that for script-opened
            # windows, so the text covers the rest).
            inner = """<h1>certmint</h1>
<p>Done — you can close this page.</p>
<script>window.close()</script>"""
            self._send(200, page('certmint', inner))
            return
        if parse_ts(s['expires']) < now_utc():
            self._send(200, page('certmint', '<h1>certmint</h1><p>This minting session has expired. Ask your agent for a fresh link.</p>'))
            return
        # Provider preselected by the agent: skip the chooser page and go
        # straight to the provider's own login page.
        provider = s.get('provider')
        if provider:
            auth_path = {'facebook': '/auth/meta', 'slack': '/auth/slack'}[provider]
            self._redirect(f'{auth_path}?s={sid}')
            return
        slack_btn = ''
        if load_slack_config().get('SLACK_CLIENT_ID'):
            slack_btn = f'\n<p><a class="btn" href="/auth/slack?s={sid}">Continue with Slack</a></p>'
        inner = f"""<h1>certmint</h1>
<p>Your agent asked to certify this public key:</p>
<p><code class="fp">{s['fingerprint']}</code></p>
<p>Sign in to certify that this key belongs to you.</p>
<p><a class="btn" href="/auth/meta?s={sid}">Continue with Meta</a></p>{slack_btn}"""
        self._send(200, page('certmint', inner))

    # ---------- mint: refresh ----------
    def _refresh_challenge(self, qs):
        serial = (qs.get('serial') or [''])[0]
        if not serial.isdigit():
            self._json(400, {'error': 'serial required'})
            return
        nonce = secrets.token_urlsafe(32)
        with LOCK:
            st = load_state()
            st['challenges'][nonce] = {'serial': int(serial),
                                       'expires': ts(now_utc() + datetime.timedelta(seconds=CHALLENGE_TTL_SECS))}
            save_state(st)
        self._json(200, {'nonce': nonce, 'signing_string': f'certmint-refresh-v1\n{serial}\n{nonce}'})

    def _refresh(self):
        req = self._body_json()
        cert_text = req.get('cert') or ''
        nonce = req.get('nonce') or ''
        sig_b64 = req.get('signature') or ''
        try:
            fields, identities, body, mint_sig = parse_cert(cert_text)
        except Exception:
            self._json(400, {'error': 'unparseable cert'})
            return
        if not verify_mint_sig(body, mint_sig):
            self._json(400, {'error': 'mint signature does not verify'})
            return
        serial = fields.get('serial', '')
        if not serial.isdigit():
            self._json(400, {'error': 'bad serial'})
            return
        with LOCK:
            st = load_state()
            ch = st['challenges'].get(nonce)
            if ch:
                del st['challenges'][nonce]
                save_state(st)
        if not ch or ch.get('serial') != int(serial) or parse_ts(ch['expires']) < now_utc():
            self._json(400, {'error': 'unknown or expired challenge'})
            return
        if int(serial) in st.get('revoked', []):
            self._json(403, {'error': 'serial revoked'})
            return
        if parse_ts(fields['expires']) < now_utc():
            self._json(403, {'error': 'cert expired — a fresh login is required'})
            return
        if parse_ts(fields['authenticated']) + datetime.timedelta(days=AUTH_CAP_DAYS) < now_utc():
            self._json(403, {'error': 'authentication is over 12 months old — a fresh login is required'})
            return
        try:
            blob, raw = parse_openssh_key(fields['key'])
            Ed25519PublicKey.from_public_bytes(raw).verify(
                base64.b64decode(sig_b64),
                f'certmint-refresh-v1\n{serial}\n{nonce}'.encode())
        except Exception:
            self._json(403, {'error': 'possession proof does not verify'})
            return
        identity_lines = [f'identity: {v}' for v in identities]
        with LOCK:
            st = load_state()
            new_cert, new_serial = issue_cert(st, fields['key'], fields.get('name'),
                                              identity_lines, parse_ts(fields['authenticated']))
            save_state(st)
        self._json(200, {'cert': new_cert, 'serial': new_serial})

    # ---------- routing ----------
    def do_GET(self):
        self._log()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        cfg = load_config()
        app_id = cfg.get('META_APP_ID', '')
        app_secret = cfg.get('META_APP_SECRET', '')

        if path == '/pubkey':
            self._json(200, {'key': MINT_KEY_LINE, 'fingerprint': MINT_FP, 'issuer': ISSUER})
            return
        if path == '/revoked':
            with LOCK:
                st = load_state()
            body = ''.join(f'{n}\n' for n in st.get('revoked', [])).encode()
            self._send(200, body, 'text/plain; charset=utf-8')
            return
        if path.startswith('/v1/sessions/'):
            self._get_session(path.split('/')[3], qs)
            return
        if path.startswith('/s/'):
            self._session_page(path.split('/')[2])
            return
        if path == '/v1/refresh/challenge':
            self._refresh_challenge(qs)
            return

        if path in ('/', '/index.html'):
            user = self._session_user()
            if user:
                name_line = f"<p>name: <code>{user.get('name') or '(unknown)'}</code></p>" if user.get('name') else ''
                if user.get('provider') == 'slack':
                    email_line = f"<p>email: <code>{user['email']}</code></p>" if user.get('email') else ''
                    inner = f"""<h1>certmint</h1>
<p>You are signed in with Slack.</p>
<p>Team: <code>{user.get('team', '')}</code></p>
<p>Your Slack ID: <code>{user.get('sub', '')}</code></p>
{name_line}
{email_line}
<p><a href="/logout">Sign out</a></p>"""
                else:
                    inner = f"""<h1>certmint</h1>
<p>You are signed in with Meta.</p>
<p>Your Meta ID: <code>{user['id']}</code></p>
{name_line}
<p><a href="/logout">Sign out</a></p>"""
                self._send(200, page('certmint', inner))
            else:
                buttons = []
                if app_id:
                    buttons.append('<p><a class="btn" href="/auth/meta">Continue with Meta</a></p>')
                if load_slack_config().get('SLACK_CLIENT_ID'):
                    buttons.append('<p><a class="btn" href="/auth/slack">Continue with Slack</a></p>')
                if buttons:
                    inner = '<h1>certmint</h1>\n<p>Sign in to continue.</p>\n' + '\n'.join(buttons)
                else:
                    inner = """<h1>certmint</h1>
<p>No login provider is configured yet.</p>"""
                self._send(200, page('certmint', inner))
            return

        if path == '/auth/meta':
            if not app_id:
                self._send(503, page('certmint', '<h1>certmint</h1><p>Meta login is not configured yet.</p>'))
                return
            state = secrets.token_urlsafe(24)
            mint_sid = (qs.get('s') or [''])[0]
            if mint_sid:
                with LOCK:
                    st = load_state()
                    s = st['sessions'].get(mint_sid)
                    if s and s['status'] == 'pending':
                        s['oauth_state'] = state
                        save_state(st)
            params = urllib.parse.urlencode({
                'client_id': app_id,
                'redirect_uri': REDIRECT_URI,
                'state': state,
                'response_type': 'code',
                'scope': 'public_profile,email',
            })
            cookie = f'cm_state={state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600'
            self._redirect(f'https://www.facebook.com/{GRAPH_VERSION}/dialog/oauth?{params}',
                           [('Set-Cookie', cookie)])
            return

        if path == '/auth/meta/callback':
            if 'error' in qs:
                self._send(400, page('certmint', f"<h1>certmint</h1><p>Meta login was declined or failed: {qs.get('error_description', qs['error'])[0]}</p><p><a href=\"/\">Back</a></p>"))
                return
            code = (qs.get('code') or [''])[0]
            state = (qs.get('state') or [''])[0]
            if not code or not state or state != self._cookies().get('cm_state'):
                self._send(400, page('certmint', '<h1>certmint</h1><p>Invalid login callback (state check failed).</p><p><a href="/">Back</a></p>'))
                return
            try:
                token_params = urllib.parse.urlencode({
                    'client_id': app_id,
                    'client_secret': app_secret,
                    'redirect_uri': REDIRECT_URI,
                    'code': code,
                })
                with urllib.request.urlopen(f'https://graph.facebook.com/{GRAPH_VERSION}/oauth/access_token?{token_params}', timeout=15) as r:
                    token = json.load(r)['access_token']
                me_params = urllib.parse.urlencode({'fields': 'id,name,email', 'access_token': token})
                with urllib.request.urlopen(f'https://graph.facebook.com/{GRAPH_VERSION}/me?{me_params}', timeout=15) as r:
                    me = json.load(r)
            except Exception as e:
                self._send(502, page('certmint', f'<h1>certmint</h1><p>Could not complete Meta login: {type(e).__name__}</p><p><a href="/">Back</a></p>'))
                return
            tok = secrets.token_urlsafe(32)
            SESSIONS_WEB[tok] = {'id': me['id'], 'name': me.get('name')}
            cookie = f'cm_session={tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400'
            clear_state = 'cm_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            # mint issuance, if this callback belongs to a minting session
            target = '/'
            with LOCK:
                st = load_state()
                for sid, s in st['sessions'].items():
                    if s.get('oauth_state') == state and s['status'] == 'pending':
                        identity = f"identity: provider=facebook sub={me['id']}"
                        if me.get('email'):
                            identity = f"identity: provider=facebook email={me['email']} sub={me['id']}"
                        cert, serial = issue_cert(st, s['key'], me.get('name'), [identity], now_utc())
                        s['status'] = 'issued'
                        s['cert'] = cert
                        s['serial'] = serial
                        s.pop('oauth_state', None)
                        save_state(st)
                        target = f'/s/{sid}'
                        break
            self._redirect(target, [('Set-Cookie', cookie), ('Set-Cookie', clear_state)])
            return

        if path == '/auth/slack':
            scfg = load_slack_config()
            slack_client_id = scfg.get('SLACK_CLIENT_ID', '')
            if not slack_client_id:
                self._send(503, page('certmint', '<h1>certmint</h1><p>Slack login is not configured yet.</p>'))
                return
            state = secrets.token_urlsafe(24)
            nonce = secrets.token_urlsafe(24)
            mint_sid = (qs.get('s') or [''])[0]
            if mint_sid:
                with LOCK:
                    st = load_state()
                    s = st['sessions'].get(mint_sid)
                    if s and s['status'] == 'pending':
                        s['oauth_state'] = state
                        s['oauth_nonce'] = nonce
                        save_state(st)
            params = urllib.parse.urlencode({
                'client_id': slack_client_id,
                'scope': 'openid profile email',
                'response_type': 'code',
                'redirect_uri': SLACK_REDIRECT_URI,
                'state': state,
                'nonce': nonce,
                **({'team': scfg['SLACK_TEAM_ID']} if scfg.get('SLACK_TEAM_ID') else {}),
            })
            extra = [('Set-Cookie', f'cm_state={state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600'),
                     ('Set-Cookie', f'cm_nonce={nonce}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600')]
            self._redirect(f'https://slack.com/openid/connect/authorize?{params}', extra)
            return

        if path == '/auth/slack/callback':
            scfg = load_slack_config()
            slack_client_id = scfg.get('SLACK_CLIENT_ID', '')
            slack_client_secret = scfg.get('SLACK_CLIENT_SECRET', '')
            if 'error' in qs:
                self._send(400, page('certmint', f"<h1>certmint</h1><p>Slack login was declined or failed: {qs['error'][0]}</p><p><a href=\"/\">Back</a></p>"))
                return
            code = (qs.get('code') or [''])[0]
            state = (qs.get('state') or [''])[0]
            nonce_cookie = self._cookies().get('cm_nonce', '')
            if not code or not state or state != self._cookies().get('cm_state'):
                self._send(400, page('certmint', '<h1>certmint</h1><p>Invalid login callback (state check failed).</p><p><a href="/">Back</a></p>'))
                return
            try:
                token_body = urllib.parse.urlencode({
                    'client_id': slack_client_id,
                    'client_secret': slack_client_secret,
                    'code': code,
                    'redirect_uri': SLACK_REDIRECT_URI,
                }).encode()
                treq = urllib.request.Request('https://slack.com/api/openid.connect.token',
                                              data=token_body,
                                              headers={'Content-Type': 'application/x-www-form-urlencoded'})
                with urllib.request.urlopen(treq, timeout=15) as r:
                    tok_resp = json.load(r)
                if not tok_resp.get('ok'):
                    raise ValueError(f"slack token error: {tok_resp.get('error')}")
                claims = slack_verify_id_token(tok_resp['id_token'], slack_client_id, nonce_cookie,
                                               scfg.get('SLACK_TEAM_ID', ''))
            except Exception as e:
                self._send(502, page('certmint', f'<h1>certmint</h1><p>Could not complete Slack login: {type(e).__name__}</p><p><a href="/">Back</a></p>'))
                return
            sub = claims.get('sub', '')
            team = claims.get('https://slack.com/team_id', '')
            name = claims.get('name')
            email = claims.get('email')
            tok = secrets.token_urlsafe(32)
            SESSIONS_WEB[tok] = {'provider': 'slack', 'team': team, 'sub': sub, 'name': name, 'email': email}
            cookie = f'cm_session={tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400'
            clear_state = 'cm_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            clear_nonce = 'cm_nonce=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            # mint issuance, if this callback belongs to a minting session
            target = '/'
            with LOCK:
                st = load_state()
                for sid, s in st['sessions'].items():
                    if s.get('oauth_state') == state and s['status'] == 'pending':
                        identity = f'identity: provider=slack team={team} sub={sub}'
                        if email:
                            identity = f'identity: provider=slack team={team} email={email} sub={sub}'
                        cert, serial = issue_cert(st, s['key'], name, [identity], now_utc())
                        s['status'] = 'issued'
                        s['cert'] = cert
                        s['serial'] = serial
                        s.pop('oauth_state', None)
                        s.pop('oauth_nonce', None)
                        save_state(st)
                        target = f'/s/{sid}'
                        break
            self._redirect(target, [('Set-Cookie', cookie), ('Set-Cookie', clear_state), ('Set-Cookie', clear_nonce)])
            return

        if path == '/logout':
            tok = self._cookies().get('cm_session')
            if tok:
                SESSIONS_WEB.pop(tok, None)
            clear = 'cm_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            self._redirect('/', [('Set-Cookie', clear)])
            return

        self._send(404, b'not found\n', 'text/plain')

    def do_POST(self):
        self._log()
        path = urllib.parse.urlparse(self.path).path
        if path == '/v1/sessions':
            self._create_session()
            return
        if path == '/v1/refresh':
            self._refresh()
            return
        self._send(404, b'not found\n', 'text/plain')

    do_HEAD = do_GET

http.server.ThreadingHTTPServer(('127.0.0.1', 18080), H).serve_forever()
