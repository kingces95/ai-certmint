#!/usr/bin/env python3
"""certmint agent client — stdlib + openssl CLI only.

Usage:
  cm-client.py genkey            # one-time keypair in ~/.certmint/
  cm-client.py open              # open a minting session, print the user link
  cm-client.py claim             # poll the session; on issuance save + verify cert
  cm-client.py refresh           # refresh the held cert (possession proof)
  cm-client.py verify [file]     # verify a cert's mint signature + fingerprint
  cm-client.py show              # print the held cert
  cm-client.py guid-new          # birth a GUID, authorized by the held identity cert
  cm-client.py guid-renew [cert] [key]
                                 # mint a peer of a held guid cert (same key)
  cm-client.py guid-show         # print the GUID and its peer certs
"""
import base64, hashlib, json, os, struct, subprocess, sys, time, urllib.parse, urllib.request

BASE = 'https://certmint.ai'
DIR = os.path.expanduser('~/.certmint')
KEY_PEM = os.path.join(DIR, 'id_ed25519.pem')
SESSION_FILE = os.path.join(DIR, 'session.json')
CERT_FILE = os.path.join(DIR, 'cert.txt')
GUID_FILE = os.path.join(DIR, 'guid.txt')
GUID_DIR = os.path.join(DIR, 'guid-certs')
MINT_PUB_FILE = os.path.join(DIR, 'mint-pubkey.json')
SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')

def sh(*args, inp=None):
    r = subprocess.run(args, input=inp, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {r.stderr.decode()[:200]}")
    return r.stdout

def pubkey_of(pem):
    der = sh('openssl', 'pkey', '-in', pem, '-pubout', '-outform', 'DER')
    raw = der[-32:]
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + raw
    line = 'ssh-ed25519 ' + base64.b64encode(blob).decode()
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return line, fp, raw

def my_pubkey():
    return pubkey_of(KEY_PEM)

def sign_with(pem, msg_bytes):
    msg_f = os.path.join(DIR, '.smsg')
    open(msg_f, 'wb').write(msg_bytes)
    sig = sh('openssl', 'pkeyutl', '-sign', '-inkey', pem, '-rawin', '-in', msg_f)
    os.unlink(msg_f)
    return base64.b64encode(sig).decode()

def req(method, path, obj=None):
    # curl, not urllib: this VM's egress proxy 403s urllib's requests.
    args = ['curl', '-s', '-X', method, BASE + path,
            '-H', 'Content-Type: application/json', '-w', '\n%{http_code}']
    if obj is not None:
        args += ['-d', json.dumps(obj)]
    out = sh(*args).decode()
    body, _, code = out.rpartition('\n')
    try:
        parsed = json.loads(body) if body else {}
    except Exception:
        parsed = {}
    return int(code), parsed

def mint_pubkey():
    if os.path.exists(MINT_PUB_FILE):
        return json.load(open(MINT_PUB_FILE))
    _, obj = req('GET', '/pubkey')
    json.dump(obj, open(MINT_PUB_FILE, 'w'))
    return obj

def parse_cert(text):
    lines = text.strip().split('\n')
    sig_line = lines[-1]
    assert sig_line.startswith('signature: '), 'no signature line'
    body = ('\n'.join(lines[:-1]) + '\n').encode()
    fields = {}
    for ln in lines[:-1]:
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            fields.setdefault(k, []).append(v)
    return fields, body, sig_line.split(': ', 1)[1]

def verify_cert(text, check_mine=True):
    fields, body, sig_b64 = parse_cert(text)
    mp = mint_pubkey()
    blob = base64.b64decode(mp['key'].split()[1])
    raw = blob[-32:]
    spki = SPKI_PREFIX + raw
    pub_pem = os.path.join(DIR, 'mint-pub.pem')
    with open(pub_pem, 'wb') as f:
        f.write(b'-----BEGIN PUBLIC KEY-----\n')
        f.write(base64.encodebytes(spki))
        f.write(b'-----END PUBLIC KEY-----\n')
    body_f, sig_f = os.path.join(DIR, '.vbody'), os.path.join(DIR, '.vsig')
    open(body_f, 'wb').write(body)
    open(sig_f, 'wb').write(base64.b64decode(sig_b64))
    r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', pub_pem,
                        '-rawin', '-in', body_f, '-sigfile', sig_f], capture_output=True)
    os.unlink(body_f); os.unlink(sig_f)
    if r.returncode != 0:
        return False, 'mint signature does not verify'
    if check_mine:
        _, my_fp, _ = my_pubkey()
        if fields['key-fingerprint'][0] != my_fp:
            return False, f"fingerprint mismatch: cert {fields['key-fingerprint'][0]} != mine {my_fp}"
    return True, f"verified; serial {fields['serial'][0]}, expires {fields['expires'][0]}"

def cmd_genkey():
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    if os.path.exists(KEY_PEM):
        print('key already exists')
        return
    sh('openssl', 'genpkey', '-algorithm', 'ed25519', '-out', KEY_PEM)
    os.chmod(KEY_PEM, 0o600)
    line, fp, _ = my_pubkey()
    print('key:', line)
    print('fingerprint:', fp)

def cmd_open():
    line, fp, _ = my_pubkey()
    body = {'key': line}
    provider = sys.argv[2] if len(sys.argv) > 2 else ''
    if provider:
        body['provider'] = provider
    code, obj = req('POST', '/v1/sessions', body)
    assert code == 201, f'open failed: {code} {obj}'
    json.dump(obj, open(SESSION_FILE, 'w'))
    print('session:', obj['session_id'])
    print('provider:', obj.get('provider'))
    print('fingerprint:', obj['fingerprint'])
    print('link:', obj['url'])
    print('expires:', obj['expires'])

def cmd_claim():
    s = json.load(open(SESSION_FILE))
    code, obj = req('GET', f"/v1/sessions/{s['session_id']}")
    print('status:', obj.get('status'))
    if obj.get('status') == 'issued':
        cert = obj['cert']
        open(CERT_FILE, 'w').write(cert)
        ok, msg = verify_cert(cert)
        print(msg)
        print('cert saved to', CERT_FILE)

def cmd_await():
    """Long-poll the session: hold ?wait=60 requests until issuance."""
    s = json.load(open(SESSION_FILE))
    deadline = time.time() + 600
    while time.time() < deadline:
        code, obj = req('GET', f"/v1/sessions/{s['session_id']}?wait=60")
        print('wait returned:', obj.get('status'), flush=True)
        if obj.get('status') == 'issued':
            cert = obj['cert']
            open(CERT_FILE, 'w').write(cert)
            ok, msg = verify_cert(cert)
            print('CLAIMED:', msg, flush=True)
            print(cert, flush=True)
            return
        if obj.get('status') == 'expired':
            print('SESSION EXPIRED', flush=True)
            return
    print('AWAIT TIMEOUT', flush=True)

def cmd_refresh():
    cert = open(CERT_FILE).read()
    fields, _, _ = parse_cert(cert)
    serial = fields['serial'][0]
    code, ch = req('GET', f"/v1/refresh/challenge?serial={serial}")
    assert code == 200, f'challenge failed: {code} {ch}'
    msg = ch['signing_string'].encode()
    msg_f = os.path.join(DIR, '.rmsg')
    open(msg_f, 'wb').write(msg)
    sig = sh('openssl', 'pkeyutl', '-sign', '-inkey', KEY_PEM, '-rawin', '-in', msg_f)
    os.unlink(msg_f)
    code, obj = req('POST', '/v1/refresh',
                    {'cert': cert, 'nonce': ch['nonce'],
                     'signature': base64.b64encode(sig).decode()})
    if code != 200:
        print('refresh failed:', code, obj)
        return
    new_cert = obj['cert']
    ok, msg2 = verify_cert(new_cert)
    print('refreshed:', msg2)
    open(CERT_FILE, 'w').write(new_cert)
    print(new_cert)

# ---------- guid certs ----------
def save_guid_cert(cert):
    os.makedirs(GUID_DIR, mode=0o700, exist_ok=True)
    fields, _, _ = parse_cert(cert)
    path = os.path.join(GUID_DIR, f"{fields['serial'][0]}.txt")
    open(path, 'w').write(cert)
    return path

def guid_certs():
    """All held guid certs as (serial:int, path), oldest first."""
    out = []
    if os.path.isdir(GUID_DIR):
        for name in os.listdir(GUID_DIR):
            if name.endswith('.txt'):
                try:
                    out.append((int(name[:-4]), os.path.join(GUID_DIR, name)))
                except ValueError:
                    pass
    return sorted(out)

def my_guid_cert():
    """The newest held guid cert bound to my own key, or None."""
    _, my_fp, _ = my_pubkey()
    best = None
    for serial, path in guid_certs():
        fields, _, _ = parse_cert(open(path).read())
        if fields['key-fingerprint'][0] == my_fp:
            best = (serial, path)
    return best

def guid_challenge(serial):
    code, ch = req('GET', f'/v1/guids/challenge?serial={serial}')
    assert code == 200, f'guid challenge failed: {code} {ch}'
    return ch

def cmd_guid_new():
    cert = open(CERT_FILE).read()
    fields, _, _ = parse_cert(cert)
    ch = guid_challenge(fields['serial'][0])
    sig = sign_with(KEY_PEM, ch['signing_string'].encode())
    code, obj = req('POST', '/v1/guids',
                    {'cert': cert, 'nonce': ch['nonce'], 'signature': sig})
    assert code == 201, f'guid-new failed: {code} {obj}'
    # The raw GUID arrives exactly once, in this response. Save it like
    # a key: it is the address every webhook will carry.
    with open(GUID_FILE, 'w') as f:
        f.write(obj['guid'] + '\n')
    os.chmod(GUID_FILE, 0o600)
    path = save_guid_cert(obj['cert'])
    ok, msg = verify_cert(obj['cert'])
    print('guid:', obj['guid'])
    print('cert:', msg, '->', path)
    print('guid saved to', GUID_FILE)

def cmd_guid_renew():
    cert_path = sys.argv[2] if len(sys.argv) > 2 else None
    key_pem = sys.argv[3] if len(sys.argv) > 3 else KEY_PEM
    if cert_path is None:
        found = my_guid_cert()
        assert found, 'no held guid cert for my key'
        cert_path = found[1]
    cert = open(cert_path).read()
    fields, _, _ = parse_cert(cert)
    ch = guid_challenge(fields['serial'][0])
    sig = sign_with(key_pem, ch['signing_string'].encode())
    code, obj = req('POST', '/v1/guids/renew',
                    {'cert': cert, 'nonce': ch['nonce'], 'signature': sig})
    assert code == 201, f'guid-renew failed: {code} {obj}'
    path = save_guid_cert(obj['cert'])
    _, want_fp, _ = pubkey_of(key_pem)
    ok, msg = verify_cert(obj['cert'], check_mine=False)
    assert ok and parse_cert(obj['cert'])[0]['key-fingerprint'][0] == want_fp, msg
    print('renewed peer:', msg, '->', path)

def cmd_guid_show():
    if os.path.exists(GUID_FILE):
        print('guid:', open(GUID_FILE).read().strip())
    for serial, path in guid_certs():
        fields, _, _ = parse_cert(open(path).read())
        print(f"serial {serial}: fp {fields['key-fingerprint'][0]} "
              f"hash {fields['guid-hash'][0]} expires {fields['expires'][0]}")

def cmd_verify():
    path = sys.argv[2] if len(sys.argv) > 2 else CERT_FILE
    ok, msg = verify_cert(open(path).read(), check_mine=False)
    print(('OK: ' if ok else 'FAIL: ') + msg)

def cmd_show():
    print(open(CERT_FILE).read())

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'show'
    {'genkey': cmd_genkey, 'open': cmd_open, 'claim': cmd_claim,
     'await': cmd_await,
     'refresh': cmd_refresh, 'verify': cmd_verify, 'show': cmd_show,
     'guid-new': cmd_guid_new, 'guid-renew': cmd_guid_renew,
     'guid-show': cmd_guid_show}[cmd]()
