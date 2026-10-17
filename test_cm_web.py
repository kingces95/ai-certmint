import importlib.util
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class GoogleIdTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.tmp.name)
        key = Ed25519PrivateKey.generate()
        (root / 'mint.pem').write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        cls.env = mock.patch.dict(os.environ, {
            'CERTMINT_MINT_KEY': str(root / 'mint.pem'),
            'CERTMINT_STATE': str(root / 'state.json'),
            'CERTMINT_META_CONFIG': str(root / 'meta.env'),
            'CERTMINT_SLACK_CONFIG': str(root / 'slack.env'),
            'CERTMINT_GOOGLE_CONFIG': str(root / 'google.env'),
        })
        cls.env.start()
        spec = importlib.util.spec_from_file_location(
            'cm_web', pathlib.Path(__file__).with_name('cm-web.py'))
        cls.cm_web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cm_web)

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.tmp.cleanup()

    def verify(self, claims):
        class FakeJwkClient:
            def __init__(self, url):
                self.url = url

            def get_signing_key_from_jwt(self, token):
                return types.SimpleNamespace(key='public-key')

        fake_jwt = types.SimpleNamespace(
            PyJWKClient=FakeJwkClient,
            decode=mock.Mock(return_value=claims),
        )
        self.cm_web.GOOGLE_JWK_CLIENT = None
        with mock.patch.dict(sys.modules, {'jwt': fake_jwt}):
            result = self.cm_web.google_verify_id_token(
                'token', 'client-id', 'expected-nonce')
        fake_jwt.decode.assert_called_once_with(
            'token', 'public-key', algorithms=['RS256'], audience='client-id')
        return result

    def base_claims(self):
        return {
            'iss': 'https://accounts.google.com',
            'sub': 'google-subject',
            'aud': 'client-id',
            'nonce': 'expected-nonce',
            'email': 'person@example.com',
            'email_verified': True,
        }

    def test_accepts_verified_google_identity(self):
        claims = self.base_claims()
        self.assertEqual(self.verify(claims), claims)

    def test_accepts_legacy_google_issuer(self):
        claims = self.base_claims()
        claims['iss'] = 'accounts.google.com'
        self.assertEqual(self.verify(claims), claims)

    def test_rejects_wrong_issuer(self):
        claims = self.base_claims()
        claims['iss'] = 'https://example.com'
        with self.assertRaisesRegex(ValueError, 'unexpected issuer'):
            self.verify(claims)

    def test_rejects_nonce_mismatch(self):
        claims = self.base_claims()
        claims['nonce'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'nonce mismatch'):
            self.verify(claims)

    def test_rejects_unverified_or_missing_email(self):
        for value in (False, None):
            with self.subTest(email_verified=value):
                claims = self.base_claims()
                claims['email_verified'] = value
                with self.assertRaisesRegex(ValueError, 'email is not verified'):
                    self.verify(claims)

    def test_rejects_missing_subject(self):
        claims = self.base_claims()
        claims['sub'] = ''
        with self.assertRaisesRegex(ValueError, 'missing subject'):
            self.verify(claims)


if __name__ == '__main__':
    unittest.main()
