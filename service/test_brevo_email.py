import os
from unittest import TestCase, mock

from django.core.mail import EmailMessage

from service.brevo_email import EmailBackend


class BrevoEmailBackendTests(TestCase):
    @mock.patch.dict(os.environ, {'VIPERNET_BREVO_API_KEY': 'synthetic-test-key'})
    @mock.patch('service.brevo_email.urlopen')
    def test_sends_plain_text_without_exposing_key_in_body(self, open_url):
        response = mock.MagicMock(status=201)
        open_url.return_value.__enter__.return_value = response
        sent = EmailBackend().send_messages([
            EmailMessage('Verify', 'Synthetic body', 'ViperNet <sender@example.com>', ['member@example.com']),
        ])
        self.assertEqual(sent, 1)
        request = open_url.call_args.args[0]
        self.assertNotIn(b'synthetic-test-key', request.data)
        self.assertEqual(request.headers['Api-key'], 'synthetic-test-key')

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_requires_provider_key(self):
        with self.assertRaises(RuntimeError):
            EmailBackend().send_messages([
                EmailMessage('Verify', 'Synthetic body', 'sender@example.com', ['member@example.com']),
            ])
