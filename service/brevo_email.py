import json
import os
from email.utils import parseaddr
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.core.mail.backends.base import BaseEmailBackend


class EmailBackend(BaseEmailBackend):
    def send_messages(self, email_messages):
        if not email_messages:
            return 0
        api_key = os.environ.get('VIPERNET_BREVO_API_KEY', '')
        if not api_key:
            if self.fail_silently:
                return 0
            raise RuntimeError('VIPERNET_BREVO_API_KEY is required')
        sent = 0
        for message in email_messages:
            sender_name, sender_email = parseaddr(message.from_email)
            payload = {
                'sender': {'name': sender_name or 'ViperNet', 'email': sender_email},
                'to': [{'email': address} for address in message.to],
                'subject': message.subject,
                'textContent': message.body,
            }
            request = Request(
                'https://api.brevo.com/v3/smtp/email',
                data=json.dumps(payload).encode(),
                headers={'accept': 'application/json', 'api-key': api_key, 'content-type': 'application/json'},
                method='POST',
            )
            try:
                with urlopen(request, timeout=15) as response:
                    if response.status not in (200, 201, 202):
                        raise RuntimeError(f'Email provider returned status {response.status}')
                sent += 1
            except (HTTPError, URLError, RuntimeError):
                if not self.fail_silently:
                    raise
        return sent
