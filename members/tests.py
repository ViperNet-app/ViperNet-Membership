import json
from urllib.parse import parse_qs
from datetime import timedelta
from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from .models import Device, Grant, Vault, Revision, MailAction
from .domain import digest, save_revision, unseal, Conflict

@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class MembershipTests(TestCase):
    def setUp(self):
        self.a = get_user_model().objects.create_user('one@example.com', 'one@example.com', 'Synthetic-only-passphrase-381!')
        self.b = get_user_model().objects.create_user('two@example.com', 'two@example.com', 'Synthetic-only-passphrase-382!')
        self.web = Client()
        self.web.force_login(self.a)
        self.native = Client()
        self.manifest = {'version': 1, 'subscriptions': [{'id': 'alpha', 'name': 'Example', 'url': 'https://vpn.example/subscription', 'rules': ['DOMAIN-SUFFIX,example.org,DIRECT']}]}

    def post(self, route, payload):
        return self.native.post('/api/member/' + route + '/', json.dumps(payload), content_type='application/json')

    def link(self):
        pending = self.post('authorize', {'challenge': digest('synthetic-verifier'), 'name': 'Test device'}).json()
        self.web.post('/member/approve/', {'code': pending['user_code'], 'decision': 'approve'})
        token = self.post('exchange', {'device_code': pending['device_code'], 'verifier': 'synthetic-verifier'}).json()
        return pending, token

    def test_registration_verification_and_login(self):
        c = Client()
        response = c.post('/member/register/', {'email': 'new@example.com', 'password1': 'Unique-synthetic-example-3982!', 'password2': 'Unique-synthetic-example-3982!'})
        self.assertEqual(response.status_code, 200)
        user = get_user_model().objects.get(username='new@example.com')
        self.assertFalse(user.is_active)
        raw = mail.outbox[-1].body.split('#')[1].split('\n')[0]
        self.assertEqual(c.post('/member/confirm/', {'token': raw}).status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertEqual(c.post('/member/sign-in/', {'email': user.email, 'password': 'Unique-synthetic-example-3982!'}).status_code, 302)
        self.assertContains(c.post('/member/confirm/', {'token': raw}), 'expired')

    def test_device_link_preserves_sign_in_and_registration_handoff(self):
        pending = self.post('authorize', {'challenge': digest('handoff')}).json()
        self.assertIn('?code=' + pending['user_code'], pending['verification_uri'])
        next_path = '/member/approve/?code=' + pending['user_code']
        anonymous = Client()
        response = anonymous.get(next_path)
        self.assertIn('next=', response.url)
        response = anonymous.post('/member/sign-in/', {
            'email': self.a.email,
            'password': 'Synthetic-only-passphrase-381!',
            'next': next_path,
        })
        self.assertRedirects(response, next_path, fetch_redirect_response=False)
        self.assertContains(anonymous.get(next_path), 'value="' + pending['user_code'] + '"')

        registration = Client()
        response = registration.post('/member/register/', {
            'email': 'handoff@example.com',
            'password1': 'Unique-synthetic-example-3983!',
            'password2': 'Unique-synthetic-example-3983!',
            'next': next_path,
        })
        fragment = mail.outbox[-1].body.split('#')[1].split('\n')[0]
        values = parse_qs(fragment)
        self.assertEqual(values['next'], [next_path])
        response = registration.post('/member/confirm/', {
            'token': values['token'][0],
            'next': values['next'][0],
        })
        self.assertIn('next=', response.url)

    def test_approved_device_page_returns_to_app_without_credentials(self):
        pending = self.post('authorize', {'challenge': digest('return')}).json()
        response = self.web.post('/member/approve/', {
            'code': pending['user_code'],
            'decision': 'approve',
        })
        self.assertContains(response, 'vipernet://membership-linked')
        self.assertContains(response, 'intent://membership-linked#Intent;scheme=vipernet;end')
        self.assertNotContains(response, pending['device_code'])

    def test_root_enters_the_member_flow(self):
        self.assertRedirects(self.web.get('/'), '/member/account/', fetch_redirect_response=False)

    def test_device_binding_pending_single_use_and_expiry(self):
        p = self.post('authorize', {'challenge': digest('right')}).json()
        self.assertEqual(self.post('exchange', {'device_code': p['device_code'], 'verifier': 'right'}).json()['error'], 'authorization_pending')
        self.web.post('/member/approve/', {'code': p['user_code'], 'decision': 'approve'})
        self.assertEqual(self.post('exchange', {'device_code': p['device_code'], 'verifier': 'wrong'}).status_code, 400)
        self.assertIn('access_token', self.post('exchange', {'device_code': p['device_code'], 'verifier': 'right'}).json())
        self.assertEqual(self.post('exchange', {'device_code': p['device_code'], 'verifier': 'right'}).status_code, 400)
        Grant.objects.update(expires=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.post('exchange', {'device_code': p['device_code'], 'verifier': 'right'}).status_code, 400)

    def test_feed_etag_revocation_and_account_isolation(self):
        save_revision(self.a, 0, self.manifest)
        _, token = self.link()
        auth = {'HTTP_AUTHORIZATION': 'Bearer ' + token['access_token']}
        response = self.native.get('/api/member/feed/', **auth)
        self.assertEqual(response.json()['revision'], 1)
        self.assertEqual(response.json()['defaultSubscriptionId'], 'alpha')
        self.assertEqual(self.native.get('/api/member/feed/', HTTP_IF_NONE_MATCH=response['ETag'], **auth).status_code, 304)
        self.web.force_login(self.b)
        self.assertEqual(self.web.post('/member/devices/', {'id': token['device_id'], 'action': 'revoke'}).status_code, 404)
        self.assertNotContains(self.web.get('/member/configuration/'), 'vpn.example')
        self.assertEqual(self.web.post('/member/restore/1/', {'revision': 0}).status_code, 404)
        self.web.force_login(self.a)
        self.web.post('/member/devices/', {'id': token['device_id'], 'action': 'revoke'})
        self.assertEqual(self.native.get('/api/member/feed/', **auth).status_code, 401)

    def test_native_account_identity_and_revocation(self):
        _, token = self.link()
        self.assertEqual(token['email'], self.a.email)
        auth = {'HTTP_AUTHORIZATION': 'Bearer ' + token['access_token']}
        response = self.native.get('/api/member/account/', **auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], self.a.email)
        self.assertEqual(response.json()['device_name'], 'Test device')
        self.assertNotIn('access_token', response.json())
        Device.objects.filter(pk=token['device_id']).update(revoked=True)
        self.assertEqual(self.native.get('/api/member/account/', **auth).status_code, 401)

    def test_conflicts_tombstones_and_intentional_restore(self):
        save_revision(self.a, 0, self.manifest)
        with self.assertRaises(Conflict):
            save_revision(self.a, 0, self.manifest)
        save_revision(self.a, 1, {'version': 1, 'subscriptions': []})
        with self.assertRaises(Conflict):
            save_revision(self.a, 2, self.manifest)
        save_revision(self.a, 2, self.manifest, restore=True)
        value = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertIn('alpha', value['tombstones'])
        self.assertNotEqual(value['subscriptions'][0]['id'], 'alpha')
        self.assertEqual(Revision.objects.count(), 3)

    def test_platform_app_bypass_mappings_are_validated_and_preserved(self):
        value = {
            **self.manifest,
            'appBypass': {
                'windowsExecutables': ['WeChat.exe', 'DingTalk.exe', 'WeChat.exe'],
                'androidPackages': ['com.tencent.mm', 'com.alibaba.android.rimet'],
            },
        }
        save_revision(self.a, 0, value)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['appBypass']['windowsExecutables'], ['WeChat.exe', 'DingTalk.exe'])
        self.assertEqual(stored['appBypass']['androidPackages'], ['com.tencent.mm', 'com.alibaba.android.rimet'])
        for invalid in ['C:\\Apps\\WeChat.exe', '../WeChat.exe', '']:
            value['appBypass']['windowsExecutables'] = [invalid]
            with self.assertRaises(ValueError):
                save_revision(self.a, 1, value)
        value['appBypass']['windowsExecutables'] = []
        value['appBypass']['androidPackages'] = ['not-a-package']
        with self.assertRaises(ValueError):
            save_revision(self.a, 1, value)

    def test_native_android_routing_lists_save_with_revision_conflicts(self):
        save_revision(self.a, 0, {
            **self.manifest,
            'appBypass': {
                'windowsExecutables': ['WeChat.exe'],
                'androidPackages': [],
            },
        })
        _, token = self.link()
        auth = {'HTTP_AUTHORIZATION': 'Bearer ' + token['access_token']}
        payload = {
            'revision': 1,
            'active_list_id': 'chinaapps',
            'lists': [{
                'id': 'chinaapps',
                'name': 'Chinese apps',
                'identifiers': ['com.tencent.mm', 'com.alibaba.android.rimet'],
            }],
        }
        response = self.native.post(
            '/api/member/app-routing/',
            json.dumps(payload),
            content_type='application/json',
            **auth,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['revision'], 2)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['activeAppRoutingListIds']['android'], 'chinaapps')
        self.assertEqual(stored['appBypass']['androidPackages'], payload['lists'][0]['identifiers'])
        self.assertEqual(stored['appBypass']['windowsExecutables'], ['WeChat.exe'])
        conflict = self.native.post(
            '/api/member/app-routing/',
            json.dumps(payload),
            content_type='application/json',
            **auth,
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()['error'], 'conflict')

    def test_app_routing_lists_reject_invalid_packages(self):
        value = {
            **self.manifest,
            'appRoutingLists': [{
                'id': 'badlist',
                'name': 'Bad list',
                'platform': 'android',
                'identifiers': ['not-a-package'],
            }],
            'activeAppRoutingListIds': {'android': 'badlist'},
        }
        with self.assertRaises(ValueError):
            save_revision(self.a, 0, value)

    def test_global_rules_mode_is_validated_and_preserved(self):
        value = {**self.manifest, 'globalRules': {'mode': 'loyalsoldier-whitelist', 'sourceUrl': 'https://github.com/Loyalsoldier/clash-rules'}}
        save_revision(self.a, 0, value)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['globalRules'], {'mode': 'loyalsoldier-whitelist', 'sourceUrl': 'https://github.com/Loyalsoldier/clash-rules'})
        value['globalRules'] = {'mode': 'unknown'}
        with self.assertRaises(ValueError):
            save_revision(self.a, 1, value)

    def test_default_subscription_is_stable_and_must_reference_a_saved_source(self):
        second = {'id': 'beta', 'name': 'Second', 'url': 'https://vpn.example/second', 'rules': []}
        value = {**self.manifest, 'subscriptions': [*self.manifest['subscriptions'], second]}
        save_revision(self.a, 0, value)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['defaultSubscriptionId'], 'alpha')
        value['defaultSubscriptionId'] = 'beta'
        save_revision(self.a, 1, value)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['defaultSubscriptionId'], 'beta')
        value['defaultSubscriptionId'] = 'missing'
        with self.assertRaises(ValueError):
            save_revision(self.a, 2, value)

    def test_generic_github_rules_links_are_accepted_but_other_hosts_are_rejected(self):
        value = {**self.manifest, 'globalRules': {'mode': 'github-auto', 'sourceUrl': 'https://github.com/example/clash-rules/tree/main/rules'}}
        save_revision(self.a, 0, value)
        stored = unseal(Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(stored['globalRules'], value['globalRules'])
        for invalid in ['https://example.com/rules', 'http://github.com/example/rules', 'https://user:pass@github.com/example/rules', 'https://github.com/example/rules#readme']:
            value['globalRules']['sourceUrl'] = invalid
            with self.assertRaises(ValueError):
                save_revision(self.a, 1, value)

    def test_browser_autosave_returns_revision_and_conflicts_as_json(self):
        response = self.web.post(
            '/member/configuration/',
            {'revision': 0, 'configuration': json.dumps(self.manifest)},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'saved': True, 'revision': 1})
        conflict = self.web.post(
            '/member/configuration/',
            {'revision': 0, 'configuration': json.dumps(self.manifest)},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertFalse(conflict.json()['saved'])

    def test_encryption_export_delete(self):
        save_revision(self.a, 0, self.manifest)
        self.assertNotIn('vpn.example', Vault.objects.get(user=self.a).ciphertext)
        self.assertEqual(self.web.post('/member/export/', {'password': 'Synthetic-only-passphrase-381!'}).json()['configuration']['subscriptions'][0]['id'], 'alpha')
        _, token = self.link()
        self.web.post('/member/delete/', {'password': 'Synthetic-only-passphrase-381!', 'confirm': 'DELETE'})
        self.assertFalse(get_user_model().objects.filter(pk=self.a.pk).exists())
        self.assertEqual(Vault.objects.count(), 0)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(self.native.get('/api/member/feed/', HTTP_AUTHORIZATION='Bearer ' + token['access_token']).status_code, 401)

    def test_recovery_preserves_vault_revokes_devices(self):
        save_revision(self.a, 0, self.manifest)
        self.link()
        self.native.post('/member/recovery/', {'email': self.a.email})
        raw = mail.outbox[-1].body.split('#')[1].split('\n')[0]
        response = self.native.post('/member/confirm/', {'token': raw, 'new_password1': 'Another-synthetic-passphrase-396!', 'new_password2': 'Another-synthetic-passphrase-396!'})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Device.objects.filter(revoked=False).exists())
        self.assertEqual(Vault.objects.get(user=self.a).revision, 1)
        self.assertEqual(self.web.get('/member/account/').status_code, 302)

    def test_csrf_rate_limits_invalid_config_and_cookie_rejection(self):
        csrf = Client(enforce_csrf_checks=True)
        self.assertEqual(csrf.post('/member/sign-in/', {}).status_code, 403)
        self.assertEqual(self.web.post('/api/member/authorize/', json.dumps({'challenge': digest('x')}), content_type='application/json').status_code, 403)
        for _ in range(16):
            last = self.post('authorize', {'challenge': digest('x')})
        self.assertEqual(last.status_code, 429)
        for url in ['http://vpn.example', 'https://user:pass@vpn.example', 'file:///private']:
            bad = {'version': 1, 'subscriptions': [{'name': 'Bad', 'url': url}]}
            with self.assertRaises(ValueError):
                save_revision(self.a, 0, bad)

    def test_expired_device_and_logout(self):
        _, token = self.link()
        Device.objects.update(expires=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.native.get('/api/member/feed/', HTTP_AUTHORIZATION='Bearer ' + token['access_token']).status_code, 401)
        self.assertEqual(self.web.get('/member/logout/').status_code, 405)
        self.web.post('/member/logout/')
        self.assertEqual(self.web.get('/member/account/').status_code, 302)

    def test_denied_grant_and_malformed_native_inputs(self):
        pending = self.post('authorize', {'challenge': digest('denied')}).json()
        self.web.post('/member/approve/', {'code': pending['user_code'], 'decision': 'deny'})
        self.web.post('/member/approve/', {'code': pending['user_code'], 'decision': 'approve'})
        grant = Grant.objects.get(user_code=pending['user_code'])
        self.assertIsNone(grant.user_id)
        self.assertEqual(self.post('exchange', {'device_code': pending['device_code'], 'verifier': 'denied'}).status_code, 403)
        for malformed in [None, [], {}, 42]:
            self.assertEqual(self.post('exchange', {'device_code': malformed, 'verifier': 'x'}).status_code, 400)

    def test_security_headers_and_plaintext_absence(self):
        save_revision(self.a, 0, self.manifest)
        response = self.web.get('/member/configuration/')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])
        for version in Revision.objects.all():
            self.assertNotIn('vpn.example', version.ciphertext)
