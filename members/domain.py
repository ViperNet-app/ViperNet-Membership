import hashlib
import json
import re
import secrets
from datetime import timedelta
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from .models import Vault, Revision, RateBucket

def digest(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError('Invalid value')
    return hashlib.sha256(value.encode()).hexdigest()

def seal(value):
    return Fernet(settings.VAULT_KEY.encode()).encrypt(json.dumps(value).encode()).decode()

def unseal(value):
    return json.loads(Fernet(settings.VAULT_KEY.encode()).decrypt(value.encode())) if value else {'version': 1, 'subscriptions': [], 'tombstones': []}

def limited(request, scope, count=20, seconds=600):
    key = digest(scope + ':' + request.META.get('REMOTE_ADDR', '') + ':' + str(int(timezone.now().timestamp()) // seconds))
    bucket, _ = RateBucket.objects.get_or_create(key=key, defaults={'expires': timezone.now() + timedelta(seconds=seconds * 2)})
    RateBucket.objects.filter(pk=key).update(count=F('count') + 1)
    bucket.refresh_from_db()
    RateBucket.objects.filter(expires__lt=timezone.now()).delete()
    return bucket.count > count

def validate_manifest(value):
    if not isinstance(value, dict) or value.get('version') != 1:
        raise ValueError('Unsupported configuration version.')
    items = value.get('subscriptions')
    if not isinstance(items, list) or len(items) > 64:
        raise ValueError('Use at most 64 subscription sources.')
    seen = set()
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('Invalid source.')
        identity = item.get('id') or secrets.token_hex(16)
        name = item.get('name', '')
        url = item.get('url', '')
        if not isinstance(identity, str) or not identity.isascii() or not identity.isalnum() or len(identity) > 64 or identity in seen:
            raise ValueError('Source identifiers must be unique.')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not isinstance(url, str) or len(url) > 4096:
            raise ValueError('Give each source a name and HTTPS URL.')
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Subscription URLs must use HTTPS without embedded credentials or fragments.')
        rules = item.get('rules', [])
        if not isinstance(rules, list) or len(rules) > 512 or any(not isinstance(x, str) or not 1 <= len(x) <= 2048 or ',' not in x or '\n' in x or '\r' in x for x in rules):
            raise ValueError('Routing rules must be single-line Mihomo rules, at most 512 per source.')
        hours = item.get('autoUpdateHours', 24)
        if not isinstance(hours, int) or not 1 <= hours <= 168:
            raise ValueError('Refresh must be between 1 and 168 hours.')
        seen.add(identity)
        result.append({'id': identity, 'name': name.strip(), 'url': url, 'rules': rules, 'autoUpdateHours': hours})
    clean = {'version': 1, 'subscriptions': result}
    default_id = value.get('defaultSubscriptionId')
    if result:
        if default_id is None:
            default_id = result[0]['id']
        if not isinstance(default_id, str) or default_id not in seen:
            raise ValueError('Choose a default subscription from the saved sources.')
        clean['defaultSubscriptionId'] = default_id
    elif default_id not in {None, ''}:
        raise ValueError('Remove the default subscription when there are no sources.')
    global_rules = value.get('globalRules')
    if global_rules is not None:
        if not isinstance(global_rules, dict) or global_rules.get('mode') not in {
            'subscription',
            'github-auto',
            'loyalsoldier-whitelist',
            'loyalsoldier-blacklist',
        }:
            raise ValueError('Choose a supported global rules mode.')
        source_url = global_rules.get('sourceUrl', '')
        if not isinstance(source_url, str) or len(source_url) > 4096:
            raise ValueError('Use a valid GitHub rules link.')
        source_url = source_url.strip()
        if not source_url and global_rules['mode'] in {'loyalsoldier-whitelist', 'loyalsoldier-blacklist'}:
            source_url = 'https://github.com/Loyalsoldier/clash-rules'
        if source_url:
            parsed = urlsplit(source_url)
            hostname = (parsed.hostname or '').lower()
            if (
                parsed.scheme != 'https'
                or hostname not in {'github.com', 'raw.githubusercontent.com'}
                or parsed.username
                or parsed.password
                or parsed.fragment
                or len([part for part in parsed.path.split('/') if part]) < 2
            ):
                raise ValueError('Rules links must be HTTPS GitHub repository, folder, file, or raw-file links.')
        if global_rules['mode'] == 'subscription' and source_url:
            raise ValueError('Remove the GitHub rules link when keeping subscription rules.')
        if global_rules['mode'] != 'subscription' and not source_url:
            raise ValueError('Add the GitHub rules link for this rules mode.')
        clean['globalRules'] = {'mode': global_rules['mode']}
        if source_url:
            clean['globalRules']['sourceUrl'] = source_url
    bypass = value.get('appBypass')
    if bypass is not None:
        if not isinstance(bypass, dict):
            raise ValueError('App bypass mappings must be an object.')
        windows = bypass.get('windowsExecutables', [])
        android = bypass.get('androidPackages', [])
        if not isinstance(windows, list) or len(windows) > 512 or any(
            not isinstance(item, str)
            or not 1 <= len(item.strip()) <= 260
            or '/' in item
            or '\\' in item
            or any(ord(char) < 32 for char in item)
            for item in windows
        ):
            raise ValueError('Windows bypass entries must be executable names, at most 512 items.')
        if not isinstance(android, list) or len(android) > 512 or any(
            not isinstance(item, str)
            or not 3 <= len(item) <= 255
            or re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+', item) is None
            for item in android
        ):
            raise ValueError('Android bypass entries must be package names, at most 512 items.')
        clean_windows = {}
        for item in windows:
            name = item.strip()
            clean_windows.setdefault(name.casefold(), name)
        clean['appBypass'] = {
            'windowsExecutables': list(clean_windows.values()),
            'androidPackages': list(dict.fromkeys(item.strip() for item in android)),
        }
    routing_lists = value.get('appRoutingLists')
    if routing_lists is not None:
        if not isinstance(routing_lists, list) or len(routing_lists) > 64:
            raise ValueError('Use at most 64 app routing lists.')
        clean_lists = []
        list_ids = set()
        for routing_list in routing_lists:
            if not isinstance(routing_list, dict):
                raise ValueError('Invalid app routing list.')
            identity = routing_list.get('id', '')
            name = routing_list.get('name', '')
            platform = routing_list.get('platform', '')
            identifiers = routing_list.get('identifiers', [])
            if (
                not isinstance(identity, str)
                or not identity.isascii()
                or not identity.isalnum()
                or not 1 <= len(identity) <= 64
                or identity in list_ids
            ):
                raise ValueError('App routing list identifiers must be unique.')
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                raise ValueError('Give each app routing list a name.')
            if platform not in {'android', 'windows'}:
                raise ValueError('Choose a supported app routing platform.')
            if not isinstance(identifiers, list) or len(identifiers) > 512:
                raise ValueError('Use at most 512 apps in a routing list.')
            if platform == 'android':
                if any(
                    not isinstance(item, str)
                    or not 3 <= len(item) <= 255
                    or re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+', item) is None
                    for item in identifiers
                ):
                    raise ValueError('Android routing entries must be package names.')
                normalized = list(dict.fromkeys(item.strip() for item in identifiers))
            else:
                if any(
                    not isinstance(item, str)
                    or not 1 <= len(item.strip()) <= 260
                    or '/' in item
                    or '\\' in item
                    or any(ord(char) < 32 for char in item)
                    for item in identifiers
                ):
                    raise ValueError('Windows routing entries must be executable names.')
                unique = {}
                for item in identifiers:
                    executable = item.strip()
                    unique.setdefault(executable.casefold(), executable)
                normalized = list(unique.values())
            list_ids.add(identity)
            clean_lists.append({
                'id': identity,
                'name': name.strip(),
                'platform': platform,
                'identifiers': normalized,
            })
        active = value.get('activeAppRoutingListIds', {})
        if not isinstance(active, dict) or any(key not in {'android', 'windows'} for key in active):
            raise ValueError('Invalid active app routing lists.')
        clean_active = {}
        for platform, identity in active.items():
            if not isinstance(identity, str) or not any(
                item['id'] == identity and item['platform'] == platform for item in clean_lists
            ):
                raise ValueError('The active app routing list must exist for its platform.')
            clean_active[platform] = identity
        routing_tombstones = value.get('appRoutingTombstones', [])
        if (
            not isinstance(routing_tombstones, list)
            or len(routing_tombstones) > 256
            or any(not isinstance(item, str) or not item.isascii() or not item.isalnum() or len(item) > 64 for item in routing_tombstones)
        ):
            raise ValueError('Invalid app routing deletion history.')
        clean['appRoutingLists'] = clean_lists
        clean['activeAppRoutingListIds'] = clean_active
        clean['appRoutingTombstones'] = list(dict.fromkeys(routing_tombstones))
    return clean

class Conflict(Exception):
    pass

@transaction.atomic
def save_revision(user, expected, value, restore=False):
    vault, _ = Vault.objects.get_or_create(user=user)
    vault = Vault.objects.select_for_update().get(pk=vault.pk)
    if expected != vault.revision:
        raise Conflict('Your configuration changed on another device. Reload and review before saving.')
    previous = unseal(vault.ciphertext)
    clean = validate_manifest(value)
    old_ids = {x['id'] for x in previous['subscriptions']}
    new_ids = {x['id'] for x in clean['subscriptions']}
    tombstones = set(previous.get('tombstones', [])) | (old_ids - new_ids)
    if new_ids & tombstones and not restore:
        raise Conflict('A deleted source cannot be restored by a stale edit. Use version history to restore it.')
    if restore:
        restored_ids = {}
        for source in clean['subscriptions']:
            if source['id'] in tombstones:
                previous_id = source['id']
                source['id'] = secrets.token_hex(16)
                restored_ids[previous_id] = source['id']
        if clean.get('defaultSubscriptionId') in restored_ids:
            clean['defaultSubscriptionId'] = restored_ids[clean['defaultSubscriptionId']]
    clean['tombstones'] = sorted(tombstones)
    encrypted = seal(clean)
    changed = Vault.objects.filter(pk=vault.pk, revision=expected).update(revision=expected + 1, ciphertext=encrypted)
    if not changed:
        raise Conflict('Configuration changed. Reload before saving.')
    Revision.objects.create(vault=vault, number=expected + 1, ciphertext=encrypted)
    return expected + 1
