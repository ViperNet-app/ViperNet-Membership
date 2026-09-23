import json
import re
import secrets
from urllib.parse import urlencode
from datetime import timedelta
from functools import wraps
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm
from django.core.mail import send_mail
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from .domain import digest, limited, unseal, validate_manifest, save_revision, Conflict
from .models import Vault, Revision, Device, Grant, MailAction

User = get_user_model()

def csrf_failure(request, reason=''):
    response = page(request, 'Session expired', error=('Local CSRF check: ' + reason) if settings.DEV else 'Reload the page and try again. Your session may have expired.')
    response.status_code = 403
    return response

class RegisterForm(UserCreationForm):
    email = forms.EmailField(max_length=150)
    class Meta:
        model = User
        fields = ('email',)

def page(request, title, **context):
    return render(request, 'member.html', {'title': title, 'dev': settings.DEV, **context})

def safe_next(request):
    value = request.POST.get('next') or request.GET.get('next') or ''
    if not value.startswith('/') or value.startswith('//'):
        return ''
    if not url_has_allowed_host_and_scheme(value, {request.get_host()}, require_https=request.is_secure()):
        return ''
    return value

def mail_action(user, purpose, next_path=''):
    MailAction.objects.filter(user=user, purpose=purpose).delete()
    raw = secrets.token_urlsafe(32)
    MailAction.objects.create(user=user, digest=digest(raw), purpose=purpose, expires=timezone.now() + timedelta(minutes=30))
    fragment = raw if not next_path else urlencode({'token': raw, 'next': next_path})
    link = settings.PUBLIC_ORIGIN + '/member/confirm/#' + fragment
    send_mail('ViperNet ' + ('verify your email' if purpose == 'verify' else 'account recovery'), 'Open this link within 30 minutes: ' + link + '\nIf you did not request this, ignore this email.', settings.DEFAULT_FROM_EMAIL, [user.email])

def register(request):
    next_path = safe_next(request)
    form = RegisterForm(request.POST or None)
    if request.method == 'POST':
        if limited(request, 'register', 5):
            return page(request, 'Please wait', error='Too many requests. Try again in ten minutes.')
        if form.is_valid():
            email = form.cleaned_data['email'].strip().lower()
            if not User.objects.filter(username=email).exists():
                user = form.save(commit=False)
                user.username = email
                user.email = email
                user.is_active = False
                user.save()
                mail_action(user, 'verify', next_path)
            return page(request, 'Check your email', notice='If this address can be registered, a verification link has been sent. Existing members can use account recovery.')
    return page(request, 'Register', form=form, submit='Create account', next_path=next_path)

def sign_in(request):
    next_path = safe_next(request)
    if request.method == 'POST':
        if limited(request, 'login', 15):
            return page(request, 'Sign in', error='Too many attempts. Try again in ten minutes.', login_form=True, next_path=next_path)
        user = authenticate(request, username=request.POST.get('email', '').strip().lower(), password=request.POST.get('password', ''))
        if user:
            login(request, user)
            return redirect(next_path or '/member/account/')
        return page(request, 'Sign in', error='Unable to sign in. Check your details and verify your email, or use recovery.', login_form=True, next_path=next_path)
    return page(request, 'Sign in', login_form=True, next_path=next_path)

def recovery(request):
    if request.method == 'POST':
        if not limited(request, 'recovery', 5):
            user = User.objects.filter(username=request.POST.get('email', '').strip().lower()).first()
            if user:
                mail_action(user, 'reset' if user.is_active else 'verify')
        return page(request, 'Check your email', notice='If the account exists, we sent a recovery link. Check your spam folder too.')
    return page(request, 'Account recovery', recovery_form=True)

def confirm(request):
    if request.method != 'POST':
        return page(request, 'Confirm your email', confirm_form=True)
    if limited(request, 'confirm', 15):
        return page(request, 'Please wait', error='Too many attempts.')
    with transaction.atomic():
        action = MailAction.objects.select_for_update().filter(digest=digest(request.POST.get('token', '')), expires__gt=timezone.now()).first()
        if not action:
            return page(request, 'Link expired', error='This link has expired or was already used. Request a new recovery email.')
        user = action.user
        if action.purpose == 'reset':
            form = SetPasswordForm(user, request.POST if request.POST.get('new_password1') else None)
            if not form.is_bound or not form.is_valid():
                return page(request, 'Choose a new password', form=form, token=request.POST['token'], submit='Save password')
            form.save()
            Device.objects.filter(user=user).update(revoked=True)
        else:
            user.is_active = True
            user.save(update_fields=['is_active'])
        MailAction.objects.filter(user=user).delete()
    next_path = safe_next(request)
    return redirect('/member/sign-in/' + (('?' + urlencode({'next': next_path})) if next_path else ''))

@login_required
def account(request):
    vault, _ = Vault.objects.get_or_create(user=request.user)
    active_devices = Device.objects.filter(user=request.user, revoked=False, expires__gt=timezone.now())
    return page(request, 'Account', account=True, revision=vault.revision, device_count=active_devices.count(), recent_devices=active_devices.order_by('-created')[:3])

@login_required
@require_POST
def sign_out(request):
    logout(request)
    return redirect('/member/sign-in/')

@login_required
def configuration(request):
    vault, _ = Vault.objects.get_or_create(user=request.user)
    error = None
    status = 200
    draft = None
    if request.method == 'POST':
        automatic = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        try:
            draft = json.loads(request.POST.get('configuration', '{}'))
            revision = save_revision(request.user, int(request.POST.get('revision', '-1')), draft)
            if automatic:
                return JsonResponse({'saved': True, 'revision': revision})
            messages.success(request, 'Configuration saved. Linked devices can refresh now.')
            return redirect('/member/configuration/')
        except (ValueError, TypeError, Conflict) as exc:
            error = str(exc) if isinstance(exc, Conflict) else 'Invalid configuration. Check the names, HTTPS URLs, routing rules and app identifiers.'
            status = 409 if isinstance(exc, Conflict) else 400
            if automatic:
                return JsonResponse({'saved': False, 'error': error}, status=status)
    value = validate_manifest(unseal(vault.ciphertext))
    value.pop('tombstones', None)
    response = page(request, 'Configuration', configuration=json.dumps(draft or value, indent=2), revision=vault.revision, error=error, history=Revision.objects.filter(vault=vault).order_by('-number')[:50])
    response.status_code = status
    return response

@login_required
@require_POST
def restore(request, number):
    vault = get_object_or_404(Vault, user=request.user)
    revision = get_object_or_404(Revision, vault=vault, number=number)
    try:
        save_revision(request.user, int(request.POST.get('revision', '-1')), unseal(revision.ciphertext), restore=True)
    except (ValueError, Conflict):
        return page(request, 'Configuration changed', error='Reload the configuration before restoring a version.')
    messages.success(request, 'Version restored as a new revision.')
    return redirect('/member/configuration/')

@login_required
def devices(request):
    if request.method == 'POST':
        device = get_object_or_404(Device, pk=request.POST.get('id'), user=request.user)
        if request.POST.get('action') == 'revoke':
            device.revoked = True
        else:
            device.name = request.POST.get('name', '').strip()[:80] or device.name
        device.save()
        return redirect('/member/devices/')
    return page(request, 'Devices', devices=Device.objects.filter(user=request.user).order_by('-created'), devices_page=True)

@login_required
def security(request):
    return page(request, 'Security', security=True)

@login_required
@require_POST
def export(request):
    if limited(request, 'export', 5) or not request.user.check_password(request.POST.get('password', '')):
        return page(request, 'Security', security=True, error='Confirm your password to export.')
    vault, _ = Vault.objects.get_or_create(user=request.user)
    response = JsonResponse({'email': request.user.email, 'revision': vault.revision, 'configuration': unseal(vault.ciphertext), 'history': [{'revision': r.number, 'configuration': unseal(r.ciphertext)} for r in Revision.objects.filter(vault=vault)], 'devices': list(Device.objects.filter(user=request.user).values('name', 'created', 'expires', 'revoked'))})
    response['Content-Disposition'] = 'attachment; filename="vipernet-export.json"'
    return response

@login_required
@require_POST
def delete_account(request):
    if limited(request, 'delete', 5) or not request.user.check_password(request.POST.get('password', '')) or request.POST.get('confirm') != 'DELETE':
        return page(request, 'Security', security=True, error='Enter your password and DELETE to confirm account deletion.')
    user = request.user
    logout(request)
    user.delete()
    return page(request, 'Account deleted', notice='Your account, hosted configuration, versions and devices have been deleted. Copies previously downloaded to devices are not remotely erased.')

@login_required
def approve(request):
    code = request.POST.get('code', '').strip().upper() if request.method == 'POST' else request.GET.get('code', '').strip().upper()
    if request.method == 'POST':
        if limited(request, 'approve', 20):
            return page(request, 'Link device', error='Too many attempts.', approve=True, code=code)
        with transaction.atomic():
            grant = Grant.objects.select_for_update().filter(user_code=code, expires__gt=timezone.now(), consumed=False, denied=False, user__isnull=True).first()
            if not grant:
                return page(request, 'Link device', error='This code is invalid, expired or already approved.', approve=True, code=code)
            if request.POST.get('decision') == 'approve':
                grant.user = request.user
            else:
                grant.denied = True
            grant.save()
        approved = request.POST.get('decision') == 'approve'
        return page(
            request,
            'Device approved' if approved else 'Device denied',
            approval_complete=True,
            return_uri='vipernet://membership-linked',
            notice=(
                'This device is approved. ViperNet will finish linking automatically.'
                if approved else
                'This device request was denied. ViperNet will not receive access.'
            ),
        )
    return page(request, 'Link device', approve=True, code=code)

def json_endpoint(fn):
    @csrf_exempt
    @require_POST
    @wraps(fn)
    def wrapped(request):
        if request.headers.get('Origin') or request.COOKIES:
            return JsonResponse({'error': 'native_client_required'}, status=403)
        if limited(request, fn.__name__, 120 if fn.__name__ == 'exchange' else 15):
            return JsonResponse({'error': 'slow_down'}, status=429)
        try:
            data = json.loads(request.body)
            if not isinstance(data, dict):
                raise ValueError()
            return fn(request, data)
        except (ValueError, TypeError, KeyError):
            return JsonResponse({'error': 'invalid_request'}, status=400)
    return wrapped

@json_endpoint
def authorize(request, data):
    challenge = data.get('challenge', '')
    if not isinstance(challenge, str) or not re.fullmatch('[a-f0-9]{64}', challenge):
        raise ValueError()
    name = str(data.get('name', 'ViperNet device')).strip()[:80]
    code = secrets.token_urlsafe(32)
    human = secrets.token_hex(4).upper()
    Grant.objects.create(code_hash=digest(code), user_code=human, challenge=challenge, name=name, expires=timezone.now() + timedelta(minutes=10))
    verification_uri = settings.PUBLIC_ORIGIN + '/member/approve/?code=' + human
    return JsonResponse({'device_code': code, 'user_code': human, 'verification_uri': verification_uri, 'expires_in': 600, 'interval': 5})

@json_endpoint
@transaction.atomic
def exchange(request, data):
    grant = Grant.objects.select_for_update().filter(code_hash=digest(data.get('device_code', '')), consumed=False, expires__gt=timezone.now()).first()
    if not grant or not secrets.compare_digest(grant.challenge, digest(data.get('verifier', ''))):
        return JsonResponse({'error': 'expired_or_invalid_grant'}, status=400)
    if grant.denied:
        return JsonResponse({'error': 'access_denied'}, status=403)
    if not grant.user_id:
        return JsonResponse({'error': 'authorization_pending'}, status=400)
    if not grant.user.is_active:
        return JsonResponse({'error': 'access_denied'}, status=403)
    grant.consumed = True
    grant.save(update_fields=['consumed'])
    token = secrets.token_urlsafe(48)
    device = Device.objects.create(user=grant.user, name=grant.name, token_hash=digest(token), expires=timezone.now() + timedelta(days=30))
    return JsonResponse({'access_token': token, 'token_type': 'Bearer', 'expires_in': 2592000, 'device_id': device.id, 'feed_url': settings.PUBLIC_ORIGIN + '/api/member/feed/', 'email': grant.user.email})

def device_for(request):
    token = request.headers.get('Authorization', '')
    if not token.startswith('Bearer '):
        return None
    device = Device.objects.filter(token_hash=digest(token[7:]), revoked=False, expires__gt=timezone.now(), user__is_active=True).first()
    if device:
        Device.objects.filter(pk=device.pk).update(last_seen=timezone.now())
    return device

@require_GET
def native_account(request):
    device = device_for(request)
    if not device:
        return JsonResponse({'error': 'unauthorized'}, status=401)
    return JsonResponse({
        'email': device.user.email,
        'device_name': device.name,
        'expires': device.expires.isoformat(),
    })

@require_GET
def feed(request):
    device = device_for(request)
    if not device:
        return JsonResponse({'error': 'unauthorized'}, status=401)
    vault, _ = Vault.objects.get_or_create(user=device.user)
    etag = '"' + str(vault.revision) + '"'
    if request.headers.get('If-None-Match') == etag:
        response = HttpResponse(status=304)
    else:
        stored = unseal(vault.ciphertext)
        value = validate_manifest(stored)
        value['tombstones'] = stored.get('tombstones', [])
        value['revision'] = vault.revision
        response = JsonResponse(value, content_type='application/vnd.vipernet.config+json')
    response['ETag'] = etag
    return response

@json_endpoint
@transaction.atomic
def app_routing(request, data):
    device = device_for(request)
    if not device:
        return JsonResponse({'error': 'unauthorized'}, status=401)
    vault, _ = Vault.objects.get_or_create(user=device.user)
    try:
        expected = int(data.get('revision', -1))
        incoming = data.get('lists')
        active_id = data.get('active_list_id')
        if not isinstance(incoming, list) or active_id is not None and not isinstance(active_id, str):
            raise ValueError()
        current = unseal(vault.ciphertext)
        previous_lists = current.get('appRoutingLists', [])
        windows_lists = [item for item in previous_lists if item.get('platform') == 'windows']
        previous_android_ids = {
            item.get('id') for item in previous_lists if item.get('platform') == 'android'
        }
        incoming_ids = {item.get('id') for item in incoming if isinstance(item, dict)}
        tombstones = set(current.get('appRoutingTombstones', [])) | (previous_android_ids - incoming_ids)
        if incoming_ids & tombstones:
            raise Conflict('A deleted app routing list cannot be restored by a stale edit.')
        draft = dict(current)
        draft['appRoutingLists'] = windows_lists + [
            {**item, 'platform': 'android'} for item in incoming
        ]
        active = dict(current.get('activeAppRoutingListIds', {}))
        if active_id:
            active['android'] = active_id
        else:
            active.pop('android', None)
        draft['activeAppRoutingListIds'] = active
        draft['appRoutingTombstones'] = sorted(tombstones)
        selected = next((item for item in incoming if item.get('id') == active_id), None)
        bypass = dict(current.get('appBypass', {}))
        bypass.setdefault('windowsExecutables', [])
        bypass['androidPackages'] = selected.get('identifiers', []) if selected else []
        draft['appBypass'] = bypass
        revision = save_revision(device.user, expected, draft)
        saved = validate_manifest(unseal(Vault.objects.get(user=device.user).ciphertext))
        return JsonResponse({
            'saved': True,
            'revision': revision,
            'lists': [item for item in saved.get('appRoutingLists', []) if item['platform'] == 'android'],
            'active_list_id': saved.get('activeAppRoutingListIds', {}).get('android'),
        })
    except Conflict as exc:
        return JsonResponse({'error': 'conflict', 'message': str(exc)}, status=409)

@json_endpoint
def revoke(request, data):
    device = device_for(request)
    if device:
        device.revoked = True
        device.save(update_fields=['revoked'])
    return JsonResponse({'ok': True})
