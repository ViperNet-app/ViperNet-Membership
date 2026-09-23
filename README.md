# ViperNet membership service

Public ViperNet account service, deployed at `https://members.vipernet.app`. Android and Windows remain usable with a
user-controlled configuration page, manual subscription URL, or local file, without an account.

Membership lets a user enter subscription sources, routing rules, and platform-aware bypass-app mappings once, then
receive the appropriate configuration on linked Windows and Android devices. The version 1 native clients are read-only
replicas of the hosted workspace. See `docs/SYNC_CONTRACT.md` for the exact synchronized and device-local boundaries.

## Local review

Requires Python 3.11 or later. From this directory:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export VIPERNET_DEV=1
.venv/bin/python manage.py migrate
.venv/bin/python manage.py runserver 127.0.0.1:8765
```

On Windows use `.venv\Scripts\python.exe` and `$env:VIPERNET_DEV='1'`.
Open `http://127.0.0.1:8765/member/register/`. Verification and recovery messages are written to `.state/mail` in local
mode; no email is sent. Use synthetic email addresses and configurations for review. Local keys and SQLite data are
generated under `.state` and excluded from Git.

```sh
python manage.py test
python manage.py check
```

## Implemented

- Email/password registration, one-use email verification, password recovery, 12-hour browser sessions and logout.
- Configuration editor, encrypted current state and version history, explicit version restore and stale-write rejection.
- New subscription drafts require an explicit green Add action before their first save. Saved sources are locked until
  Edit is chosen, then require Save or Cancel, and use the right-aligned red trash action for removal. Drafts remain local until Add succeeds, so
  an unfinished draft does not block global rules or other saved settings. Saved-source title bars use the lighter
  green treatment; drafts remain visually distinct.
- Locked GitHub rules-link entry with explicit Add/Edit/Save actions, automatic recognition of the maintained Loyalsoldier collection and a generic,
  validation-gated path for other Clash/Mihomo rule repositories, folders and files.
- Browser-approved device linking, read-only configuration feed, per-device revocation and 30-day expiry.
- Device names, account data export with password confirmation, account deletion and access invalidation.
- CSRF protection for browser writes, login/API rate limits, no third-party scripts, and restrictive security headers.

Passwords use Django's password hashing. Configuration is encrypted at rest with an operator-owned Fernet key.
This is **not end-to-end encryption**: the service operator can decrypt stored configurations. Linked devices necessarily
receive subscription credentials. Revocation prevents future service access, but cannot erase previously downloaded
profiles or revoke the VPN provider's own credentials. Password recovery preserves encrypted configuration and revokes
all device credentials; it also invalidates existing browser sessions through Django's password-session checks.

## Configuration and sync contract

The feed uses the clients' version-1 configuration-source manifest, adding stable ASCII-alphanumeric `id` values and a
monotonically increasing `revision`. Configuration writes include the revision the editor loaded. A stale write returns
409, preserving the submitted draft for review; it does not overwrite the newer server state. Deleted source identifiers
remain tombstoned. Explicit restore creates a new revision and new identifiers for previously deleted sources.

Clients are read-only replicas. They manage only profiles mapped to source IDs; manually imported profiles remain
independent. Switching sources clears the old source cache and ownership mapping and preserves existing local profiles.
Removing an item from the same managed source removes its corresponding managed profile after successful refresh.
Temporary network failure retains a bounded offline cache; 401/403 and expired device credentials fail closed for sync.

## Native device authorization (ViperNet protocol v1)

This is a small custom proof-bound device protocol, not an OAuth compliance claim.

1. Native client generates a random verifier, sends its SHA-256 hex digest and device name to
   `POST /api/member/authorize/`.
2. Service returns a random `device_code`, 8-character `user_code`, same-origin `verification_uri`, and 10-minute expiry.
3. Client opens the system browser at a same-origin approval URL with the short code prefilled. Sign-in and registration
   preserve that pending approval. After approval, the browser securely returns to the app when supported.
4. Client polls `POST /api/member/exchange/` with `device_code` plus the original verifier. Pending approval returns
   `authorization_pending`. Approval is single-use and bound to the verifier; denial and expiration fail closed.
5. A successful exchange returns a read-only opaque bearer credential, exact same-origin feed URL and 30-day lifetime.
   Only the credential hash is stored server-side. Clients use Android secure storage or Windows Credential Manager.
6. Feed requests use `Authorization: Bearer ...`; credentials never enter browser URLs or cookies. ETags support 304.
   `POST /api/member/revoke/` revokes the current device. Expired access requires browser linking again.

Native POST endpoints reject browser Origin headers and cookies. Browser approval always requires session authentication
and CSRF. Request bodies and authorization headers must never be logged. Forwarding credentials across redirects is
forbidden. The user can supply another compatible service origin; a ViperNet-operated service is not required.

## Production operations

Use a dedicated Linux service account, a dedicated PostgreSQL database, HTTPS termination and an audited mail provider.
Example environment names are in `deployment.env.example`; generate values locally and store them outside the source tree.
Keep `VIPERNET_DEV` unset. Set the public origin to the exact HTTPS service origin. Never reuse a marketing-site password,
private portal session, personal provider token, or development key.

Run migrations, `collectstatic`, tests and `check --deploy` before starting the service. A representative process is:

```sh
waitress-serve --listen=127.0.0.1:8765 --trusted-proxy=127.0.0.1 --trusted-proxy-headers=x-forwarded-proto service.wsgi:application
```

The reverse proxy must strip incoming forwarded headers, supply the actual scheme, enforce a 1 MiB body limit and rate
limits, and serve `.static/` at `/member-static/`. Block direct external access to the WSGI port. Rate buckets currently
use the WSGI peer address; configure/verify trusted forwarding before multi-user production to avoid one shared bucket.
Do not log request bodies, query strings, cookies, authorization headers or exported configuration. Restrict database,
mail-capture and key-file permissions to the service user. Never expose `.state`, backups or application source as static
files. The production database must be independent of any other ViperNet or personal application database.

Back up encrypted database data and keys separately, and rehearse restoration in an isolated environment. Losing the
vault key loses configuration access. Rotating it requires decrypting and re-encrypting all current and historical
records under a maintenance plan; changing the environment value alone is not a migration. The service does not yet
publish a time limit for encrypted backups after account deletion; define and publish that retention period. Account
deletion removes live records immediately. Run `python manage.py clearsessions` and `python manage.py purge_expired`
periodically.

Production uses PostgreSQL, real email delivery, a daily maintenance timer, HTTPS, and protected off-tree secrets. The
initial production cutover included a database/key backup and isolated restore rehearsal. Remaining installer acceptance
gates are Windows TUN and physical Android routing; browser-to-app device linking is implemented and requires physical
Android acceptance.
Native Android writes are limited to named app-routing lists and require a current revision. Subscription and rule editing
remains browser-only. Billing, paid plans, curated rule packs, and connection-health warnings are not implemented.

## License

New membership code is licensed under GPL-3.0-only; see `LICENSE`. Django, cryptography, Waitress and psycopg retain their
own upstream licenses. No upstream notices are removed. General contact: info@vipernet.app.
