# ViperNet membership synchronization contract

Status: production synchronization contract. Native app-routing writes use the version 2 extension described below.

## Product boundary

ViperNet remains fully usable without registration. Membership adds hosted convenience; it does not provide a VPN
subscription, unlock the VPN engine, or make an account mandatory. Manual subscription URLs, local files, and
user-controlled configuration pages remain independent of membership.

## Version 1 synchronized data

- Clash/Mihomo-compatible subscription sources, identified by stable source IDs.
- One global routing policy applied across synchronized subscriptions. Version 1 supports provider rules and the
  maintained Loyalsoldier whitelist or blacklist presets. A user may paste an HTTPS GitHub repository, folder, file,
  or raw-file URL. Known collections map to a reviewed preset; other GitHub sources remain in automatic-detection mode
  until a client validates a compatible Clash/Mihomo rule format. Legacy per-source rules remain readable during migration.
- Bypass-app templates with platform mappings. A logical app entry may contain Windows executable identities and Android
  package names. A client applies only identities valid for its platform and reports unsupported mappings without
  treating them as errors.
- Named platform-specific app-routing lists with stable IDs, one active list per platform, and deletion tombstones.
- Source and rule tombstones so deletions do not reappear from stale devices.
- Revision metadata, version history, explicit restore, and the member-visible device list.

## Device-local data

- VPN connected state, TUN/System selection, current proxy, and current routing mode.
- Traffic totals, connection history, logs, latency results, and transient errors.
- OS permissions, service installation state, paths, window preferences, and notification settings.
- Local profiles imported outside the member source.

These values describe one device or may expose sensitive activity. They are not uploaded. Chinese-app detection also
stays on the device; only package identifiers that the member explicitly saves in a named routing list are synchronized.

## Authority and conflicts

The hosted member workspace is authoritative in version 1. The browser editor saves valid changes automatically and
shows whether a save is pending, complete, or blocked by a conflict. Clients are read-only replicas. Every successful write creates
a monotonically increasing server revision. Browser edits use compare-and-swap; stale writes return HTTP 409 and preserve
the submitted draft for user review. Restore creates a new revision instead of rewriting history.

Native Android clients may replace only their account's Android routing-list collection through the authenticated
app-routing endpoint. The request includes the expected server revision; a stale request receives HTTP 409 and cannot
overwrite subscriptions, rules, Windows lists, or a newer Android edit. Every successful list save creates a complete
encrypted revision and mirrors the active Android list into the legacy flat bypass field for older clients.

## Authentication and credential storage

- Registration, sign-in, verification, recovery, and device approval happen in the system browser.
- Native apps receive a proof-bound, single-use, read-only device credential after browser approval.
- Windows stores the credential in Windows Credential Manager; Android uses platform secure storage.
- Credentials are exact-origin, expire after 30 days, are individually revocable, never enter URLs, and must not be
  logged. Registration passwords and browser cookies never enter the native apps.
- The official service origin is `https://members.vipernet.app`. Advanced builds may accept another compatible HTTPS
  origin. Plain HTTP is allowed only for localhost development.

## Refresh, cache, and offline behavior

- Refresh on explicit user request, application start when due, and at most every six hours in the background.
- Use ETag validation. A 304 response updates the successful-check timestamp without rewriting profiles.
- Retain an encrypted or OS-protected bounded cache for temporary network failure, with a maximum offline age of 30 days.
- Authentication failure, revocation, origin changes, malformed data, and expired credentials fail closed for member
  synchronization. They must not silently extend cache freshness.
- Manual profiles remain available when member synchronization is unavailable.

## Validation and limits

- HTTPS and exact-origin authorization are mandatory outside localhost.
- Redirects carrying authorization are rejected.
- Manifests use a versioned schema, stable ASCII-alphanumeric IDs, bounded text fields, bounded collection sizes, and
  Clash/Mihomo configuration validation before activation.
- Rule-source inspection accepts only `github.com` and `raw.githubusercontent.com` HTTPS URLs. Clients must limit
  redirects, response size, file count and parse depth; reject executable content; preview detected rule behavior; and
  preserve the last valid rules when a refresh is unavailable or invalid. An ambiguous repository must never replace
  active rules silently.
- App mappings are data only. They may contain executable names or Android package IDs, never scripts or commands.

## Privacy, revocation, and deletion

Configuration is encrypted at rest with operator-controlled keys. This is not end-to-end or zero-knowledge encryption.
The operator can decrypt stored configuration, and linked clients necessarily receive subscription credentials.
Revocation blocks future service access but cannot erase data already downloaded or revoke provider credentials.

Account deletion removes live account, configuration, history, and grants immediately. Encrypted backups expire under
the published retention policy. Export requires password confirmation and contains subscription secrets.
