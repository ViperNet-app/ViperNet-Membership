# Current status

Last updated: 2026-09-23

The service is deployed at `https://members.vipernet.app` and serves ViperNet accounts, encrypted configuration revisions,
revocable device feeds, and synchronized routing lists. Production runs PostgreSQL and real email delivery. A protected
backup and isolated database restore rehearsal were completed before production changes.

The Android and Windows clients remain optional readers of member configuration. Manual profile import works without an
account. Android named app-routing lists support revision-checked writes; subscriptions and rules remain browser-managed.

## Remaining acceptance work

- Demonstrate device linking and revocation from installed public Android and Windows clients.
- Complete Windows clean-machine service, TUN, DNS and IP leak, reconnect, sleep/resume, uninstall, and recovery checks.
  A Windows test build connected with TUN; this does not cover the full checklist.
- Complete Android VPN startup, per-app routing, lifecycle, and membership checks on physical hardware.
- Set and publish the encrypted-backup retention period.
- Commission an independent security review of the public client and membership service.
- Prepare and verify public release signing identities and matching source revisions before distributing binaries.

These are separate checks from the production service deployment and from source availability.
