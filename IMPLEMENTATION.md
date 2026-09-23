# Membership service status

Updated 2026-09-23. The service is live at `https://members.vipernet.app` (Bld 6, 2026-09-23 14:02).

Production uses PostgreSQL and real email delivery. A protected database and key backup was made and restored into an
isolated database before production changes. Accounts, recovery, export, deletion, encrypted configuration revisions,
device authorization, revocation, and synchronized Android routing lists are implemented.

Basic VPN use remains available without membership. Native clients receive a read-only configuration feed; Android may
write only its named routing lists with a current revision. Subscriptions and rules remain browser-managed.

Before describing client binaries as public releases, finish installed-client linking and revocation, Windows clean-machine
TUN and network-leak checks, and physical Android VPN and per-app-routing checks. Public signing and an independent security
review also remain outstanding. Define and publish backup-retention timing. Production service availability does not imply
that app binaries have passed these gates.
