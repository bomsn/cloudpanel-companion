# How CloudPanel Companion works

This is the detailed reference. To install and use the Companion, start with the [README](../README.md).

Independent monitoring, staging and reviewed code releases for an operator-managed
CloudPanel server. The interface runs beside CloudPanel on its own HTTPS hostname.
It does not patch CloudPanel's application, database or authentication system.

The qualified baseline is a single-site WordPress/WooCommerce installation on
Ubuntu 24.04 with CloudPanel 2.5 and PHP 8.3. Native settings saves, reboot,
interruption/recovery, ownership, private shopping journeys and freshness have
been tested on an isolated server. Prepare and check the actual application and
its integrations before changing production DNS.

## Interface

- **Overview:** fresh HTTP, certificate, application/database and server-resource
  observations. Stale or missing observations are unavailable, never healthy.
- **Monitoring:** seven-day CPU/memory and request history, web-PHP workers and
  OPcache, database counters, cache-separated origin timings, grouped server
  errors, service changes and specific firewall/SSH checks. Private data stays
  outside the web service; the browser receives bounded aggregate exports.
- **Staging:** reuse a registered private testing address, pause/resume viewing,
  change its password or explicitly allow public access, and refresh its copy.
- **External tests:** separate controls for captured email, approved HTTPS requests
  and manually triggered webhooks. They default off. Capture does not deliver mail;
  attachments, background commerce jobs and payments remain blocked.
- **Test inbox:** escaped text messages, bounded to 50 messages and 8 MB.
- **Releases:** background file checking, searchable theme/plugin folders, changed
  file counts, expandable details, whole-folder or individual-file selection and
  a fresh review before applying. Destination-only files are labelled and retained.

The native HTML/CSS interface uses one shared token stylesheet and local Lucide SVGs
(see `companion_web/static/LUCIDE-LICENSE.txt`). It has no remote icon dependency or
frontend framework build step. Explicit progress and retry states keep long work
outside the web request where possible. Password/MFA confirmation is required for
sensitive changes; public registration is closed. Sign-in uses a password plus
an authenticator or recovery code. Passkey entry and enrolment routes are disabled.
The interface uses self-hosted assets with a self-only content security policy.

## Safety boundaries

The UI is a separate, unprivileged service. WordPress administrators and CloudPanel
sessions do not implicitly grant Companion access. Operator credentials, MFA state,
notification secrets, registry and recovery data stay outside website roots.
Security Redis has its own private Unix socket, separate from WordPress object caches.

A serialized root coordinator accepts fixed actions for registered source/staging
pairs through a peer-UID-checked Unix socket. Browser requests cannot supply shell
commands, service names or arbitrary root filesystem paths. The coordinator retains
root identity with a reduced capability set; it is not an unprivileged sandbox.
PHP, WordPress CLI, code inventory and file transfer run as the relevant site owner.

Staging has an independent Unix identity, database, credentials, salts and URLs.
Its UID-scoped network policy blocks initiated connections, including loopback,
without flushing UFW or Fail2ban. Approved HTTPS tests use a constrained relay.
Postfix submission is denied separately. Application filters alone are insufficient
to enforce this isolation. This is not complete arbitrary-code sandboxing.

Refresh prepares a new files/database generation before switching staging. Durable
receipts, request draining, uncached health checks and recovery handle failed or
interrupted switches. Superseded generations are kept until the operator removes
them with `install.sh cleanup-staging` (or opts into the 6-hourly timer with
`install-operations.py --automatic-cleanup`). Removal always protects active state
and the latest two successful and two rolled-back generations. Initial provisioning is an operator task; it does not
create arbitrary public sites or DNS records from WordPress.

## Code releases

Comparison reads bounded theme/plugin folder inventories and SHA-256 hashes as
their owners. It does not execute PHP or expose file contents. Private artifacts,
links, special files and separately managed cache infrastructure cannot be released
through the picker. Exclusions remain visible. Only completed checks are published;
three recent comparison records are retained. Refresh/release/recovery invalidates
the old comparison instead of presenting it as current.

A folder review freezes its members and fingerprints both sides. Only changed files
enter the payload: a 6,000-file plugin with one edit produces a one-file release.
Final approval expires after ten minutes. Later source or target changes require a
new review, including changes to an originally unchanged file in a selected folder.

Limits: 50,000 fingerprinted files, 5,000 changed files per release, 8 MB per changed
file and 32 MB total payload. Comparison also has a 2 GB read and bounded time limit.
Large folders containing exclusions require eligible individual files to be selected.
The picker inventories code folders; standalone plugin files need separate deployment.

The database, uploads, credentials, staging settings and deletions are excluded.
This is a reviewed copy, not folder mirroring. Plugin updates that migrate database
schemas require a separate release plan. Never overwrite live orders or customers
with a staging database.

During apply, new requests briefly receive maintenance while existing requests drain.
PHP syntax is checked before writes. Recovery copies and write intents are durable;
uncached rendered-page checks and cache invalidation verify the result. Failure
restores previous code where safe. Recovery refuses to overwrite later edits and
retains conflicts for review. Files are replaced individually, not atomically as a
multi-file group. External code writers still require operator coordination.

## Monitoring and recovery

The private collector runs once a minute and retains seven days. It streams its
history into last-hour, 24-hour and 7-day exports; gaps stay gaps. The collector
follows both numbered rotations and CloudPanel's native dated log rotations.
Rotations that cannot be recovered are explicitly marked as incomplete.
Resource samples are not a function profiler. OPcache is read from web PHP, not CLI PHP. Worker
queues can be unavailable under saturation rather than being reported as zero.
A dedicated database account has USAGE only, with no customer-table access.

Nginx records coarse route groups, HTTP status, cache status and upstream header
time. It does not record visitor IPs, identities, raw URLs, arguments, cookies or
authorization values in this dedicated log. Static assets and own health probes
are excluded. Origin header timing includes upstream queueing and transport; it
is not pure PHP time or browser TTFB. p95 uses 10% histogram steps with 1 ms minimum
resolution. The public hit ratio includes HIT/MISS only; private bypasses remain
visible separately. Error groups count log entries, not unique incidents.

Graphs update without a full-page reload, preserve open details and pause while
the tab is hidden or the operator selects text. A failed refresh labels the last
snapshot explicitly. No history is fabricated before collection starts.

The standard-library probe engine supports explicit statuses, bounded deadlines,
validated TLS/SNI, a separate connect address, certificate-expiry warnings and
optional literal JSON fields for an uncached application/database check. A cached
homepage response alone does not establish WordPress or database health.

A website with a Cloudflare Origin CA certificate isn't trusted by the system
store. When setup is told so, it installs Cloudflare's Origin CA roots
(`assets/cloudflare-origin-ca.crt`) as `/etc/cloudpanel-companion/site-ca-HOST.crt`,
and every check that reaches the website through this server (origin and
application monitoring, release and cache-upgrade checks) verifies against that
file instead. Checks through Cloudflare's edge and of other hosts keep the system
store. Answering no removes the file and those checks go back to the system store.

Incident state and notification delivery are separate. Persistent outboxes retry
failed Slack deliveries. Delivery is at least once: a crash after webhook acceptance
can produce a duplicate with the same event identity. Service recovery is allowlisted,
requires two failed checks, has a five-minute cooldown and permits at most two restarts
per service per hour. Deliberately stopped services stay stopped.

The same service watch reads Rclone Automated Backups' schedule (`/etc/cron.d`) and
the success record each job writes after a successful run. A job whose latest
scheduled run has not succeeded within three hours becomes an incident on the same
outbox (Slack, when configured) and is listed on the Overview. Jobs created by
versions of the backup tool that write no success record must be recreated.

A monitor on the same machine cannot detect complete machine loss. Connect an
independent uptime observer and, where used, a monitored heartbeat. Inventory adapters
for other panels and automatic external heartbeat delivery are not complete features.

## Installation and persistence

`sudo bash install.sh` is the normal way to install, continue or update. It asks
its questions once (saved privately in `/etc/cloudpanel-companion/setup.json`),
checks which steps are already done and runs the component installers below in
this order. The individual installers stay available for operators who need one
step on its own; each has `--help`.

| Component | Installer run by `install.sh` |
|---|---|
| Monitoring services | `install-monitor.py`, explicit monitor/delivery configuration; optional `--site-host HOST --site-user USER --php VERSION` for history |
| HTTPS interface and authentication service | `install-web.py` and `requirements.txt` in a dedicated virtualenv |
| Initial isolated copy | `python3 -m companion.provision` with a private specification |
| Registered controls and retention | `install-operations.py --specification FILE --site ID` |
| External test relay | `install-relay.py` |
| Code release checks/routing | `install-deployment.py --registry FILE --site ID` |
| Varnish/controller integration | `install-cache.py` and Cache Manager for CloudPanel |
| Maintained Redis provider integration | `install-object-cache.py` |
| Application safeguards | `assets/cloudpanel-application-hardening.py`; read `docs/security-safeguards.md` |

`install.sh` also creates the Companion's reverse-proxy site and certificate with
`clpctl`, creates the first operator account (authenticator enrolment happens at
first sign-in) and generates the two native vhost texts that must be pasted into
CloudPanel's Vhost editor, because CloudPanel has no command for saving them.
Use CloudPanel's native Custom Domain for its management address.
The Companion uses a normal native Reverse Proxy site with its owned routing include.

Install the dedicated virtualenv and shared runtime with `install-web.py` first,
then install monitoring and the other selected components. Component installers
refuse a different or incomplete shared runtime; they never independently copy
Python modules. Endpoint export setup also works on a fresh host.

The package installer holds an exclusive admissions lock and refuses active jobs
or unresolved recoveries. It prepares and compiles the complete candidate before
stopping consumers, backs up accounts/configuration, exchanges runtime directories
atomically and restarts registered consumers before releasing admissions. Website
PHP, Nginx and its database stay running; cache-controller downtime falls back to
uncached PHP. Two complete package recovery sets are retained. Old content-hashed
assets remain available to existing browser tabs.

An interrupted update leaves a private receipt under
`/var/lib/cloudpanel-companion-updates`. From a reviewed release source, run
`python3 -m companion.package_install --recover RECORD_DIRECTORY --confirm` as the
operator. It validates recorded identities and restores the previous runtime,
managed files and stopped account database. Automatic recovery refuses completed
updates so later password/MFA changes cannot be silently reverted. Never remove
an unresolved receipt to bypass the installer guard.

Persist staging access, sensitive-file, cache and release-maintenance includes through
the **native saved Vhost template** using `companion.nginx_templates`. Editing generated
Nginx files alone is insufficient: ordinary PHP settings saves regenerate them. Native
settings-save acceptance has passed; future CloudPanel software updates still require
regression checks. Do not modify vendor application files to add menu or SSO hooks.

Request-timing collection needs the owned HTTP-level log-format file in
`sites-enabled/000-companion-observations.conf` and the printed public-vhost include
saved in the native template. CloudPanel does not load `conf.d` in the qualified
layout. Existing security, backend and PHP-setting placeholders must be retained.

## Disabling or retiring an installation

Stopping the independent interface and operations service does not stop WordPress.
Keep the cache controller, Redis and staging-isolation services if those website
features remain in use. They do not require a subscription or the web interface.

Full removal is a planned operator operation: retire staging through CloudPanel,
route the website directly to uncached PHP in its saved native template, disable
the matching WordPress integration, and remove only the owned service/drop-in
dependencies after checking the regenerated configuration. Keep needed Redis or
replace its provider deliberately. Never delete `/opt/cloudpanel-companion` while
PHP or registered service units still reference its isolation/cache code. There is
no destructive one-click uninstaller.

The hardening utility audits by default, records rollback data before writes and
requires an explicit planned PHP restart. It is not a complete WAF or firewall installer.
Protect actual management HTTPS domains as well as port 8443. Preserve a working SSH
session and provider-console recovery before changing access rules. SSH, firewall,
Fail2ban, OS updates, off-server backups and external monitoring remain explicit
operating responsibilities.

## Tests

On Linux, `python3 -m unittest discover -s tests -v` runs the standard-library suite.
Run `tests/test_deployment.py` as a non-root site identity with a root-owned PHP CLI;
root skips those tests and does not qualify their behavior. TLS tests need OpenSSL.

Inside the pinned web virtualenv, `python tests/run_web_checks.py` uses disposable
Redis/account state. Never point tests at operators' real MFA cache or account database.
Actual clone, refresh, interruption, release/recovery, privacy, cache and notification
acceptance must also run against an authorized disposable site. Unit tests alone do
not qualify customer integrations or a production migration.

## References

- [CloudPanel root CLI](https://www.cloudpanel.io/docs/v2/cloudpanel-cli/root-user-commands/)
- [CloudPanel site-user CLI](https://www.cloudpanel.io/docs/v2/cloudpanel-cli/site-user-commands/)
- [CloudPanel Varnish settings](https://www.cloudpanel.io/docs/v2/frontend-area/varnish-cache/settings/)
- [nftables reference](https://netfilter.org/projects/nftables/manpage.html)
- [Postfix submission controls](https://www.postfix.org/postconf.5.html#authorized_submit_users)
- [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
