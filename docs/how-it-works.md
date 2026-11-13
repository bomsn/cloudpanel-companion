# How CloudPanel Companion works

This is the detailed reference: what each part does, where it keeps its data, its
limits and the safety rules behind it. To install and use the Companion, start with
the [README](../README.md).

The Companion runs beside CloudPanel on its own HTTPS address. It never patches
CloudPanel's application, database or sign-in system. It is built and tested for one
WordPress or WooCommerce site on Ubuntu 24.04 with CloudPanel 2.5 and PHP 8.3. Before
moving a production site to it, try your own plugins and integrations on staging.

## Interface

Each page answers one question, with the most important answer first.

- **Overview: does anything need me?** A single alert lists every problem, worst
  first, each with an icon for what it is about (website, certificate, service, mail,
  disk, backups, updates) and a link to the exact section that explains it. Then come
  the server tiles (load, memory, disk and swap, each with a usage bar and its last 24
  hours), the website and certificate checks grouped by domain, the state of every
  watched service and scheduled job, and the scheduled backups. Stale or missing observations are shown as
  unavailable, never as healthy.
- **Monitoring: how is the server performing?** For the chosen period (last hour,
  24 hours or 7 days): traffic and errors, CPU, memory, response time and request
  charts with their average and peak, response times by page type, recurring errors and
  the latest PHP and database counters. Then the current state of disk growth, the mail
  queue, WordPress updates and every watched service, with scheduled jobs and recent
  changes. Services installed for the website (its private Redis, its staging email and
  test requests) come first under its domain; services the whole server shares follow
  by kind, under their products' own names, then the Companion's own services and jobs.
- **Security: who is signing in?** Problems first (a sign-in from a new source, a
  burst of failures). Then one card per panel (Companion, CloudPanel, SSH) with its
  24-hour counts; the chosen panel shows its last 7 days as daily bars, its sign-ins,
  its failed attempts grouped by source and, for the two web panels, visits per day,
  country and IP address. SSH also shows the firewall and Fail2ban. The Website card
  shows the bots that went looking for secret files, the addresses banned for it and
  other missing pages, with suggestions to copy into a Cloudflare rule.
- **Staging**, in three tabs. **Copy and access** shows the copy, its visitor access
  and the refresh, with step-by-step progress while a refresh runs. **External tests**
  approves test emails, HTTPS requests and WooCommerce webhooks; all three are off by
  default, and payments and background commerce jobs stay blocked. **Test inbox** shows
  captured emails as plain text, up to 50 messages and 8 MB.
- **Releases: what can I ship?** A review card for a prepared release, the changed
  theme and plugin folders with whole-folder or single-file selection, and the release
  history with recovery.
- **Account**: two-factor sign-in, password and other sessions.

Every visual has a text equivalent: status labels carry an icon and a word, never
colour alone, and each chart prints its values or range. Charts are drawn on the
server as inline SVG with no chart library, and the pages follow CloudPanel's layout
and colours so the two panels feel like one product. Everything is served from the
Companion itself under a strict content security policy: scripts and styles only from
its own files, no inline styles or scripts. Icons are from
[Lucide](https://lucide.dev/) (`companion_web/static/LUCIDE-LICENSE.txt`).
Brand icons are from [Simple Icons](https://simpleicons.org/) (CC0); the marks belong to their owners.

Changes that affect the live site or staging ask the operator to confirm access again,
with a password or, once enrolled, an authenticator code; that confirmation lasts five
minutes. Two-factor sign-in is optional, as in CloudPanel, and turning it off also
needs a fresh confirmation. Public registration, passkeys and email password resets
are switched off: the server operator creates accounts with
`sudo bash install.sh add-operator NAME`.

## Safety boundaries

**The interface has no special powers.** It runs as its own unprivileged service. Being
a WordPress administrator or signed in to CloudPanel gives no access to it. Operator
accounts, two-factor secrets, Slack settings and recovery data are kept outside every
website folder. Sign-in sessions and rate limits use a private Redis on its own Unix
socket, never the website's object cache.

**Root work goes through a fixed list of actions.** A root coordinator listens on a
Unix socket that only the interface may use, and accepts a fixed set of actions for the
registered website and staging pair, one at a time. A browser request can never pass
in a shell command, a service name or a file path. The coordinator keeps root identity
with reduced capabilities, so treat it as trusted code, not a sandbox. PHP, WP-CLI,
code comparison and file copies run as the site's own user.

**Staging is a separate site.** It has its own Unix user, database, passwords, salts
and URLs. Network rules for that user block every connection it starts, loopback
included, without touching UFW or Fail2ban. Approved HTTPS tests go through a narrow
relay, and Postfix refuses mail from staging separately. These rules, not WordPress
plugins, keep staging contained, but they are not a sandbox for arbitrary code.

**A refresh never leaves staging half-copied.** It prepares a complete new copy of the
files and database first, then switches over. It copies a busy site safely: short-lived
files that appear or change during the copy (WordPress writes some on every visit) are
skipped rather than failing it. Saved receipts, request draining,
uncached health checks and automatic recovery cover a failed or interrupted switch.
Earlier copies stay until you remove them with `sudo bash install.sh cleanup-staging`
(or turn on the 6-hourly cleanup with `install-operations.py --automatic-cleanup`).
Cleanup always keeps the active copy and the latest two successful and two rolled-back
copies. Creating staging is a server task: WordPress can't create sites or DNS records.

## Code releases

To find changes, the Companion lists the registered theme and plugin folders on both
sides and compares SHA-256 hashes, reading the files as their owners. It never runs
PHP or shows file contents. Private files, links, special files and the separately
managed cache code can't be released through the picker, but they stay visible as
exclusions. Only finished comparisons are shown, and the three latest are kept. A
refresh, release or recovery marks the previous comparison as out of date instead of
showing it as current.

Reviewing a folder freezes its list of files and fingerprints both sides. Only changed
files go into the release: a 6,000-file plugin with one edit gives a one-file release.
The final approval expires after ten minutes. If either side changes after the review,
including a file in a selected folder that was unchanged at first, you need a new review.

Limits: 50,000 fingerprinted files, 5,000 changed files per release, 8 MB per changed
file and 32 MB in total. A comparison also stops after reading 2 GB or after a set time.
In a large folder that contains exclusions, select the eligible files one by one. The
picker lists code folders only; a plugin that is a single file needs its own deployment.

The database, uploads, credentials, staging settings and deletions are never released.
A release is a reviewed copy, not a folder mirror. Plugin updates that change the
database schema need their own release plan. Never overwrite live orders or customers
with a staging database.

While a release applies, new requests briefly get a maintenance response and running
requests finish. PHP syntax is checked before anything is written. Recovery copies and
write intents are saved to disk, and uncached page checks and cache clearing confirm
the result. If something fails, the previous code is put back where that is safe.
Recovery never overwrites later edits; it keeps conflicts for you to review. Files are
replaced one by one, not as one atomic group, so coordinate with anything else that
writes code to the site.

## Page cache

Varnish keeps public pages for anonymous visitors. After content changes, Cache
Manager for CloudPanel asks the Companion's loopback controller to clear them,
authenticated with a per-site key. A whole-site clear activates a new VCL revision
before it answers, so a page rendered before the edit is never served afterwards.
A single-page clear bans that page's stored copies (both spellings of its
percent-escapes and, for a page given without a query, its query variants) and
repeats the ban about 70 seconds later, once any render begun before the edit has
been stored. When a ban cannot be relied on (Varnish refused it, or one site has
256 page clears awaiting their repeat), the controller clears the whole site
instead and its answer says so. A connection test (`OPTIONS`) checks the key and
Varnish without clearing anything. While the controller is stopped or a clear
fails, Nginx serves the site uncached from PHP.

## Monitoring and recovery

Performance history is recorded once a minute and kept for seven days, as last-hour,
24-hour and 7-day exports; gaps stay gaps. It follows both numbered log rotations and
CloudPanel's own dated ones, and marks rotations it cannot recover as incomplete. The
resource samples are not a function profiler. OPcache is read from the website's PHP,
not command-line PHP, including how much of its memory is wasted on replaced scripts
and whether it is full. When PHP is saturated, its worker queue can show as unavailable
rather than as zero. The database counters use a dedicated account with USAGE only,
which cannot read any customer table.

Nginx records coarse route groups, HTTP status, cache status and upstream header
time. It does not record visitor IPs, identities, raw URLs, arguments, cookies or
authorization values in this dedicated log. Static assets and own health probes
are excluded. Origin header timing includes upstream queueing and transport; it
is not pure PHP time or browser TTFB. Each page type's typical response (the median)
and slowest 5% count only requests the page cache did not answer, from 10% histogram
steps with 1 ms minimum resolution. Its cache share counts every request it received;
the public hit ratio includes HIT/MISS only. Error groups count log entries, not
unique incidents. Chart averages and peaks use the chart's own intervals.

The disk trend is a least-squares line through the week's free-space samples, so a
single staging copy or clean-up moves it little; it needs a day of samples and dates
a full disk only within a century. WordPress health is read hourly, not every minute:
an operator-owned probe in the website user's home (`assets/wordpress-health.php`)
runs through the website's own PHP pool over its loopback FastCGI port, as the website
user. It reads only what WordPress already cached from its own update checks (pending
core, plugin and theme updates, and offers with no package, typically an inactive
premium licence) and counts WP-Cron events more than an hour overdue. It never
contacts WordPress.org, installs anything or runs WP-CLI, and nothing runs WordPress
as root. The result is kept between runs and bounded to 100 entries per list.

The Monitoring page refreshes itself every minute without a full reload. It keeps
open sections open and pauses while the tab is hidden or text is selected. If a refresh
fails, the page says the values are the last loaded snapshot. Nothing is drawn for time
before collection started or for intervals that were not measured.

The Overview's 24-hour lines come from the same history. Usage bars turn amber at 80%
and red at 90%; the load bar compares the 1-minute load with the number of CPUs.

The standard-library probe engine supports explicit statuses, bounded deadlines,
validated TLS/SNI, a separate connect address, certificate-expiry warnings and
optional literal JSON fields for an uncached application/database check. A cached
homepage response alone does not establish WordPress or database health. Setup also
watches the certificates of the Companion's address and CloudPanel's custom domain
(from `web.json`) with certificate-only checks: a TLS handshake through this server,
with no page request, so the panels see no extra visits or sessions.

A website with a Cloudflare Origin CA certificate isn't trusted by the system
store. When setup is told so, it installs Cloudflare's Origin CA roots
(`assets/cloudflare-origin-ca.crt`) as `/etc/cloudpanel-companion/site-ca-HOST.crt`,
and every check that reaches the website through this server (origin and
application monitoring, release and cache-upgrade checks) verifies against that
file instead. Checks through Cloudflare's edge and of other hosts keep the system
store. Answering no removes the file and those checks go back to the system store.

**PHP-FPM and OPcache.** Setup owns the website PHP version's OPcache settings in
`/etc/php/VERSION/fpm/conf.d/99-companion-performance.ini`: 768 MB of memory, a 64 MB
string buffer (CloudPanel's 8 MB fills up on a WooCommerce and Elementor site), 100,000
script slots (a WooCommerce site caches about 15,000 scripts; CloudPanel's 1,000,000
cost memory for nothing) and `opcache.enable_file_override`. OPcache keeps checking
file times every 2 seconds, so code changes still show up on their own, and
`opcache.max_wasted_percentage` stays at PHP's default 5%. A graceful reload depends on
PHP-FPM's `process_control_timeout`, which CloudPanel's PHP packages already set to 10
seconds in `pool.d/global.conf` for every PHP version: a reload lets running requests
finish for up to 10 seconds instead of stopping them at once, from the very first
reload. The Companion does not set it a second time. Before any reload, setup and the
nightly check run `php-fpm -tt`; if PHP-FPM refuses its configuration or reports the timeout
as 0, setup puts the previous file back and stops, and the nightly check does not reload.
PHP-FPM's own reload does not test the configuration first, so a file it refuses would
stop PHP.

When a script changes, OPcache compiles it again and only marks the old copy as
wasted; PHP frees that memory by restarting OPcache only when memory is full and more
than 5% is wasted, at whatever hour that happens. The nightly OPcache check
(`companion-opcache-upkeep.timer`, 04:30 server time by default; setup asks) reads the
website pool's OPcache through the same diagnostic performance history uses, and reloads PHP-FPM
gracefully only when 10% or more is wasted or OPcache is full. Otherwise it changes
nothing. It never reloads while a staging refresh, a release or a staging cleanup runs:
it takes each site's workflow lock first, and skips the night if one is held. A missed
night is skipped, never caught up at a busy hour. Monitoring shows the waste, the cached
scripts and what the last check found and did.

**Alert messages.** Every Slack message, from website and certificate checks, service
checks and sign-in and visit history alike, is laid out in one place (`companion/delivery.py`). It
starts with the server (its name and public address) and the website, then the event,
then its details and the event's time and identity. The server's name and address are
detected once during setup (the address is the one the server uses to reach the
internet, when it is public) and can be changed with `--reconfigure`; they are kept with
the website's domain in `/etc/cloudpanel-companion/alert-context.json`, which every
delivery service can read and which holds no secret. The Slack webhook stays in the
root-only `slack.json`, reaches the sending process only on its standard input and
never appears in logs, errors or the interface.

Incident state and notification delivery are separate. Persistent outboxes retry
failed Slack deliveries. Delivery is at least once: a crash after webhook acceptance
can produce a duplicate with the same event identity. Service recovery is allowlisted,
requires two failed checks, has a five-minute cooldown and permits at most two restarts
per service per hour. Deliberately stopped services stay stopped.

Service checks read each unit's load state too, so a registered unit that is no
longer installed is reported as not installed rather than stopped, and a long-running
service shows since when it has been in its state. The package's timers are observed
as scheduled jobs: the last run of their oneshot service, its result (or a skip when
its condition, such as Slack being set up, is not met) and the next run. A failed run
alerts like a failed service; there is nothing to restart, since the timer runs it
again. A timer that is enabled but no longer scheduled alerts too; one switched off on
purpose, like staging cleanup by default, is shown as off.

They also read Postfix's queue (`postqueue -j`, Postfix 3.1 and later) once a
minute: only how many messages wait and when the oldest arrived, never recipients,
senders or contents. Mail still queued after an hour, or a queue that cannot be read,
alerts like a failed service.

The same checks read Rclone Automated Backups' schedule (`/etc/cron.d`) and
the success record each job writes after a successful run. A job whose latest
scheduled run has not succeeded within three hours becomes an incident on the same
outbox (Slack, when configured) and is listed on the Overview. Jobs created by
versions of the backup tool that write no success record must be recreated.

A monitor on the same machine cannot see the whole machine go down. Use an
independent uptime monitor as well.

## Sign-in and visit history

**Which address is believed.** CloudPanel's `nginx.conf` trusts every IPv4 peer to
rewrite the client address (`set_real_ip_from 0.0.0.0/0` with the default
`real_ip_header X-Real-IP`), so Nginx's `$remote_addr` is whatever a client puts in an
`X-Real-IP` header. The Companion never reads it. Its HTTP-level rules
(`sites-enabled/000-companion-security.conf`, generated by `companion/client_address.py`
from `assets/cloudflare-ips.txt`) look at the connecting peer (`$realip_remote_addr`):
only when that peer is in Cloudflare's published ranges are `CF-Connecting-IP` and
`CF-IPCountry` believed. Any other request is recorded with the peer address and an
unknown country. The interface's routing include forwards only this decided address
(as `X-Forwarded-For`, which allauth's rate limits also use) and country, and strips
Cloudflare's own headers, so a forged `X-Forwarded-For`, `X-Real-IP` or
`CF-Connecting-IP` changes nothing.

**The website's visitor address.** The same rule applies to the website and staging,
so WordPress and WooCommerce record the real visitor. Their vhosts include two files
that `install-web.py` writes:

- `/etc/cloudpanel-companion/client-address-public.conf`, in the public server block
  and the `www` redirect block: `set_real_ip_from` for each Cloudflare range,
  `real_ip_header CF-Connecting-IP;` and `real_ip_recursive off;`. A request from
  Cloudflare is recorded as the visitor Cloudflare names. Any other request is recorded
  as the address it came from, and its `X-Real-IP`, `X-Forwarded-For` and
  `CF-Connecting-IP` headers are ignored. That is also what happens if you stop using
  Cloudflare, since visitors then connect directly.
- `/etc/cloudpanel-companion/client-address-backend.conf`, in the 8080 PHP backend
  block: `set_real_ip_from 127.0.0.1;`, `set_real_ip_from ::1;` and
  `real_ip_header X-Real-IP;`. Only the public block and Varnish reach the backend,
  over loopback. The public block sets `X-Real-IP` to the address it decided, and
  Varnish passes it on unchanged, so PHP gets that address as `REMOTE_ADDR`. A request
  that reaches port 8080 from anywhere else keeps its own address.

A `set_real_ip_from` in a server block replaces the list from `nginx.conf` for that
block, so CloudPanel's trust in every peer no longer applies there. CloudPanel's own
files are not changed. The includes are added to the saved vhost texts that setup asks
you to paste (`companion.nginx_templates`). After updating from a release without them,
`sudo bash install.sh status` shows "Save the website's vhost in CloudPanel" and "Save
the staging vhost in CloudPanel" as to do again, and `sudo bash install.sh` writes the files and then
prints the texts to paste. Until you save them, the site keeps CloudPanel's behaviour.

**Updating the Cloudflare list.** The ranges are in `assets/cloudflare-ips.txt`, with
their source and the refresh command at the top. Replace the ranges in your checkout
and run `sudo bash install.sh`. It sees the changed file, reinstalls the interface,
and regenerates `000-companion-security.conf` and both includes from the list, then
tests and reloads Nginx. If the test fails, the previous files are put back. The vhosts
don't need pasting again for a list change.

**Where each entry comes from.**

| Panel | Successful sign-ins | Failed attempts | Visits |
|---|---|---|---|
| Companion | allauth's `user_logged_in` signal, with whether a two-factor code was used | Django's `user_login_failed` and allauth's MFA `authentication_failed` signals | The interface's private access log |
| CloudPanel | CloudPanel's own `LOGIN` records (read-only), with the address from the matching access-log line | A password POST to `/login` redirected back to `/login`, or a code POST to `/login/mfa` answered with the form again | CloudPanel's private access log |
| SSH | sshd's `Accepted` journal entries | `Invalid user`, `Failed ...` and pre-authentication disconnects, once per connection | Not applicable; Fail2ban bans and the firewall state are shown instead |

The interface records its own sign-ins in its database: time, user name, address,
country, a short browser label ("Firefox 133 on Windows") and the two-factor step. No
password and no full user agent is stored. A rejected password keeps the name that was
tried only when it is an existing account's (case as the account spells it); any other
name is recorded as "no account name", because it may be a password typed into the name
field. SSH keeps the names a failed connection tried, as sshd itself logs them: an SSH
client sends the name from its command line or configuration rather than a prompt, the
servers this is run on refuse password sign-in over SSH, and the names attackers guess
show what they aim at. Everything else is read once a minute by
`companion-security-log.service`, a root collector that keeps a root-only database
(`/var/lib/cloudpanel-companion-security-log`) and writes one bounded export the
interface reads. The interface never reads CloudPanel's database, the journal or a log.

CloudPanel records the address its own Nginx saw, which behind Cloudflare is a
Cloudflare server (or a client-chosen `X-Real-IP`). The collector therefore takes the
address of a CloudPanel sign-in from the access-log line within ten seconds of it; a
record with no matching line keeps CloudPanel's address, is shown as unverified and
is never judged a new source. Sign-ins made directly on port 8443 bypass the panel's
custom domain and its log; close that port once the custom domain is in use. CloudPanel
records the sign-in when the password is accepted, before any code step; its two-factor
column shows whether the account must enter a code to finish.

**The private access logs.** Both panels write
`/var/log/cloudpanel-companion/{companion,cloudpanel}-access.log` (root only, rotated
daily, three files kept) in one format: time, decided address, country, method, a path
class (sign-in, code or other), status and where a redirect leads (back to sign-in,
the code page or elsewhere). No URL, query string, cookie, body or user agent is
written; images, scripts and stylesheets are not logged. CloudPanel's custom-domain
vhost ships with its access log commented out, so `install-security.py` adds one
`include /etc/cloudpanel-companion/cloudpanel-access.conf;` line after its
`server_name`, tests Nginx and restores the file if the test fails. CloudPanel rewrites
that vhost when its custom domain or certificate changes; the Security page then says
the log is disconnected, and `sudo bash install.sh` adds the line again.

**New sources, bursts and alerts.** A successful sign-in from an IP address, or a
Cloudflare country, not seen for that panel in the previous 90 days is marked new; the
first recorded sign-in sets the baseline. A burst is 10 failed attempts within ten
minutes on the Companion or CloudPanel, or 60 on SSH, which meets constant
internet-wide guessing that Fail2ban already answers. With Slack configured, every
successful sign-in to CloudPanel and to the Companion sends an alert through the system
incident outbox, marked when it comes from a new IP address or country. An SSH sign-in
alerts once per user and address within 24 hours, because automation reconnects often;
a new address is by definition one not seen that day. Each sign-in alert names the
account, the address, the country (not known for SSH), the method (SSH key or password;
for the panels, whether a two-factor code was needed), the browser and the time; a
CloudPanel sign-in whose address is CloudPanel's own record is marked unverified and
never called new. A panel alerts about bursts at most once every six hours, and entries
older than an hour when first read (history caught up after installation) are
highlighted but never alerted. At most 20 security alerts are sent in an hour; past
that, one message says the rest are held back, and the Security page still lists every
event. The interface cannot reach Slack: it writes an alert's fields to a private spool
in its state directory, and the collector validates them and words the message itself.

Entries are deleted after 90 days, and every table is bounded: 100,000 collector
entries, 20,000 interface entries, 1,000 visiting addresses per panel and day (more
are counted together, without an address), and an hour of the helper records that match
CloudPanel sign-ins and count each SSH connection once. The collector cuts every table
back to these bounds before it adds anything, and its database refuses to grow past
128 MiB; the largest these bounds allow (with the blocked scan counts below), with IPv6
addresses and the longest names, is about 87 MiB, so a full database cannot happen in
normal use and would free its own
space on the next run. Reading the journal and the mail queue each has its own deadline
(20 and 10 seconds), well inside the collectors' service time limits.

**What the installers change on the server.** `install-web.py` writes
`/etc/nginx/sites-enabled/000-companion-security.conf` (the address rules and the log
format), the website's two address includes in `/etc/cloudpanel-companion`,
`/etc/logrotate.d/cloudpanel-companion-access`, the log directory
`/var/log/cloudpanel-companion` (root, mode 0750) and the interface's routing include,
then tests and reloads Nginx; its database migration adds the sign-in table to the
interface's existing account database. `install-security.py` installs
`companion-security-log.service` and its timer, the export directory
`/var/lib/cloudpanel-companion-security-log-observations` (root, readable by the
interface's group), `/etc/cloudpanel-companion/cloudpanel-access.conf` and the one
`include` line in CloudPanel's `/etc/nginx/sites-enabled/custom-domain.conf`, keeping
that file's owner and mode. A vhost with an unexpected layout (not one server block with
CloudPanel's `server_name` line, or a second copy of the include) is left unchanged rather
than guessed at: the collector is installed anyway, the Security page shows CloudPanel's
log as not connected, and setup carries on and lists "Log CloudPanel sign-ins and
visits" as still to do, with the reason. The collector's database lives in
`/var/lib/cloudpanel-companion-security-log` (root only); the interface's alert spool is
`security-alerts` in its own state directory.

## Blocking bots that scan for secret files

Bots constantly ask websites for files that are never public: `/.env`, `/.git/config`,
`/backup.sql`, `/wp-config.php.bak`, `/terraform.tfstate` and many more. Before scan
blocking, many of those requests reached WordPress, which started up for each one only to
answer "not found" (about a third of a second of CPU each). One address sending them
at 30 to 50 a second was enough to fill every CPU and slow real visitors down.

**What counts as a scan.** One list in `companion/probe_guard.py` decides, matching
the request path Nginx has already decoded and cleaned up, without the query string
and regardless of case:

- dotfiles and dot folders anywhere, except `/.well-known/`;
- every `wp-config` file name with a dot in it (`wp-config.php`, `wp-config.php.bak`,
  `wp-config.txt` and so on). WordPress slugs never contain a dot, so a post called
  `/wp-config-explained/` is not one;
- backups, dumps and editor swap files: `.bak`, `.backup`, `.old`, `.orig`, `.save`,
  `.sav`, `.swp`, `.swo`, `.dump`;
- configuration, secrets and keys: `.env`, `.ini`, `.conf`, `.cfg`, `.log`, `.yml`,
  `.yaml`, `.toml`, `.tfvars`, `.tfstate`, `.py`, `.sh`, `.pem`, `.key`, `.ppk`, `.sql`,
  `.sqlite`, `.sqlite3`;
- at the web root only: `kubeconfig`, `railway.json`, `composer.json`, `composer.lock`,
  `package.json` and `package-lock.json`;
- archives at the web root only (`.zip`, `.rar`, `.7z`, `.tar`, `.tgz`, `.gz`, `.bz2`,
  `.xz`, `.zst`), and only when the file does not exist: a real download at the root
  is still served. A missing archive gets its 404 and shows on the Security page, but it
  never counts towards a ban, because a customer could follow a dead download link.

Never a scan: any path through `wp-content`, `wp-includes`, `wp-admin` or `wp-json`, at
any depth (WordPress in a folder or a multisite too), and REST requests by
`?rest_route=`, since the query is not part of the path. Plugins and themes ship files
of every kind, and a page can make every visitor's browser ask for a broken asset path
such as `/wp-content/plugins/NAME/dist/.min.js`; counting those would ban real visitors.
Also never a scan: `/.well-known/`, `wp-login.php`, `wp-cron.php`, `xmlrpc.php`, sitemaps
(`.xml` and `.xml.gz`), `robots.txt`, `llms.txt`, WooCommerce's pages and endpoints, and
ordinary missing pages. In WordPress's folders, the files the safeguards always hid
(dotfiles and `.sql`, `.sqlite`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, `.env`, `.ini`,
`.log`, `/wp-content/debug.log` among them) still get a 404, but are never logged or
counted. `/graphql` is left
out: whether it is a scan depends on whether the WPGraphQL plugin is active, which
can change at any time, so it shows up under other missing pages instead.

**What happens to a scan.** `/etc/nginx/sites-enabled/000-companion-probes.conf`
holds the list as an Nginx `map`. The website's and staging's security file,
`/etc/cloudpanel-companion/sites/USER-security.conf`, is already included in both of
their server blocks, so setup only rewrites that file and no vhost needs pasting
again. In it, a scan gets a plain 404 from Nginx, before Varnish and PHP. It is never
a 444 (closing the connection without an answer), because Cloudflare turns that into
a 520 error page. Each scan is also written to `/var/log/cloudpanel-companion/probes.log`
(root only, rotated daily, kept for a week): the time, the visitor address (decided at
HTTP level by `000-companion-security.conf`: CF-Connecting-IP only from a Cloudflare
edge, otherwise the connecting address), the Cloudflare edge it came through, the country Cloudflare
reported, the site, the method, the path without its query string, the status and the
user agent. The same security file keeps the safeguards it held before: links to other
users' files are not followed, PHP files under uploads, cache and upgrade folders are
refused, and backup plugin folders are closed. It also adds
`location ^~ /wp-content/uploads/woocommerce_uploads/ { internal; }`, so WooCommerce's
private downloads can only be handed out by WooCommerce itself (its X-Accel-Redirect
and Force downloads methods). A store that uses WooCommerce's "Redirect only" download
method, which needs those files to be public, should switch to one of the other two.

**Bans.** A Fail2ban jail, `companion-probes`, reads only that scan log, never the
website's ordinary 404s, so a visitor following an old link is never counted. Three
scans from one address within an hour ban it for 24 hours. Each new ban of the same
address lasts twice as long as the one before, up to a week; Fail2ban keeps 30 days of
ban history (`dbpurgeage` in `/etc/fail2ban/fail2ban.d/cloudpanel-companion.conf`) so it
can recognise repeat offenders. Ubuntu tells Fail2ban to read the journal by default,
so the jail names its own log-file backend.

A scan is counted only when its address is certain: a Cloudflare edge naming the
visitor, or a direct visitor naming no one. A request that carries CF-Connecting-IP but
does not come from a listed Cloudflare range is forged, or comes through a range
`assets/cloudflare-ips.txt` does not list yet; it gets its 404 and is never counted.

All of the website's traffic arrives through Cloudflare, so a firewall ban would block
nothing: the connecting address is always a Cloudflare server. The ban is enforced in
Nginx instead, on that same visitor address. It does not depend on a vhost's own realip
rules, so a vhost saved before the client-address includes cannot be talked into
banning someone else with an `X-Real-IP` header. Fail2ban's action
(`/etc/fail2ban/action.d/companion-nginx-ban.conf`) records the banned addresses in
`/var/lib/cloudpanel-companion-probe-guard/banned.json` and starts
`companion-probe-reload.service`. That job waits five seconds, so a wave of bans joins
one run, writes the Nginx ban list (`banned.conf`, a `geo` list included by
`000-companion-probes.conf`), tests the whole configuration with `nginx -t` and reloads
Nginx gracefully. If the test or the reload fails, the previous list is put back. A
banned address gets a 403 for every request to the website and staging; the Companion's
own address and CloudPanel are not affected, so a banned operator can still reach both. When
a ban ends, Fail2ban's unban updates the list the same way. Stopping Fail2ban lifts its
bans and starting it restores the ones still running; the list itself survives Nginx
restarts. A systemd drop-in creates the scan log before Fail2ban starts if it is ever
missing, because Fail2ban refuses to start at all, SSH jail included, while one jail's
log is missing.

Never banned, whatever the jail asks: loopback, every address on the server's own
interfaces, every Cloudflare range in `assets/cloudflare-ips.txt` (a guard in case the
address rules were ever wrong) and the addresses you give setup ("Addresses never to
ban", empty by default, kept in `/etc/cloudpanel-companion/probe-guard.json`). The jail
ignores them too, and the action refuses them again. Requests whose user agent says
they come from a search engine crawler (Googlebot, Bingbot, Applebot and others) or an
uptime monitor (UptimeRobot, Pingdom, StatusCake and others) still get their 404 but
are never counted. A bot that pretends to be one only avoids the ban.

`sudo fail2ban-client status companion-probes` lists the current bans,
`sudo fail2ban-client get companion-probes banip --with-time` adds when each ends, and
`sudo fail2ban-client set companion-probes unbanip ADDRESS` lifts one at once.

**What it tells you.** Sign-in and visit history reads the scan log, the website's own
access log and the jail's current bans every minute, and keeps per-day counts for 90
days: at most 200 distinct paths and 200 addresses a day for scans, and the same for
missing pages (the rest are counted together), and up to 10,000 bans. The Security
page's Website tab shows blocked scans per day for the last 7 days, the most requested
files and the addresses asking for them with their countries, current bans with their end
and the bans of the last 7 days, and **Other missing pages**: 404s from the website's
access log that were not blocked as scans (WordPress answered a page; a
missing `.php` file is answered by the PHP server block without starting WordPress).
Those are the candidates for a new scan pattern or a manual Cloudflare rule.
**Cloudflare rule suggestions** turns both lists into Cloudflare rule-language conditions to review
and copy, such as `http.request.uri.path contains "/.env"` or
`http.request.uri.path.extension eq "sql"`, each leaving WordPress's folders alone as
scan blocking does, with every condition joined into one expression. Not-found pages are listed
by their exact path, never widened into a pattern that could match real pages. Nothing is sent to Cloudflare: the server has no
Cloudflare token and never calls its API.

## Installation and persistence

`sudo bash install.sh` is the normal way to install, continue or update. It asks
its questions once (saved privately in `/etc/cloudpanel-companion/setup.json`),
checks which steps are already done and runs the component installers below in
this order. The individual installers stay available for operators who need one
step on its own; each has `--help`.

| Component | Installer run by `install.sh` |
|---|---|
| Fail2ban's SSH jail on every SSH port | `companion/ssh_jail.py`, run by `install.sh` itself; it writes `/etc/fail2ban/jail.d/companion-sshd.conf` only when Fail2ban's own settings miss a port SSH listens on |
| Companion services and sign-in | `install-web.py` and `requirements.txt` in a dedicated virtualenv |
| Staging copy | `python3 -m companion.provision` with a private specification |
| Staging controls and cleanup | `install-operations.py --specification FILE --site ID` |
| Staging email capture and test requests | `install-relay.py` |
| Code releases | `install-deployment.py --registry FILE --site ID` |
| Page cache | `install-cache.py` and Cache Manager for CloudPanel |
| Object cache | `install-object-cache.py` |
| Monitoring | `install-monitor.py`; add `--site-host HOST --site-user USER --php VERSION` for performance history |
| Sign-in and visit history and CloudPanel's access log | `install-security.py --panel-host HOST` |
| Scan blocking and its Fail2ban jail | `install-probe-guard.py --site-user USER [--staging-user USER] [--allow ADDRESS]` |
| OPcache settings and the nightly OPcache check | `install-php-runtime.py --php VERSION [--upkeep-time HH:MM]` |
| Application safeguards | `assets/cloudpanel-application-hardening.py`; read `docs/security-safeguards.md` |

`install.sh` also creates the Companion's reverse-proxy site and certificate with
`clpctl`, creates the first operator account (each operator can turn on two-factor
sign-in from their account menu) and writes the vhost texts to paste into CloudPanel's
Vhost editor, because CloudPanel has no command for saving them. Use CloudPanel's own
Custom Domain setting for its management address. The Companion's address is an
ordinary CloudPanel reverse-proxy site with the Companion's routing include.

When you run installers by hand, run `install-web.py` first: it installs the dedicated
virtualenv and the shared runtime. Then install monitoring and the other components you
want. The component installers refuse a different or incomplete shared runtime and
never copy Python modules on their own. Monitoring's website checks can also be set up
on a fresh server.

An update holds an exclusive lock and refuses to start while a job is running or a
recovery is unresolved. It prepares and compiles the complete new version before
stopping anything, backs up accounts and configuration, swaps the runtime directories
atomically and restarts the registered services before accepting new work again. The
website's PHP, Nginx and database keep running; while the cache controller is down,
the website is served uncached from PHP. The two latest package recovery sets are
kept, and old content-hashed assets stay available to browser tabs that are already open.

An interrupted update leaves a private receipt under
`/var/lib/cloudpanel-companion-updates`. From a reviewed release, run
`python3 -m companion.package_install --recover RECORD_DIRECTORY --confirm` as the
server operator. It checks the recorded identities and restores the previous runtime,
managed files and the account database as it was when the update stopped it. It
refuses to roll back a completed update, so later password or two-factor changes are
never silently undone. Never remove an unresolved receipt to get past the installer's
check.

The staging access, sensitive-file, cache and release-maintenance includes last only
when they are in the site's **saved vhost in CloudPanel** (`companion.nginx_templates`
builds that text). Editing the generated Nginx files alone is not enough: an ordinary
PHP settings save regenerates them. Saving PHP settings in CloudPanel has been tested
with these includes; check again after future CloudPanel updates. Do not modify
CloudPanel's application files to add menus or single sign-on.

Request timing needs the Companion's log-format file,
`sites-enabled/000-companion-observations.conf`, and the include that `install-monitor.py`
prints, saved in the website's vhost. CloudPanel does not load `conf.d` in the tested
layout. Keep the vhost's existing security, backend and PHP-setting placeholders.

## Disabling or retiring an installation

Stopping the Companion's interface and operations service does not stop WordPress.
Keep the cache controller, Redis and staging isolation services running while the
website still uses those features; they need neither a subscription nor the interface.

Removing everything is a planned job: retire staging in CloudPanel, route the website
straight to uncached PHP in its saved vhost, turn off the matching WordPress
integration, and only then remove the Companion's own services and drop-ins, checking
the regenerated configuration as you go. Nginx refuses a configuration that names a
missing file or variable, so remove the Companion's `include` line from CloudPanel's
custom-domain vhost before deleting `/etc/cloudpanel-companion/cloudpanel-access.conf`,
the `client-address-*.conf` lines from the website's and staging's vhosts before those
two files, the `USER-security.conf` lines before `000-companion-probes.conf` (whose
variables they use), and the interface's site (whose routing include uses its
variables) before `000-companion-security.conf`. Remove
`/etc/fail2ban/jail.d/companion-probes.conf` and restart Fail2ban to end the scan bans.
Keep Redis if the website needs it, or replace its provider deliberately. Never delete
`/opt/cloudpanel-companion` while PHP or registered services still use its isolation
or cache code. There is no one-click uninstaller.

The hardening tool only reports by default, saves rollback data before it writes and
needs an explicit, planned PHP restart. It is not a complete WAF or firewall installer.
Protect the real management HTTPS addresses as well as port 8443. Keep a working SSH
session and your provider's web console at hand before changing access rules. SSH, the
firewall, Fail2ban, OS updates, off-server backups and external monitoring stay your
responsibility.

## Tests

On Linux, `python3 -m unittest discover -s tests -v` runs the standard-library suite.
Run `tests/test_deployment.py` as a non-root site user with a root-owned PHP CLI; as
root those tests are skipped and prove nothing. TLS tests need OpenSSL.

Inside the web virtualenv, `python tests/run_web_checks.py` uses throwaway Redis and
account state. Never point tests at real operators' two-factor cache or account
database. Cloning, refresh, interruption, release and recovery, privacy, cache and
notification behaviour must also be tested on an authorised disposable site. Unit
tests alone don't show that customer integrations or a production migration will work.

## References

- [CloudPanel root CLI](https://www.cloudpanel.io/docs/v2/cloudpanel-cli/root-user-commands/)
- [CloudPanel site-user CLI](https://www.cloudpanel.io/docs/v2/cloudpanel-cli/site-user-commands/)
- [CloudPanel Varnish settings](https://www.cloudpanel.io/docs/v2/frontend-area/varnish-cache/settings/)
- [nftables reference](https://netfilter.org/projects/nftables/manpage.html)
- [Postfix submission controls](https://www.postfix.org/postconf.5.html#authorized_submit_users)
- [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
