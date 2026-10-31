## Optional server safeguards

`assets/cloudpanel-application-hardening.py` tightens a CloudPanel server that hosts your website and its staging copy. It is optional and separate from `install.sh`.

What it does:

- Stops website users from using `sudo`.
- Hides other users' processes from each website's PHP.
- Makes OPcache check file permissions (`99-companion-security.ini`).
- Tunes OPcache for the PHP version your sites use (`99-companion-performance.ini`): a 64 MB string buffer (CloudPanel's 8 MB fills up on a WooCommerce + Elementor site) and `opcache.enable_file_override`, so file-existence checks on cached scripts don't touch the disk. OPcache keeps checking file times every 2 seconds, so code changes still show up on their own. CloudPanel's other OPcache and realpath defaults are left as they are.
- Sets a PHP worker limit per site, keeps idle workers for 5 minutes instead of 10 seconds, and recycles them every 1,000 requests instead of 100.

These are server-wide PHP settings and pool settings that CloudPanel has no screen for. Per-site PHP values that CloudPanel does manage (memory limit, upload size, execution time) stay in Sites > the site > Settings.
- Optionally (`--production-egress-user`) stops the website from reaching private network addresses and cloud metadata, while keeping normal internet access.

It leaves CloudPanel's own PHP, SSH, firewall, Fail2ban and Cloudflare alone.

### How to use it

Check first. Without `--apply` it only reports what it would change:

```shell
cd cloudpanel-companion/assets
sudo python3 cloudpanel-application-hardening.py --site shop.example.com:shop:8.3:24 --site stg.example.com:shopstg:8.3:4
```

Each `--site` is `address:site-user:php-version:max-workers`. Pick the worker limit from measured memory: roughly the RAM you can give PHP divided by the memory one worker uses.

Then apply it in a quiet moment, because it restarts that PHP version:

```shell
sudo python3 cloudpanel-application-hardening.py --site shop.example.com:shop:8.3:24 --site stg.example.com:shopstg:8.3:4 --apply --restart-php-confirmed
```

It saves a rollback record under `/var/lib/cloudpanel-companion-hardening/` before writing, checks the result and restores the previous files if PHP fails to start.

After applying, run `sudo bash install.sh` again. It includes the new per-site security file in the website and staging routing texts you paste into CloudPanel (Sites > the site > Vhost), so it survives CloudPanel saves.

### Good to know

- This is not a firewall or a WAF. Keep using Cloudflare for that.
- If you restrict who can reach CloudPanel, restrict its real address on port 443 too, not only port 8443.
- HSTS for your website belongs to whatever ends the visitor's HTTPS connection. Behind Cloudflare's proxy, turn it on in Cloudflare (SSL/TLS > Edge Certificates); the Companion doesn't add a second copy. The Companion's own address already sends it.
- Before changing any access rules, keep an SSH session open and make sure you can reach your provider's web console.
