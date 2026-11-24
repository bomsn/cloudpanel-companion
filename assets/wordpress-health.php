<?php
// Read through the registered loopback FPM listener, never a public web route.
if (PHP_SAPI !== 'fpm-fcgi' || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403);
    exit;
}
$host = $_SERVER['SERVER_NAME'] ?? '';
$overdue = $_GET['overdue'] ?? '';
if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $host) || !ctype_digit($overdue)) {
    http_response_code(400);
    exit;
}
// Only the update information WordPress already cached is read. Nothing here
// contacts WordPress.org or changes the site. Output from the site's own code
// while it loads is discarded, so the response stays this report.
ob_start();
define('WP_USE_THEMES', false);
require __DIR__ . '/htdocs/' . $host . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
ob_end_clean();

$installed = get_plugins();
$checked = [];
$plugins = [];
$cache = get_site_transient('update_plugins');
$checked[] = $cache->last_checked ?? null;
foreach ((array) ($cache->response ?? []) as $file => $offer) {
    $offer = (object) $offer;
    $plugins[] = ['name' => (string) ($installed[$file]['Name'] ?? $file), 'version' => (string) ($installed[$file]['Version'] ?? ''),
                  'update' => (string) ($offer->new_version ?? ''), 'package' => !empty($offer->package)];
}
$themes = [];
$cache = get_site_transient('update_themes');
$checked[] = $cache->last_checked ?? null;
foreach ((array) ($cache->response ?? []) as $slug => $offer) {
    $offer = (array) $offer;
    $theme = wp_get_theme($slug);
    $themes[] = ['name' => (string) ($theme->exists() ? $theme->get('Name') : $slug), 'version' => (string) $theme->get('Version'),
                 'update' => (string) ($offer['new_version'] ?? ''), 'package' => !empty($offer['package'])];
}
$core = null;
$cache = get_site_transient('update_core');
$checked[] = $cache->last_checked ?? null;
foreach ((array) ($cache->updates ?? []) as $offer) {
    if (($offer->response ?? '') === 'upgrade') {
        $core = (string) $offer->current;
        break;
    }
}
// Events are keyed by the time they were due.
$late = time() - (int) $overdue;
$count = 0;
$oldest = null;
$hooks = [];
foreach ((array) _get_cron_array() as $due => $events) {
    if ((int) $due >= $late) {
        continue;
    }
    $oldest = min($oldest ?? (int) $due, (int) $due);
    foreach ((array) $events as $hook => $instances) {
        $count += count((array) $instances);
        $hooks[$hook] = ($hooks[$hook] ?? 0) + count((array) $instances);
    }
}
arsort($hooks);
header('Content-Type: application/json');
header('Cache-Control: private, no-store');
echo json_encode([
    'core' => ['version' => (string) get_bloginfo('version'), 'update' => $core],
    'plugins' => array_slice($plugins, 0, 100),
    'themes' => array_slice($themes, 0, 100),
    // The oldest of WordPress's own update checks; none until all three have run.
    'updates_checked' => in_array(null, $checked, true) ? null : (int) min($checked),
    'cron' => ['overdue' => $count, 'oldest' => $oldest, 'hooks' => (object) array_slice($hooks, 0, 5, true)],
], JSON_INVALID_UTF8_SUBSTITUTE);
