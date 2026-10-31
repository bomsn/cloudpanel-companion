<?php
/** Read-only application probe. Provisioned at an unpredictable operator-owned URL. */
header('Cache-Control: private, no-store');
// Do not let an access-exempt health URL become a route for WordPress init
// handlers that accept query-string, POST or session-based mutations.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true) ||
    !empty($_SERVER['QUERY_STRING']) || !empty($_COOKIE) || !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    http_response_code(404);
    exit;
}
require __DIR__ . '/wp-load.php';
header('Content-Type: application/json');
header('Cache-Control: private, no-store');
header('X-Robots-Tag: noindex, nofollow, noarchive');
$ready = isset($wpdb) && (string) $wpdb->get_var('SELECT 1') === '1';
http_response_code($ready ? 200 : 503);
echo json_encode([
    'ready' => $ready,
    'database_identity' => hash('sha256', DB_NAME),
    'staging' => wp_get_environment_type() === 'staging',
    'timestamp_validation' => (bool) ini_get('opcache.validate_timestamps'),
    'revalidate_seconds' => (int) ini_get('opcache.revalidate_freq'),
]);
