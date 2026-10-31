<?php
// Read through the registered loopback FPM listener, never a public web route.
if (PHP_SAPI !== 'fpm-fcgi' || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403);
    exit;
}
header('Content-Type: application/json');
header('Cache-Control: private, no-store');
$status = function_exists('opcache_get_status') ? opcache_get_status(false) : false;
echo json_encode($status ? [
    'available' => true,
    'opcache_used' => $status['memory_usage']['used_memory'],
    'opcache_free' => $status['memory_usage']['free_memory'],
    'opcache_restarts' => $status['opcache_statistics']['oom_restarts'] + $status['opcache_statistics']['hash_restarts'] + $status['opcache_statistics']['manual_restarts'],
] : ['available' => false]);
