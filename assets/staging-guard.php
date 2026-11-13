<?php
/**
 * Plugin Name: CloudPanel Companion Staging Guard
 * Description: Application safeguards for an isolated staging copy.
 * License: GPL-2.0-or-later
 */

if (!defined('ABSPATH')) {
    exit;
}

// The provisioner must establish these constants before WordPress loads. Fail
// closed when the guard has been copied without its matching staging config.
if (!defined('CLOUDPANEL_COMPANION_STAGING') || CLOUDPANEL_COMPANION_STAGING !== true ||
    !defined('DISABLE_WP_CRON') || DISABLE_WP_CRON !== true ||
    !defined('WP_ENVIRONMENT_TYPE') || WP_ENVIRONMENT_TYPE !== 'staging') {
    http_response_code(503);
    exit('Staging safeguards are not configured.');
}

require_once __DIR__ . '/staging-policy.php';
require_once __DIR__ . '/staging-relay.php';
$companionStagingPolicy = CloudPanelCompanionStagingPolicy::load();

add_filter('pre_wp_mail', static function ($pre, $attributes) use ($companionStagingPolicy) {
    return $companionStagingPolicy->allowsMail((array) $attributes)
        ? CloudPanelCompanionStagingRelay::mail((array) $attributes) : false;
}, PHP_INT_MAX, 2);

add_filter('http_request_args', static function ($args) {
    // Each destination is explicit; a permitted endpoint cannot redirect a
    // staging request to an unreviewed live endpoint.
    $args['redirection'] = 0;
    return $args;
}, PHP_INT_MAX);
add_filter('pre_http_request', static function ($pre, $args, $url) use ($companionStagingPolicy) {
    // Disposable cache acceptance can use only its own authenticated loopback
    // purge endpoint. Normal staging has no such exception or public cache.
    if (defined('CLOUDPANEL_COMPANION_CACHE_ACCEPTANCE') && CLOUDPANEL_COMPANION_CACHE_ACCEPTANCE === true &&
        defined('CACHE_MANAGER_FOR_CLOUDPANEL_ENABLED') && CACHE_MANAGER_FOR_CLOUDPANEL_ENABLED === true &&
        defined('CACHE_MANAGER_FOR_CLOUDPANEL_PORT') && is_int(CACHE_MANAGER_FOR_CLOUDPANEL_PORT) &&
        defined('CACHE_MANAGER_FOR_CLOUDPANEL_PURGE_KEY') &&
        $url === 'http://127.0.0.1:' . CACHE_MANAGER_FOR_CLOUDPANEL_PORT . '/' &&
        ($args['method'] ?? '') === 'PURGE' &&
        ($args['headers']['Host'] ?? '') === wp_parse_url(home_url('/'), PHP_URL_HOST) &&
        hash_equals(CACHE_MANAGER_FOR_CLOUDPANEL_PURGE_KEY, (string) ($args['headers']['X-Cache-Manager-For-CloudPanel-Key'] ?? ''))) {
        return $pre;
    }
    if (!$companionStagingPolicy->allowsHttp($url, $args['method'] ?? 'GET')) {
        return new WP_Error('companion_staging_network_blocked', 'This destination is not enabled in staging controls.');
    }
    return $pre === false ? CloudPanelCompanionStagingRelay::http($url, $args) : $pre;
}, PHP_INT_MAX, 3);

add_filter('woocommerce_webhook_should_deliver', static function ($deliver) use ($companionStagingPolicy) {
    return $deliver && $companionStagingPolicy->webhooksEnabled();
}, PHP_INT_MAX);
add_filter('action_scheduler_allow_async_request_runner', '__return_false', PHP_INT_MAX);
add_filter('woocommerce_payment_gateways', '__return_empty_array', PHP_INT_MAX);
add_filter('pre_option_blog_public', static function () { return '0'; }, PHP_INT_MAX);

add_action('send_headers', static function (): void {
    header('X-Robots-Tag: noindex, nofollow, noarchive', true);
    if (!defined('CLOUDPANEL_COMPANION_CACHE_ACCEPTANCE') || CLOUDPANEL_COMPANION_CACHE_ACCEPTANCE !== true) {
        header('Cache-Control: private, no-store', true);
    }
}, PHP_INT_MAX);
