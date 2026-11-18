<?php
/** Blocked-request reports: what is sent, and which code it is attributed to. */
$root = sys_get_temp_dir() . '/companion-report-' . bin2hex(random_bytes(4));
define('ABSPATH', $root . '/');
define('WP_PLUGIN_DIR', $root . '/plugins');
define('WPMU_PLUGIN_DIR', $root . '/mu-plugins');

function wp_normalize_path($path) { return str_replace('\\', '/', $path); }
function trailingslashit($path) { return rtrim($path, '/') . '/'; }
function get_theme_root() { return ABSPATH . 'themes'; }
function wp_strip_all_tags($text) { return strip_tags($text); }
function get_plugins($folder) { return $folder === '/example-mailer' ? ['example-mailer.php' => ['Name' => 'Example <b>Mailer</b>']] : []; }
function get_file_data($file, $headers) { return ['Name' => 'Site Tools']; }
function wp_get_theme($slug) {
    return new class($slug) { public function __construct(private string $slug) {} public function get($key) { return 'Shop Theme'; } };
}

require dirname(__DIR__) . '/assets/staging-relay.php';

function expect(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$caller = <<<'PHP'
<?php
function %s($url) { return CloudPanelCompanionStagingRelay::blockedEntry('http', 'post', $url); }
PHP;
$files = [
    'plugins/example-mailer/includes/client.php' => 'from_plugin',
    'mu-plugins/site-tools.php' => 'from_mu_plugin',
    'themes/shop-theme/inc/api.php' => 'from_theme',
];
foreach ($files as $path => $function) {
    @mkdir(dirname($root . '/' . $path), 0700, true);
    file_put_contents($root . '/' . $path, sprintf($caller, $function));
    require $root . '/' . $path;
}

try {
    $entry = from_plugin('https://API.Example.com/v3.3/subscribers/abc.json?apikey=SECRET#fragment');
    expect($entry === ['kind' => 'http', 'source_type' => 'plugin', 'source' => 'example-mailer', 'label' => 'Example Mailer',
        'method' => 'POST', 'scheme' => 'https', 'host' => 'api.example.com', 'path' => '/v3.3/subscribers'], 'Plugin source, first two segments');
    expect(!str_contains(json_encode($entry), 'SECRET') && !str_contains(json_encode($entry), 'abc.json'), 'No query string or deeper path');
    expect(from_mu_plugin('https://example.com/hook')['source'] === 'site-tools', 'Must-use plugin source');
    expect(from_mu_plugin('https://example.com/hook')['label'] === 'Site Tools', 'Must-use plugin name');
    expect(from_theme('https://example.com/')['source_type'] === 'theme' && from_theme('https://example.com/')['path'] === '/', 'Theme source and root path');
    $core = CloudPanelCompanionStagingRelay::blockedEntry('http', 'GET', 'https://example.com/a');
    expect([$core['source_type'], $core['source'], $core['label']] === ['core', 'wordpress', 'WordPress'], 'WordPress itself');
    expect(from_plugin('https://example.com/api/../live/x')['path'] === '/api', 'Dot segments end the prefix');
    expect(from_plugin('https://example.com/a%2Fb/c')['path'] === '/', 'Encoded segments end the prefix');
    expect(from_plugin('https://example.com:8443/x')['host'] === 'example.com:8443', 'A non-standard port is kept');
    expect(from_plugin('https://example.com:443/x')['host'] === 'example.com', 'The standard port is dropped');
    expect(from_plugin('ftp://example.com/x') === null && from_plugin('not a url') === null, 'Only http and https are reported');
    CloudPanelCompanionStagingRelay::blocked('http', 'GET', 'https://example.com/x');
    echo "PASS: blocked-request reports: sources, path prefixes, no query strings, silent without a relay\n";
} finally {
    foreach (array_keys($files) as $path) {
        @unlink($root . '/' . $path);
    }
    exec('rm -rf ' . escapeshellarg($root));
}
