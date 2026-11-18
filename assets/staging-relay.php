<?php
/** Bounded client for the separately isolated staging transport. */
final class CloudPanelCompanionStagingRelay
{
    /** @var array<string, true> Destinations already reported during this PHP request. */
    private static array $reported = [];

    /** @var array<string, string> Display names of sources found during this PHP request. */
    private static array $labels = [];
    /** @param float $timeout Seconds to wait for the relay; a report waits briefly, a test request longer. */
    private static function call(array $request, float $timeout = 20.0): array
    {
        $path = defined('CLOUDPANEL_COMPANION_STAGING_RELAY') ? CLOUDPANEL_COMPANION_STAGING_RELAY : '';
        if (!is_string($path) || !preg_match('~^/run/cloudpanel-companion-relay/[a-z][a-z0-9-]{2,30}/transport\.sock$~D', $path)) {
            throw new RuntimeException('Staging transport is not configured.');
        }
        $encoded = json_encode($request, JSON_THROW_ON_ERROR) . "\n";
        if (strlen($encoded) > 1048576) {
            throw new RuntimeException('The staging test request exceeds the size limit.');
        }
        $connection = @stream_socket_client('unix://' . $path, $errno, $error, min(2.0, $timeout));
        if (!$connection) {
            throw new RuntimeException('Staging transport is unavailable.');
        }
        try {
            stream_set_timeout($connection, (int) $timeout, (int) (fmod($timeout, 1.0) * 1000000));
            $offset = 0;
            while ($offset < strlen($encoded)) {
                $written = fwrite($connection, substr($encoded, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Staging transport could not receive this request.');
                }
                $offset += $written;
            }
            $raw = fgets($connection, 4194306);
            if (!is_string($raw) || strlen($raw) > 4194304 || !str_ends_with($raw, "\n")) {
                throw new RuntimeException('Staging transport returned an invalid response.');
            }
            $response = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (($response['ok'] ?? false) !== true || !is_array($response['result'] ?? null)) {
                throw new RuntimeException('This test request was blocked or could not complete.');
            }
            return $response['result'];
        } finally {
            fclose($connection);
        }
    }

    public static function http(string $url, array $arguments): array|WP_Error
    {
        try {
            if (isset($arguments['stream']) && $arguments['stream']) {
                throw new RuntimeException('File-streaming requests are not supported by the staging relay.');
            }
            $headers = $arguments['headers'] ?? [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers = $headers->getAll();
            }
            if (!is_array($headers)) {
                throw new RuntimeException('Use structured request headers for staging tests.');
            }
            $body = $arguments['body'] ?? '';
            if (is_array($body)) {
                $body = http_build_query($body, '', '&');
                if (!array_filter(array_keys($headers), static fn($name) => strtolower((string) $name) === 'content-type')) {
                    $headers['Content-Type'] = 'application/x-www-form-urlencoded';
                }
            }
            if (!is_string($body)) {
                throw new RuntimeException('Unsupported staging request body.');
            }
            $result = self::call(['operation' => 'http', 'url' => $url,
                'method' => strtoupper($arguments['method'] ?? 'GET'), 'headers' => (object) $headers,
                'body' => base64_encode($body)]);
            $body = base64_decode($result['body'], true);
            if (!is_string($body)) {
                throw new RuntimeException('Invalid staging response body.');
            }
            $headers = [];
            $cookies = [];
            foreach ($result['headers'] as [$name, $value]) {
                $key = strtolower($name);
                if ($key === 'set-cookie') {
                    $cookies[] = new WP_Http_Cookie($value, $url);
                }
                $headers[$key] = isset($headers[$key]) ? $headers[$key] . ', ' . $value : $value;
            }
            return ['headers' => new \WpOrg\Requests\Utility\CaseInsensitiveDictionary($headers),
                'body' => $body, 'response' => ['code' => (int) $result['status'], 'message' => $result['reason']],
                'cookies' => $cookies, 'filename' => null];
        } catch (Throwable $error) {
            return new WP_Error('companion_staging_transport', 'The approved staging request could not complete. Check the staging controls and endpoint.');
        }
    }

    /**
     * Report a request the staging controls refused, so the operator can see what each plugin
     * tries to reach and allow it. Reporting must never change what WordPress sees, so every
     * failure is silent, and each destination is sent once per PHP request.
     */
    public static function blocked(string $kind, string $method, string $url): void
    {
        try {
            $entry = self::blockedEntry($kind, $method, $url);
            if ($entry === null) {
                return;
            }
            $key = implode('|', $entry);
            if (isset(self::$reported[$key])) {
                return;
            }
            self::$reported[$key] = true;
            // The relay answers one connection at a time; a report never holds the page long.
            self::call(['operation' => 'blocked', 'entry' => $entry], 1.0);
        } catch (Throwable $error) {
            return;
        }
    }

    /**
     * What a report says: the source, method, scheme, host and at most the first two path
     * segments. Never a query string, body, header or credential.
     *
     * @return array<string, string>|null Null for an address that is not http or https.
     */
    public static function blockedEntry(string $kind, string $method, string $url): ?array
    {
        $parts = parse_url($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return null;
        }
        if (isset($parts['port']) && (int) $parts['port'] !== ($scheme === 'https' ? 443 : 80)) {
            $host .= ':' . (int) $parts['port'];
        }
        $segments = [];
        foreach (explode('/', (string) ($parts['path'] ?? '/')) as $segment) {
            if ($segment === '') {
                continue;
            }
            if ($segment === '.' || $segment === '..' || !preg_match('~^[A-Za-z0-9._\~!$&\'()*+,;=:@-]+$~D', $segment)) {
                break;
            }
            $segments[] = $segment;
            if (count($segments) === 2) {
                break;
            }
        }
        [$sourceType, $source, $label] = self::source();
        return ['kind' => $kind, 'source_type' => $sourceType, 'source' => $source, 'label' => $label,
            'method' => strtoupper(substr($method, 0, 10)), 'scheme' => $scheme, 'host' => $host,
            'path' => '/' . implode('/', $segments)];
    }

    /**
     * The plugin, theme or must-use plugin closest to the request in the call stack. WordPress
     * itself and these staging safeguards are skipped; a request made only by WordPress is
     * attributed to it.
     *
     * @return array{0: string, 1: string, 2: string} Type, folder or file slug, display name.
     */
    private static function source(): array
    {
        $own = array_map('wp_normalize_path', [__FILE__, __DIR__ . '/staging-policy.php', __DIR__ . '/000-companion-staging.php']);
        $roots = ['plugin' => WP_PLUGIN_DIR, 'mu-plugin' => WPMU_PLUGIN_DIR, 'theme' => get_theme_root()];
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 60) as $frame) {
            $file = wp_normalize_path((string) ($frame['file'] ?? ''));
            if ($file === '' || in_array($file, $own, true)) {
                continue;
            }
            foreach ($roots as $type => $root) {
                $root = trailingslashit(wp_normalize_path($root));
                if (!str_starts_with($file, $root)) {
                    continue;
                }
                $first = explode('/', substr($file, strlen($root)), 2)[0];
                $slug = $type === 'mu-plugin' ? preg_replace('/\.php$/', '', $first) : $first;
                if (!preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $slug)) {
                    continue 2;
                }
                return [$type, $slug, self::label($type, $slug, $root . $first)];
            }
        }
        return ['core', 'wordpress', 'WordPress'];
    }

    private static function label(string $type, string $slug, string $path): string
    {
        $key = $type . ':' . $slug;
        if (!isset(self::$labels[$key])) {
            $name = '';
            if ($type === 'theme') {
                $name = (string) wp_get_theme($slug)->get('Name');
            } elseif ($type === 'mu-plugin') {
                $name = (string) (get_file_data($path, ['Name' => 'Plugin Name'])['Name'] ?? '');
            } else {
                if (!function_exists('get_plugins')) {
                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                }
                $plugin = current(get_plugins('/' . $slug));
                $name = is_array($plugin) ? (string) ($plugin['Name'] ?? '') : '';
            }
            $name = trim(preg_replace('/[\x00-\x1F\x7F]+/', ' ', wp_strip_all_tags($name)));
            self::$labels[$key] = $name !== '' ? mb_substr($name, 0, 100) : $slug;
        }
        return self::$labels[$key];
    }

    public static function mail(array $attributes): bool
    {
        try {
            if (!empty($attributes['attachments'])) {
                throw new RuntimeException('Email attachments are not supported in capture mode.');
            }
            $recipients = [];
            foreach ((array) ($attributes['to'] ?? []) as $line) {
                $recipients = array_merge($recipients, explode(',', $line));
            }
            $headers = $attributes['headers'] ?? [];
            $headers = is_array($headers) ? $headers : preg_split('/\r?\n/', (string) $headers);
            foreach ($headers as $header) {
                if (preg_match('/^\s*(?:cc|bcc)\s*:(.*)$/i', $header, $match)) {
                    $recipients = array_merge($recipients, explode(',', $match[1]));
                }
            }
            $result = self::call(['operation' => 'mail', 'recipients' => array_map('trim', $recipients),
                'subject' => (string) ($attributes['subject'] ?? ''), 'body' => (string) ($attributes['message'] ?? '')]);
            return ($result['captured'] ?? false) === true;
        } catch (Throwable $error) {
            return false;
        }
    }
}
